#!/usr/bin/env python3
"""
scan_filter_clone.py

SAFE AUTOMATION (FILTERED CLONE ONLY)

What it does:
- Ping-sweep / scan local subnet or given targets
- For each host, run `nmap -sV --script vuln` and parse services/CVEs
- For each query (CVE or service), search GitHub repos
- Filter repos by:
    - keywords in repo name or description (quick accept)
    - OR presence of filenames in repo tree that match PoC/exploit patterns
- Clone only filtered repos into output_dir/quarantine/<host>_<port>_<repo>
- Create Dockerfile.sandbox + RUN_INSTRUCTIONS.txt (do NOT build/run)
- Produce CSV + HTML report

Requirements:
- nmap, git installed and in PATH
- pip3 install requests jinja2 pandas
- (recommended) export GITHUB_TOKEN="ghp_...." to avoid API rate limits

Usage:
    python3 scan_filter_clone.py targets.txt outdir
    OR (auto subnet detect)
    python3 scan_filter_clone.py outdir    # will auto-discover subnet and scan

Author: safe tooling (no exploit execution)
"""

import os
import re
import sys
import time
import json
import shutil
import socket
import requests
import subprocess
import datetime
from pathlib import Path
from urllib.parse import quote_plus
from jinja2 import Template
import pandas as pd

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
# Filtering keywords (case-insensitive)
KEYWORDS = [
    "exploit", "poc", "proof-of-concept", "proof_of_concept", "proof-of-concept",
    "proof", "exp", "rce", "remote-code-execution", "payload", "exploit-db"
]
# filenames patterns that strongly indicate PoC
FILENAME_PATTERNS = [
    r".*poc.*", r".*exploit.*", r".*proof.*", r".*exp.*", r".*exploit\.py", r".*poc\.py",
    r".*exploit\.sh", r".*poc\.sh", r".*README.*exploit.*"
]

MAX_REPOS_PER_QUERY = 5
SLEEP_BETWEEN_QUERIES = 1.0

# Basic HTML template for report
HTML_TMPL = """<!doctype html><html><head><meta charset="utf-8"><title>Filtered Clone Report</title>
<style>body{font-family:Arial;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f6f6f6}</style>
</head><body>
<h1>Filtered Clone Report</h1>
<p>Generated: {{ now }}</p>
<table>
<thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Cloned Repos</th></tr></thead><tbody>
{% for r in rows %}
<tr>
<td>{{ r.host }}</td><td>{{ r.port }}</td><td>{{ r.service }}</td><td>{{ r.version }}</td>
<td>
<ul>
{% for c in r.cloned %}
<li><b>{{ c.full_name }}</b> — <a href="{{ c.html_url }}" target="_blank">{{ c.html_url }}</a><br><small>{{ c.desc }}</small></li>
{% endfor %}
</ul>
</td>
</tr>
{% endfor %}
</tbody></table>
</body></html>"""

DOCKERFILE_TEMPLATE = """# Sandbox Dockerfile template (AUTO-GENERATED)
# Inspect repo contents carefully before building/running.
FROM ubuntu:24.04
WORKDIR /sandbox
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip git curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . /sandbox
CMD ["/bin/bash", "-c", "echo 'Sandbox ready. Inspect files before running anything.'; exec /bin/bash"]
"""

RUN_INSTRUCT = """# MANUAL RUN INSTRUCTIONS (AUTO-GENERATED)
# Inspect the repository at: {repo_path}
# If you decide to test, do it inside an isolated disposable VM/container.
# Example:
#   docker build -t sandbox-{safe_name} -f Dockerfile.sandbox .
#   docker run --rm -it --network=none --cap-drop=ALL --read-only -v /tmp/sandbox-logs:/tmp/logs sandbox-{safe_name}
"""

# ---------------- utility functions ----------------
def run_cmd(cmd):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def detect_local_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "192.168.1.100"
    finally:
        s.close()
    parts = local_ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return "192.168.1.0/24"

def nmap_ping_sweep(subnet):
    cmd = ["nmap", "-sn", "-n", subnet, "-oG", "-"]
    print("[*] ping-sweep:", " ".join(cmd))
    rc, out, err = run_cmd(cmd)
    hosts = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Host:"):
            m = re.match(r"Host:\s+([0-9a-fA-F\.:]+)", line)
            if m:
                hosts.append(m.group(1))
    return hosts

def nmap_scan_target(target):
    cmd = ["nmap", "-sV", "--script", "vuln", "-oG", "-", target]
    print("[*] nmap scan:", " ".join(cmd))
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        print("[!] nmap returned non-zero code:", rc, err)
    return out

def parse_nmap_grepable(output):
    rows = []
    for line in output.splitlines():
        line=line.strip()
        if not line or not line.startswith("Host:"):
            continue
        m = re.match(r'Host:\s+([0-9a-fA-F\.:]+)', line)
        if not m:
            continue
        host = m.group(1)
        parts = line.split("Ports:")
        if len(parts) < 2:
            continue
        ports_part = parts[1].strip()
        for chunk in ports_part.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            segs = chunk.split("/")
            try:
                port = segs[0]
                proto = segs[2]
                service = segs[4] if len(segs) > 4 else ""
                version = ""
                if service:
                    idx = chunk.find(service)
                    version = chunk[idx + len(service):].strip()
                else:
                    tail = chunk.split()
                    if len(tail) > 1:
                        version = " ".join(tail[1:])
                rows.append({"host": host, "port": port, "protocol": proto, "service": service, "version": version})
            except Exception:
                continue
    return rows

# ---------------- GitHub helpers ----------------
def github_search_repos(query, per_page=MAX_REPOS_PER_QUERY):
    if not query:
        return []
    q = quote_plus(query)
    url = f"https://api.github.com/search/repositories?q={q}+in:name,description,readme&sort=stars&order=desc&per_page={per_page}"
    headers = {"Accept":"application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            print(f"[!] GitHub API {r.status_code} for query '{query}'")
            return []
        items = r.json().get("items", [])[:per_page]
        return [{
            "full_name": it.get("full_name"),
            "html_url": it.get("html_url"),
            "clone_url": it.get("clone_url"),
            "desc": it.get("description") or ""
        } for it in items]
    except Exception as e:
        print("[!] GitHub search error:", e)
        return []

def github_get_repo_tree(full_name):
    # Use GitHub git/trees API with recursive=1 to list filenames (may be large)
    url = f"https://api.github.com/repos/{full_name}/git/trees/HEAD?recursive=1"
    headers = {"Accept":"application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            # sometimes HEAD not available; fallback to default branch via repo API
            if r.status_code == 404:
                return []
            print(f"[!] tree API returned {r.status_code} for {full_name}")
            return []
        j = r.json()
        tree = j.get("tree", [])
        return [item.get("path","") for item in tree if item.get("path")]
    except Exception as e:
        print("[!] GitHub tree error:", e)
        return []

# ---------------- filtering ----------------
def repo_matches_quick_keywords(repo):
    name = (repo.get("full_name") or "").lower()
    desc = (repo.get("desc") or "").lower()
    for kw in KEYWORDS:
        if kw in name or kw in desc:
            return True
    return False

def repo_has_poc_filenames(full_name):
    # fetch tree and check filenames for patterns
    files = github_get_repo_tree(full_name)
    if not files:
        return False
    for fname in files:
        low = fname.lower()
        for pat in FILENAME_PATTERNS:
            if re.match(pat, os.path.basename(low)):
                return True
        # also check path contains keywords
        for kw in KEYWORDS:
            if kw in low:
                return True
    return False

# ---------------- clone ----------------
def safe_clone(repo_clone_url, dest_dir):
    dest = Path(dest_dir)
    if dest.exists():
        print(f"    [i] already cloned: {dest}")
        return True
    cmd = ["git", "clone", "--depth", "1", repo_clone_url, str(dest)]
    print("    [*] cloning:", " ".join(cmd))
    rc, out, err = run_cmd(cmd)
    if rc != 0:
        print("    [!] git clone failed:", err.strip())
        return False
    # remove .git for safety
    gitdir = dest / ".git"
    if gitdir.exists():
        try:
            if gitdir.is_dir():
                shutil.rmtree(gitdir)
        except Exception:
            pass
    return True

def sanitize(s):
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', s)[:50].lower()

# ---------------- main workflow ----------------
def main():
    # usage: either python3 scan_filter_clone.py targets.txt outdir
    # or: python3 scan_filter_clone.py outdir  (auto subnet detect)
    if len(sys.argv) not in (2,3):
        print("Usage: python3 scan_filter_clone.py <targets.txt> <outdir>")
        print(" or:  python3 scan_filter_clone.py <outdir>   (auto-discover subnet)")
        sys.exit(1)
    if len(sys.argv) == 3:
        targets_file = Path(sys.argv[1])
        out_dir = Path(sys.argv[2])
        if not targets_file.exists():
            print("[!] targets file not found:", targets_file)
            sys.exit(1)
        with open(targets_file, "r") as f:
            targets = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    else:
        out_dir = Path(sys.argv[1])
        subnet = detect_local_subnet()
        print(f"[*] Auto-detected subnet: {subnet}")
        hosts = nmap_ping_sweep(subnet)
        print("[*] hosts discovered:", hosts)
        targets = hosts

    out_dir.mkdir(parents=True, exist_ok=True)
    quarantine = out_dir / "quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)

    aggregated = []

    for tgt in targets:
        print(f"[*] scanning target {tgt} ...")
        nout = nmap_scan_target(tgt)
        services = parse_nmap_grepable(nout)
        if not services:
            print("   [i] no services parsed for", tgt)
        for s in services:
            queries = []
            # extract CVEs
            cves = re.findall(r'(CVE-\d{4}-\d{4,7})', s.get("version",""), flags=re.IGNORECASE)
            for c in cves:
                queries.append(c)
            svc = s.get("service") or ""
            ver = s.get("version") or ""
            if svc and ver:
                queries.append(f"{svc} {ver}")
            if svc:
                queries.append(svc)
            # dedupe queries
            seen = set(); qlist = []
            for q in queries:
                k = q.lower().strip()
                if k and k not in seen:
                    seen.add(k); qlist.append(q)
            cloned = []
            for q in qlist:
                print("   [>] gitHub search:", q)
                repos = github_search_repos(q, per_page=MAX_REPOS_PER_QUERY)
                time.sleep(SLEEP_BETWEEN_QUERIES)
                for repo in repos:
                    accept = False
                    # quick keyword match in name/description
                    if repo_matches_quick_keywords(repo):
                        accept = True
                        reason = "keyword in name/desc"
                    else:
                        # deeper check: get repo tree and look for PoC file names
                        print("       [i] checking filenames in", repo["full_name"])
                        try:
                            if repo_has_poc_filenames(repo["full_name"]):
                                accept = True
                                reason = "poc-like filenames in repo tree"
                        except Exception as e:
                            print("       [!] error checking repo tree:", e)
                    if accept:
                        safe = sanitize(repo["full_name"])
                        repo_dir = quarantine / f"{tgt}_{s.get('port')}_{safe}"
                        ok = safe_clone(repo["clone_url"], repo_dir)
                        if ok:
                            # write sandbox templates
                            dfp = repo_dir / "Dockerfile.sandbox"
                            if not dfp.exists():
                                dfp.write_text(DOCKERFILE_TEMPLATE)
                            runf = repo_dir / "RUN_INSTRUCTIONS.txt"
                            runf.write_text(RUN_INSTRUCT.format(repo_path=str(repo_dir), safe_name=safe))
                            cloned.append({"full_name": repo["full_name"], "html_url": repo["html_url"], "desc": repo.get("desc",""), "reason": reason, "path": str(repo_dir.resolve())})
                # stop if we already cloned enough for this service
                if len(cloned) >= MAX_REPOS_PER_QUERY:
                    break
            aggregated.append({"host": s.get("host"), "port": s.get("port"), "service": s.get("service"), "version": s.get("version"), "cloned": cloned})

    # write csv and html
    csvp = out_dir / "filtered_cloned.csv"
    htmlp = out_dir / "filtered_cloned.html"
    records = []
    for a in aggregated:
        records.append({"host": a["host"], "port": a["port"], "service": a["service"], "version": a["version"], "cloned": json.dumps(a["cloned"], ensure_ascii=False)})
    pd.DataFrame(records).to_csv(csvp, index=False)
    with open(htmlp, "w", encoding="utf-8") as f:
        f.write(Template(HTML_TMPL).render(rows=aggregated, now=datetime.datetime.utcnow().isoformat()+"Z"))

    print("[+] Done. Cloned repos (filtered) are in:", quarantine.resolve())
    print("[+] CSV:", csvp, "HTML:", htmlp)
    print("*** REMEMBER: inspect repos before building or running anything ***")

if __name__ == "__main__":
    main()
