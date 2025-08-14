#!/usr/bin/env python3
"""
auto_scan_clone_prepare_sandbox.py

SAFE TOOL (DOES NOT EXECUTE EXPLOITS)
- Auto-discover hosts in local subnet (nmap -sn)
- For each host: run nmap -sV --script vuln
- Parse services/CVEs, search GitHub for PoC repos
- Clone top repos into output_dir/quarantine (no execution)
- Create Dockerfile.sandbox + RUN_INSTRUCTIONS.txt for manual, isolated testing
- Produce CSV and HTML report

USAGE:
  python3 auto_scan_clone_prepare_sandbox.py [output_dir] [optional: subnet]
If subnet omitted, script will auto-detect local IPv4 and use /24.

IMPORTANT: Review cloned repos manually. Do NOT build/run until you inspect the code in an isolated VM.
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
MAX_REPOS_PER_FIND = 3
SLEEP_BETWEEN_QUERIES = 1.0

HTML_TMPL = """<!doctype html>
<html><head><meta charset="utf-8"><title>Scan & Cloned PoC Report</title>
<style>body{font-family:Arial;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px}th{background:#f2f2f2}pre{white-space:pre-wrap}</style>
</head><body>
<h1>Scan & Cloned PoC Report</h1>
<p>Generated: {{ now }}</p>
<table>
<thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Cloned Repos (local path)</th></tr></thead>
<tbody>
{% for r in rows %}
<tr>
<td>{{ r.host }}</td>
<td>{{ r.port }}</td>
<td>{{ r.service }}</td>
<td>{{ r.version }}</td>
<td>
<ul>
{% for c in r.cloned %}
<li><a href="file://{{ c.path }}">{{ c.path }}</a> — <a href="{{ c.html_url }}">{{ c.html_url }}</a><br><small>{{ c.desc }}</small></li>
{% endfor %}
</ul>
</td>
</tr>
{% endfor %}
</tbody>
</table>
<p><strong>IMPORTANT:</strong> inspect repos before building. See output directory for Docker sandbox templates.</p>
</body></html>
"""

DOCKERFILE_TEMPLATE = """# AUTO-GENERATED SANDBOX DOCKERFILE TEMPLATE
# DO NOT BUILD/RUN until you have manually inspected the cloned repo.
FROM ubuntu:24.04
WORKDIR /sandbox
RUN apt-get update && apt-get install -y --no-install-recommends \\
    python3 python3-pip git curl ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . /sandbox
CMD ["/bin/bash", "-c", "echo 'Sandbox ready. Inspect files then run what you need manually.'; exec /bin/bash"]
"""

RUN_CMD_TEMPLATE = """# HOW TO BUILD & RUN (MANUAL STEPS)
# 1) Inspect the cloned repo directory: {{ repo_path }}
# 2) From inside the repo root, ensure the Dockerfile.sandbox is present.
# 3) Build the sandbox image (only do this in an isolated VM/container host):
#    docker build -t sandbox-{{ safe_name }} -f Dockerfile.sandbox .
# 4) Run the container with strict isolation (no network, drop caps):
#    docker run --rm -it --network=none --cap-drop=ALL --read-only -v /tmp/sandbox-logs:/tmp/logs sandbox-{{ safe_name }}
# Edit CMD/Caps/Volumes as appropriate after manual review.
"""

def run_cmd(cmd, capture_output=True, text=True):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE if capture_output else None,
                           stderr=subprocess.PIPE if capture_output else None, text=text)
        return p.returncode, p.stdout if capture_output else ""
    except Exception as e:
        return 1, str(e)

def detect_local_subnet():
    # Try to get local IP by creating dummy socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # connect to public DNS to get a local iface ip (no data sent)
        s.connect(("8.8.8.8", 53))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "192.168.1.100"
    finally:
        s.close()
    # default /24
    parts = local_ip.split(".")
    if len(parts) == 4:
        subnet = ".".join(parts[:3]) + ".0/24"
    else:
        subnet = "192.168.1.0/24"
    print(f"[*] Auto-detected local IP {local_ip}, using subnet {subnet}")
    return subnet

def nmap_ping_sweep(subnet):
    cmd = ["nmap", "-sn", "-n", subnet, "-oG", "-"]
    print("[*] Running ping sweep:", " ".join(cmd))
    code, out = run_cmd(cmd)
    hosts = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Host:"):
            m = re.match(r"Host:\s+([0-9a-fA-F\.:]+)\s+\(", line)
            if m:
                hosts.append(m.group(1))
    return hosts

def nmap_scan_target(target):
    cmd = ["nmap", "-sV", "--script", "vuln", "-oG", "-", target]
    print("[*] Scanning target:", target)
    _, out = run_cmd(cmd)
    return out

def parse_nmap_grepable(output):
    rows = []
    for line in output.splitlines():
        line = line.strip()
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

def github_search_repos(query, max_results=5):
    if not query:
        return []
    q = quote_plus(query)
    url = f"https://api.github.com/search/repositories?q={q}+in:name,description,readme&sort=stars&order=desc&per_page={max_results}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"
    try:
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code != 200:
            print(f"[!] GitHub API returned {r.status_code} for query '{query}'")
            return []
        items = r.json().get("items", [])[:max_results]
        return [{"full_name": it.get("full_name"), "html_url": it.get("html_url"), "clone_url": it.get("clone_url"), "description": it.get("description")} for it in items]
    except Exception as e:
        print("[!] GitHub search error:", e)
        return []

def safe_clone(repo_clone_url, dest_dir):
    dest = Path(dest_dir)
    if dest.exists():
        print(f"    [i] Already cloned: {dest}")
        return True
    cmd = ["git", "clone", "--depth", "1", repo_clone_url, str(dest)]
    print("    [*] Cloning:", " ".join(cmd))
    code, out = run_cmd(cmd)
    if code != 0:
        print("    [!] git clone failed")
        return False
    # remove .git to avoid accidental pushes/metadata
    gitdir = dest / ".git"
    try:
        if gitdir.exists():
            if gitdir.is_dir():
                shutil.rmtree(gitdir)
    except Exception:
        pass
    return True

def sanitize_name(s):
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', s)[:40].lower()

def create_templates_for_repo(repo_dir, safe_name):
    dfpath = repo_dir / "Dockerfile.sandbox"
    if not dfpath.exists():
        dfpath.write_text(DOCKERFILE_TEMPLATE)
    runf = repo_dir / "RUN_INSTRUCTIONS.txt"
    runf.write_text(Template(RUN_CMD_TEMPLATE).render(repo_path=str(repo_dir), safe_name=safe_name))

def build_reports(aggregated, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "scan_cloned.csv"
    html_path = out_dir / "scan_cloned.html"
    df = pd.DataFrame([{"host": a["host"], "port": a["port"], "service": a["service"], "version": a["version"], "cloned": json.dumps(a["cloned"], ensure_ascii=False)} for a in aggregated])
    df.to_csv(csv_path, index=False)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(Template(HTML_TMPL).render(rows=aggregated, now=datetime.datetime.utcnow().isoformat()+"Z"))
    print(f"[+] CSV: {csv_path}")
    print(f"[+] HTML: {html_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 auto_scan_clone_prepare_sandbox.py <output_dir> [subnet]")
        sys.exit(1)
    out_dir = Path(sys.argv[1])
    subnet = sys.argv[2] if len(sys.argv) > 2 else detect_local_subnet()
    quarantine = out_dir / "quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)

    # Step 1: ping sweep
    hosts = nmap_ping_sweep(subnet)
    print(f"[*] Hosts alive: {hosts}")

    aggregated = []
    for host in hosts:
        print(f"[*] Scanning {host} ...")
        nmap_out = nmap_scan_target(host)
        services = parse_nmap_grepable(nmap_out)
        if not services:
            print(f"   [i] No services parsed for {host}")
        for s in services:
            # build queries: CVE from version and service
            queries = []
            cves = re.findall(r'(CVE-\d{4}-\d{4,7})', s.get("version",""), flags=re.IGNORECASE)
            for c in cves:
                queries.append(c)
            svc = s.get("service") or ""
            ver = s.get("version") or ""
            if svc and ver:
                queries.append(f"{svc} {ver}")
            if svc:
                queries.append(svc)
            # dedupe
            seen = set(); qlist = []
            for q in queries:
                k = q.lower().strip()
                if k and k not in seen:
                    seen.add(k); qlist.append(q)
            cloned_list = []
            for q in qlist:
                print(f"   [>] GitHub search for: {q}")
                results = github_search_repos(q, max_results=MAX_REPOS_PER_FIND)
                time.sleep(SLEEP_BETWEEN_QUERIES)
                for r in results:
                    safe = sanitize_name(r["full_name"])
                    repo_dir = quarantine / f"{host}_{s.get('port')}_{safe}"
                    ok = safe_clone(r["clone_url"], repo_dir)
                    if ok:
                        create_templates_for_repo(repo_dir, safe)
                        cloned_list.append({"path": str(repo_dir.resolve()), "html_url": r["html_url"], "desc": r.get("description") or ""})
                if len(cloned_list) >= MAX_REPOS_PER_FIND:
                    break
            aggregated.append({"host": s.get("host"), "port": s.get("port"), "service": s.get("service"), "version": s.get("version"), "cloned": cloned_list})

    build_reports(aggregated, out_dir)
    print("[+] Completed. Cloned repos are in:", quarantine.resolve())
    print("\n*** SAFETY REMINDERS ***")
    print("1) DO NOT build or run anything until you manually inspect the repo.")
    print("2) Use an isolated disposable VM or container host with snapshots for any execution.")
    print("3) If you want help creating a disposable sandbox environment, ask for 'create sandbox'.")

if __name__ == "__main__":
    main()
