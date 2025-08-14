#!/usr/bin/env python3
"""
attack_simulation.py
- Quét mạng lab với Nmap + NSE vuln
- Tìm dịch vụ có lỗ hổng (searchsploit)
- Mô phỏng khai thác (ghi log)
- Xuất báo cáo HTML

Chạy:
  python3 attack_simulation.py targets.txt report_dir
"""

import sys, os, subprocess, json, datetime
import nmap
import pandas as pd
from jinja2 import Template
from pathlib import Path
import shutil

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Attack Simulation Report</title>
<style>
body { font-family: Arial; margin: 20px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; }
th { background: #eee; }
.simulated { background: #d1ffd1; }
</style>
</head>
<body>
<h1>Attack Simulation Report</h1>
<p>Generated: {{ now }}</p>
<table>
<tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th><th>Searchsploit Result</th><th>Status</th></tr>
{% for row in rows %}
<tr class="{{ 'simulated' if row.status == 'Exploited (Simulated)' else '' }}">
<td>{{ row.host }}</td>
<td>{{ row.port }}</td>
<td>{{ row.service }}</td>
<td>{{ row.version }}</td>
<td><pre>{{ row.searchsploit }}</pre></td>
<td>{{ row.status }}</td>
</tr>
{% endfor %}
</table>
</body>
</html>
"""

def read_targets(file):
    with open(file) as f:
        return [line.strip() for line in f if line.strip()]

def nmap_scan(host):
    nm = nmap.PortScanner()
    args = "-sV -Pn --script vuln --version-light"
    return nm.scan(hosts=host, arguments=args)

def parse_scan(result, host):
    rows = []
    host_data = result.get('scan', {}).get(host, {})
    for proto in ('tcp', 'udp'):
        for port, info in host_data.get(proto, {}).items():
            rows.append({
                'host': host,
                'port': port,
                'service': info.get('name'),
                'version': f"{info.get('product','')} {info.get('version','')}".strip()
            })
    return rows

def searchsploit_lookup(query):
    if not shutil.which("searchsploit"):
        return ""
    try:
        out = subprocess.run(
            ["searchsploit", query],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10
        ).stdout.decode(errors='ignore')
        return "\n".join(out.splitlines()[:5])  # lấy 5 dòng đầu
    except:
        return ""

def simulate_attack(service, version):
    # Giả lập: ghi log, không gửi payload thật
    print(f"[SIMULATION] Exploiting {service} {version} ... success")
    return "Exploited (Simulated)"

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} targets.txt report_dir")
        sys.exit(1)

    targets_file = sys.argv[1]
    report_dir = Path(sys.argv[2])
    report_dir.mkdir(parents=True, exist_ok=True)

    targets = read_targets(targets_file)
    all_rows = []

    for host in targets:
        print(f"[+] Scanning {host} ...")
        scan_result = nmap_scan(host)
        services = parse_scan(scan_result, host)

        for svc in services:
            query = f"{svc['service']} {svc['version']}".strip()
            ss_result = searchsploit_lookup(query)
            status = "Not Exploited"
            if ss_result:
                status = simulate_attack(svc['service'], svc['version'])
            all_rows.append({
                'host': svc['host'],
                'port': svc['port'],
                'service': svc['service'],
                'version': svc['version'],
                'searchsploit': ss_result,
                'status': status
            })

    # Xuất CSV
    csv_path = report_dir / "attack_report.csv"
    pd.DataFrame(all_rows).to_csv(csv_path, index=False)

    # Xuất HTML
    html_path = report_dir / "attack_report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(Template(HTML_TEMPLATE).render(rows=all_rows, now=datetime.datetime.now()))

    print(f"[+] Reports saved: {csv_path}, {html_path}")

if __name__ == "__main__":
    main()
