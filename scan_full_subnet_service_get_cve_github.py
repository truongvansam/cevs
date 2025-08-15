#!/usr/bin/env python3
import subprocess
import re
import requests
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os

# ===== CONFIG =====
TARGET_FILE = "targets.txt"
THREADS = 5
GITHUB_SEARCH_LIMIT = 3
CVSS_THRESHOLD = 7.0
OUTPUT_FILE = f"result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
TOP_PORTS = True  # True: top 1000, False: full port

# ===== CẬP NHẬT NMAP SCRIPTS =====
def update_nmap_scripts():
    print("[*] Cập nhật Nmap & scripts...")
    subprocess.run(["sudo", "apt", "update", "-y"])
    subprocess.run(["sudo", "apt", "install", "-y", "nmap"])
    vulners_path = "/usr/share/nmap/scripts/vulners.nse"
    vulscan_dir = "/usr/share/nmap/scripts/vulscan"

    subprocess.run(["sudo", "wget", "-O", vulners_path,
                    "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse"])
    if os.path.exists(vulscan_dir):
        subprocess.run(["sudo", "rm", "-rf", vulscan_dir])
    subprocess.run(["sudo", "git", "clone", "https://github.com/scipag/vulscan.git", vulscan_dir])
    print("[+] Hoàn tất cập nhật scripts.")

# ===== TÌM HOST SỐNG =====
def discover_hosts(target):
    if "/" in target:
        print(f"[*] Dò host sống trong subnet {target}...")
        try:
            result = subprocess.run(["nmap", "-sn", target], capture_output=True, text=True, timeout=120)
            hosts = re.findall(r"Nmap scan report for ([\d\.]+)", result.stdout)
            return hosts
        except Exception as e:
            print(f"[!] Lỗi dò subnet {target}: {e}")
            return []
    else:
        return [target]

# ===== KIỂM TRA DỊCH VỤ =====
SERVICE_PORTS = {
    "http": "80,443,8080",
    "ssh": "22",
    "mysql": "3306",
    "ftp": "21",
    "smtp": "25,587"
}

def get_ports_for_service(service):
    return SERVICE_PORTS.get(service.lower(), "")

# ===== QUÉT HOST =====
def scan_target(target, service_filter=None):
    print(f"[*] Quét {target}...")
    ports_option = "-F" if TOP_PORTS else "-p-"
    if service_filter:
        ports = get_ports_for_service(service_filter)
        if ports:
            ports_option = f"-p{ports}"

    cmd = ["nmap", ports_option, "--script", "vulners,vulscan", "-oN", "-", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        cve_list = []
        for line in result.stdout.splitlines():
            match = re.search(r"(CVE-\d{4}-\d+)", line)
            if match:
                cve_id = match.group(1)
                score_match = re.search(r"CVSS\s*:\s*([\d\.]+)", line)
                score = score_match.group(1) if score_match else "0"
                try:
                    score_val = float(score)
                except:
                    score_val = 0.0
                if score_val >= CVSS_THRESHOLD:
                    poc_links = search_github_poc(cve_id)
                    cve_list.append({
                        "Target": target,
                        "CVE": cve_id,
                        "CVSS": score_val,
                        "GitHub_PoC": " | ".join(poc_links) if poc_links else "Không tìm thấy"
                    })
        return cve_list
    except Exception as e:
        print(f"[!] Lỗi quét {target}: {e}")
        return []

# ===== TÌM POC GITHUB =====
def search_github_poc(cve_id):
    url = f"https://api.github.com/search/repositories?q={cve_id}+exploit&sort=stars&order=desc"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            links = [item["html_url"] for item in data.get("items", [])[:GITHUB_SEARCH_LIMIT]]
            return links
        return []
    except:
        return []

# ===== CHẠY SCRIPT =====
if __name__ == "__main__":
    if not os.path.exists(TARGET_FILE):
        print(f"[!] Không tìm thấy {TARGET_FILE}")
        exit(1)

    update_nmap_scripts()

    print("Chọn chế độ quét:")
    print("1 - Quét theo danh sách target")
    print("2 - Quét theo subnet")
    print("3 - Quét theo dịch vụ")
    choice = input("Nhập lựa chọn (1/2/3): ").strip()

    service_filter = None
    if choice == "3":
        service_filter = input("Nhập tên dịch vụ (http, ssh, mysql...): ").strip()

    with open(TARGET_FILE) as f:
        raw_targets = [line.strip() for line in f if line.strip()]

    all_hosts = []
    for t in raw_targets:
        hosts = discover_hosts(t)
        all_hosts.extend(hosts)

    print(f"[+] Tổng host cần quét: {len(all_hosts)}")
    all_results = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for res in executor.map(lambda h: scan_target(h, service_filter), all_hosts):
            if res:
                all_results.extend(res)

    if all_results:
        df = pd.DataFrame(all_results)
        df.sort_values(by="CVSS", ascending=False, inplace=True)
        df.to_csv(OUTPUT_FILE, index=False)
        print(f"[+] Kết quả lưu tại: {OUTPUT_FILE}")
    else:
        print("[!] Không tìm thấy CVE nguy hiểm.")
