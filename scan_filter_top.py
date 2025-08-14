import subprocess
import requests
import re

# ---------------- CONFIG ----------------
TARGET = "192.168.1.10"   # IP hoặc hostname của máy trong lab
MAX_RESULTS = 5           # Số repo tối đa hiển thị
# -----------------------------------------

def scan_vuln(target):
    print("[*] Đang quét lỗ hổng với Nmap...")
    try:
        result = subprocess.check_output(
            ["nmap", "--script", "vuln", "-Pn", target],
            stderr=subprocess.DEVNULL
        ).decode()
    except FileNotFoundError:
        print("[-] Nmap chưa được cài. Cài bằng: sudo apt install nmap")
        return []

    # Tìm CVE hoặc tên dịch vụ
    matches = re.findall(r"(CVE-\d{4}-\d+)", result)
    if not matches:
        services = re.findall(r"^\d+/tcp\s+open\s+([a-zA-Z0-9\-_]+)", result, re.MULTILINE)
        matches = list(set(services))
    return list(set(matches))

def search_github(query):
    print(f"[*] Tìm trên GitHub: {query}")
    url = f"https://api.github.com/search/repositories?q={query}+exploit+poc+proof-of-concept&sort=stars&order=desc"
    r = requests.get(url, headers={"Accept": "application/vnd.github.v3+json"})
    if r.status_code != 200:
        print(f"[-] Lỗi GitHub API: {r.status_code}")
        return []
    data = r.json()
    results = []
    for item in data.get("items", []):
        results.append({
            "name": item["full_name"],
            "url": item["html_url"],
            "stars": item["stargazers_count"],
            "desc": item["description"]
        })
    return results

if __name__ == "__main__":
    findings = scan_vuln(TARGET)
    if not findings:
        print("[-] Không tìm thấy CVE hay dịch vụ nào.")
    else:
        print(f"[+] Phát hiện: {findings}")
        for vuln in findings:
            repos = search_github(vuln)
            if repos:
                print(f"\n--- Kết quả cho {vuln} ---")
                for repo in repos[:MAX_RESULTS]:
                    print(f"[{repo['stars']}★] {repo['name']}\n    {repo['url']}\n    {repo['desc']}")
