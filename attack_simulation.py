#!/usr/bin/env python3
import subprocess
import sys
import os
import datetime

def scan_target(target):
    print(f"[+] Đang quét {target}...")
    result = subprocess.run(
        ["nmap", "-sV", "--script", "vuln", target],
        capture_output=True,
        text=True
    )
    return result.stdout

def simulate_exploit(scan_output):
    exploited = []
    for line in scan_output.splitlines():
        if "VULNERABLE" in line.upper():
            exploited.append(line.strip())
    return exploited

def save_report(target, scan_output, exploited, report_dir):
    os.makedirs(report_dir, exist_ok=True)
    filename = os.path.join(report_dir, f"{target.replace('.', '_')}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"=== Báo cáo quét {target} ===\n")
        f.write(f"Thời gian: {datetime.datetime.now()}\n\n")
        f.write("----- Kết quả quét -----\n")
        f.write(scan_output)
        f.write("\n----- Khai thác giả lập -----\n")
        if exploited:
            for vuln in exploited:
                f.write(f"[*] Mô phỏng exploit: {vuln}\n")
        else:
            f.write("Không phát hiện lỗ hổng nghiêm trọng.\n")
    print(f"[+] Đã lưu báo cáo: {filename}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <file_targets.txt> <report_dir>")
        sys.exit(1)

    target_file = sys.argv[1]
    report_dir = sys.argv[2]

    if not os.path.isfile(target_file):
        print(f"[!] Không tìm thấy file {target_file}")
        sys.exit(1)

    with open(target_file, "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    for target in targets:
        scan_output = scan_target(target)
        exploited = simulate_exploit(scan_output)
        save_report(target, scan_output, exploited, report_dir)

if __name__ == "__main__":
    main()
