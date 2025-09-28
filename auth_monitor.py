"""
Title: Interactive Log Monitoring Script
Author: Ayomide Aregbe
Contributors: Swave IT team
Date: 27th May 2024
Description:
- Select log source to monitor
- Provde the log path
- Regression parsing and alerts based on rules defined
- This script was initially written to monitor authentication and request error_logs but bhs log added
- Baggage error_log has pattern Error Timestamp  Device Types<conveyors belts, sorters, rfid readers, sensors etc>   Error Messages
"""

import os
import re
import time
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime


# ---------- Predefined Log Types ----------
LOG_PATTERNS = {
    "apache": {
        "pattern": re.compile(
            r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - (?P<user>\S+) \[(?P<time>[^\]]+)\] '
            r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>HTTP/\d\.\d)" (?P<status>\d{3}) (?P<size>\d+|-)'
        ),
        "failed_code": 401,
    },
    "auth": {
        "pattern": re.compile(
            r'(?P<time>\w{3}\s+\d+\s[\d:]+) (?P<host>\S+) sshd\[\d+\]: '
            r'Failed password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+'
        ),
        "failed_code": None,
    },
    "baggage": {
        "pattern": re.compile(
            r'(?P<time>[\d-]+\s[\d:]+) (?P<device>\S+) ERROR (?P<msg>.+)'
        ),
        "failed_code": None,
    }
}


# ---------- Set preferred Thresholds ----------
REQUEST_THRESHOLD = 5
ERROR_STATUS_THRESHOLD = 3
FAILED_LOGIN_THRESHOLD = 3


# ---------- Config ----------
def wait_for_logfile(path: Path, check_interval=2):
    """Wait until logfile exists and is being written to."""
    print(f"Waiting for log file: {path}")
    while not path.exists():
        time.sleep(check_interval)

    last_size = -1
    while True:
        size = path.stat().st_size
        if size > last_size:
            print(f"Log file {path} found and growing.")
            break
        last_size = size
        time.sleep(check_interval)


# ---------- Monitor Specific Log ----------
def monitor_log(name: str, path: Path, pattern, failed_code, report_path: Path):
    alerts = []
    suspicious_lines = defaultdict(list)

    failed_per_ip = Counter()
    requests_per_ip = Counter()
    errors_per_ip = Counter()

    with path.open() as file:
        for line in file:
            m = pattern.match(line)
            if not m:
                continue

            data = m.groupdict()

            # Apache-style logs
            if name == "apache":
                ip = data["ip"]
                status = int(data["status"])

                requests_per_ip[ip] += 1
                if failed_code and status == failed_code:
                    failed_per_ip[ip] += 1
                    suspicious_lines[ip].append(line.strip())
                if 500 <= status < 600:
                    errors_per_ip[ip] += 1
                    suspicious_lines[ip].append(line.strip())

            # Auth logs (SSH failed login)
            elif name == "auth":
                ip = data["ip"]
                failed_per_ip[ip] += 1
                suspicious_lines[ip].append(line.strip())

            # Baggage system logs (equipment errors)
            elif name == "baggage":
                device = data["device"]
                suspicious_lines[device].append(line.strip())
                errors_per_ip[device] += 1

    # ---------- Predefined rules ----------
    for ip, count in failed_per_ip.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            alerts.append((ip, f"{count} failed logins"))

    for ip, count in requests_per_ip.items():
        if count >= REQUEST_THRESHOLD:
            alerts.append((ip, f"{count} requests (high volume)"))

    for subject, count in errors_per_ip.items():
        if count >= ERROR_STATUS_THRESHOLD:
            alerts.append((subject, f"{count} errors"))

    # ---------- Save Report ----------
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    report_lines = [
        f"Log Monitor Report - {now}",
        "",
        f"failed_per_ip: {dict(failed_per_ip)}",
        f"requests_per_ip: {dict(requests_per_ip)}",
        f"errors_per_ip: {dict(errors_per_ip)}",
        "",
    ]

    if alerts:
        report_lines.append("ALERTS:")
        for subject, reason in alerts:
            report_lines.append(f" - {subject}: {reason}")
    else:
        report_lines.append("No alerts detected.")

    report_lines.append("")
    report_lines.append("Suspicious lines (sample):")
    for subject, lines in suspicious_lines.items():
        report_lines.append(f"{subject}:")
        for l in lines[:5]:
            report_lines.append("    " + l)
        report_lines.append("")

    report_path.write_text("\n".join(report_lines))
    print(f"Report written to {report_path}")


# ---------- MAIN ----------
if __name__ == "__main__":
    print("Available log types: apache, auth, baggage")
    choice = input("Which log do you want to monitor? ").strip().lower()

    if choice not in LOG_PATTERNS:
        print("❌ Invalid choice. Exiting.")
        exit(1)

    log_path_input = input(f"Enter the path for {choice} log file (.log, .txt, etc): ").strip()
    log_path = Path(log_path_input)

    if not log_path.exists():
        print("❌ Log file not found. But waiting...")
    
    wait_for_logfile(log_path)

    report_path = Path(f"{choice}_report.txt")
    monitor_log(
        name=choice,
        path=log_path,
        pattern=LOG_PATTERNS[choice]["pattern"],
        failed_code=LOG_PATTERNS[choice]["failed_code"],
        report_path=report_path,
    )
