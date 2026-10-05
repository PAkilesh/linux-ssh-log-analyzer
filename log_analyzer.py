import subprocess
from collections import Counter
from datetime import datetime
import socket
import os


# --------------------------------------------------
# Configuration
# --------------------------------------------------

WARNING_THRESHOLD = 3
CRITICAL_THRESHOLD = 5

REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "security_report.txt")


# --------------------------------------------------
# Read SSH logs
# --------------------------------------------------

def get_ssh_logs():
    try:
        result = subprocess.run(
            [
                "sudo",
                "journalctl",
                "-u",
                "sshd",
                "--no-pager"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout.splitlines()

    except subprocess.CalledProcessError as error:
        print("ERROR: Unable to read SSH logs.")
        print(error.stderr)
        return []


# --------------------------------------------------
# Extract IP address
# --------------------------------------------------

def extract_ip(log_line):
    words = log_line.split()

    if "from" in words:
        position = words.index("from")

        if position + 1 < len(words):
            return words[position + 1]

    return "Unknown"


# --------------------------------------------------
# Analyze SSH logs
# --------------------------------------------------

def analyze_logs(logs):
    successful_logins = []
    failed_logins = []
    invalid_users = []

    for line in logs:

        if "Accepted password" in line:
            successful_logins.append(line)

        if "Failed password" in line:
            failed_logins.append(line)

        if "Invalid user" in line:
            invalid_users.append(line)

    successful_ips = Counter(
        extract_ip(line)
        for line in successful_logins
    )

    failed_ips = Counter(
        extract_ip(line)
        for line in failed_logins
    )

    return (
        successful_logins,
        failed_logins,
        invalid_users,
        successful_ips,
        failed_ips
    )


# --------------------------------------------------
# Detect suspicious IP addresses
# --------------------------------------------------

def detect_suspicious_ips(failed_ips):
    suspicious_ips = []

    for ip, count in failed_ips.items():

        if count >= WARNING_THRESHOLD:
            suspicious_ips.append((ip, count))

    suspicious_ips.sort(
        key=lambda item: item[1],
        reverse=True
    )

    return suspicious_ips


# --------------------------------------------------
# Determine overall security status
# --------------------------------------------------

def determine_status(failed_ips):

    if not failed_ips:
        return "HEALTHY"

    highest_failure_count = max(failed_ips.values())

    if highest_failure_count >= CRITICAL_THRESHOLD:
        return "CRITICAL"

    elif highest_failure_count >= WARNING_THRESHOLD:
        return "WARNING"

    else:
        return "HEALTHY"


# --------------------------------------------------
# Generate security report
# --------------------------------------------------

def generate_report(
    successful_logins,
    failed_logins,
    invalid_users,
    successful_ips,
    failed_ips
):

    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    status = determine_status(failed_ips)

    suspicious_ips = detect_suspicious_ips(failed_ips)

    lines = []

    lines.append("=" * 62)
    lines.append("             LINUX SSH SECURITY REPORT")
    lines.append("=" * 62)

    lines.append(f"Generated              : {timestamp}")
    lines.append(f"Hostname               : {hostname}")

    lines.append("-" * 62)

    lines.append(
        f"Successful SSH Logins  : {len(successful_logins)}"
    )

    lines.append(
        f"Failed SSH Logins      : {len(failed_logins)}"
    )

    lines.append(
        f"Invalid User Attempts  : {len(invalid_users)}"
    )

    lines.append("-" * 62)

    lines.append("SUCCESSFUL LOGIN SOURCE IPs")

    if successful_ips:

        for ip, count in successful_ips.most_common():
            lines.append(
                f"  {ip:<20} {count} successful login(s)"
            )

    else:
        lines.append("  No successful SSH logins found.")

    lines.append("-" * 62)

    lines.append("FAILED LOGIN SOURCE IPs")

    if failed_ips:

        for ip, count in failed_ips.most_common():

            if count >= CRITICAL_THRESHOLD:
                ip_status = "CRITICAL"

            elif count >= WARNING_THRESHOLD:
                ip_status = "WARNING"

            else:
                ip_status = "NORMAL"

            lines.append(
                f"  {ip:<20} {count} failure(s) [{ip_status}]"
            )

    else:
        lines.append("  No failed SSH logins found.")

    lines.append("-" * 62)

    lines.append("SUSPICIOUS SOURCE IPs")

    if suspicious_ips:

        for ip, count in suspicious_ips:
            lines.append(
                f"  {ip:<20} {count} failed authentication attempt(s)"
            )

    else:
        lines.append("  No suspicious source IPs detected.")

    lines.append("-" * 62)

    lines.append(f"SECURITY STATUS        : {status}")

    lines.append("=" * 62)

    report = "\n".join(lines)

    print(report)

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    with open(REPORT_FILE, "w") as file:
        file.write(report + "\n")

    print()
    print(f"Report saved to: {REPORT_FILE}")


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    print("Reading SSH authentication logs...")
    print()

    logs = get_ssh_logs()

    if not logs:
        print("No SSH logs were found.")
        return

    (
        successful_logins,
        failed_logins,
        invalid_users,
        successful_ips,
        failed_ips
    ) = analyze_logs(logs)

    generate_report(
        successful_logins,
        failed_logins,
        invalid_users,
        successful_ips,
        failed_ips
    )


if __name__ == "__main__":
    main()
