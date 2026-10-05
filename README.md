# Linux SSH Log Analyzer

A lightweight Linux security monitoring project built using Python on Red Hat Enterprise Linux (RHEL).

The tool analyzes SSH authentication logs from the systemd journal, identifies successful and failed login attempts, extracts source IP addresses, detects repeated authentication failures, and generates a security report.

## Project Architecture

```text
SSH Authentication
        |
        v
systemd Journal
        |
        v
journalctl
        |
        v
Python Log Analyzer
        |
        +---- Successful Logins
        +---- Failed Logins
        +---- Invalid Users
        +---- Source IP Analysis
        |
        v
Threshold Detection
        |
        +---- HEALTHY
        +---- WARNING
        +---- CRITICAL
        |
        v
Security Report
```

## Features

- Analyzes RHEL SSH authentication logs
- Detects successful SSH logins
- Detects failed password attempts
- Detects invalid-user events
- Extracts SSH source IP addresses
- Counts failed attempts by source IP
- Identifies suspicious IP addresses
- Classifies activity as HEALTHY, WARNING, or CRITICAL
- Generates a readable security report

## Detection Thresholds

The current thresholds are intended for lab/demo testing.

| Failed attempts from one IP | Status |
|---|---|
| 0-2 | HEALTHY |
| 3-4 | WARNING |
| 5+ | CRITICAL |

Production thresholds should be selected according to the environment and security requirements.

## Technologies Used

- Red Hat Enterprise Linux
- Python 3
- systemd journal
- journalctl
- OpenSSH
- Linux command-line utilities
- Git
- GitHub
- PuTTY
- VirtualBox

## Linux Commands Practiced

```bash
journalctl
grep
awk
sort
uniq
wc
tail
systemctl
find
```

Example manual investigation:

```bash
sudo journalctl -u sshd --no-pager | grep "Failed password"
```

Count failed authentication attempts:

```bash
sudo journalctl -u sshd --no-pager | grep "Failed password" | wc -l
```

Count failed attempts by source IP:

```bash
sudo journalctl -u sshd --no-pager | grep "Failed password" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -nr
```

## Running the Analyzer

Clone the repository and enter the project directory:

```bash
git clone <repository-url>
cd linux-log-analyzer
```

Run:

```bash
python3 log_analyzer.py
```

Depending on the system configuration, sudo authentication may be required because the program reads system journal logs.

## Example Output

```text
==============================================================
             LINUX SSH SECURITY REPORT
==============================================================
Successful SSH Logins  : 1
Failed SSH Logins      : 5
Invalid User Attempts  : 0
--------------------------------------------------------------
FAILED LOGIN SOURCE IPs
  10.0.2.2             5 failure(s) [CRITICAL]
--------------------------------------------------------------
SUSPICIOUS SOURCE IPs
  10.0.2.2             5 failed authentication attempt(s)
--------------------------------------------------------------
SECURITY STATUS        : CRITICAL
==============================================================
```

## What I Learned

This project helped me practice:

- Linux log investigation
- SSH authentication troubleshooting
- systemd journal analysis
- Linux text-processing pipelines
- Python automation
- Log parsing
- Source IP analysis
- Threshold-based detection
- Security monitoring fundamentals
- Git version control

## Disclaimer

This project is a learning and lab monitoring tool. It is not intended to replace production SIEM, IDS/IPS, or enterprise security monitoring platforms.

## Author

Akhilesh P
