# 🔍 Basic Network Security Scanner

A lightweight, multi-threaded TCP port scanner written in pure Python. Designed as a portfolio project for cybersecurity learners and practitioners — no external libraries required.

> ⚠️ **For authorized use only.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Flagged Ports Reference](#flagged-ports-reference)
- [How It Works](#how-it-works)
- [Safe Testing Targets](#safe-testing-targets)
- [Roadmap](#roadmap)
- [Legal Disclaimer](#legal-disclaimer)
- [Author](#author)

---

## Overview

This tool performs TCP connect scans against a target host across a user-defined port range. It identifies open ports, maps them to known services, flags high-risk ports with plain-English security warnings, and generates a structured report you can save to a file.

Built for:
- Portfolio demonstrations
- Learning how port scanning and network reconnaissance work
- Basic security assessments on systems you own or are authorized to test

---

## Features

- ✅ **Zero dependencies** — uses Python's built-in `socket`, `sys`, `datetime`, and `concurrent.futures` only
- ⚡ **Multi-threaded scanning** — uses `ThreadPoolExecutor` with 150 workers for fast parallel port scanning
- 🔍 **Service identification** — resolves port numbers to service names (HTTP, SSH, FTP, etc.)
- ⚠️ **Risk flagging** — automatically identifies and warns on 17 commonly exploited ports
- 📊 **Risk assessment summary** — rates overall exposure (Low / Medium-High / High Risk)
- 💾 **Exportable reports** — save findings to a timestamped `.txt` file
- 🌐 **Hostname resolution** — accepts both IP addresses and domain names

---

## Requirements

- Python 3.6 or higher
- No external packages needed

Check your Python version:

```bash
python3 --version
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-security-scanner.git

# Navigate into the directory
cd network-security-scanner

# No pip install required — just run it
python3 security_scanner.py
```

---

## Usage

```bash
python3 security_scanner.py
```

The tool will prompt you interactively:

```
==================================================
    Basic Network Security Scanner v1.0
    ⚠  For authorized use only  ⚠
==================================================

Enter target IP or hostname: 192.168.1.1

  Common ranges:
    1-1024   = Well-known ports (default, recommended)
    1-65535  = Full scan (slower)
    80-443   = Web ports only

Enter port range (e.g. 1-1024) or press Enter for default:
```

**Inputs:**

| Prompt | Example | Notes |
|---|---|---|
| Target IP or hostname | `192.168.1.1` or `scanme.nmap.org` | IPv4 or resolvable hostname |
| Port range | `1-1024` | Default if left blank. Max: `1-65535` |

---

## Example Output

```
[*] Target IP    : 192.168.1.1
[*] Port Range   : 1 - 1024 (1024 ports)
[*] Scan Started : 2026-05-24 14:32:01

──────────────────────────────────────────────────
  PORT       STATE      SERVICE
──────────────────────────────────────────────────
  [+] 80     OPEN       http
  [!] 23     OPEN       telnet
  [!] 445    OPEN       microsoft-ds
──────────────────────────────────────────────────

[*] Scan complete. 3 open port(s) found.

============================================================
           NETWORK SECURITY SCAN REPORT
============================================================
  Target Host  : 192.168.1.1
  Resolved IP  : 192.168.1.1
  Port Range   : 1 - 1024
  Scan Date    : 2026-05-24 14:32:08
  Open Ports   : 3
============================================================

OPEN PORTS SUMMARY
────────────────────────────────────────
  PORT       SERVICE
────────────────────────────────────────
  80         http
  23         telnet
  445        microsoft-ds

SECURITY WARNINGS
────────────────────────────────────────

  [!] Port 23 (telnet)
      → Telnet — Completely unencrypted. Replace with SSH immediately.

  [!] Port 445 (microsoft-ds)
      → SMB — File sharing. Frequent ransomware target (e.g. WannaCry).

RISK ASSESSMENT
────────────────────────────────────────
  ⚠ LOW-MEDIUM RISK: 2 potentially risky port(s) open.

Save report to file? (y/n): y
[+] Report saved to: scan_192_168_1_1_20260524_143208.txt
```

---

## Flagged Ports Reference

The scanner automatically flags the following ports with security advisories:

| Port | Service | Risk |
|---|---|---|
| 21 | FTP | Unencrypted file transfer — use SFTP instead |
| 22 | SSH | Ensure key-based auth; disable password login |
| 23 | Telnet | Completely unencrypted — replace with SSH immediately |
| 25 | SMTP | Ensure server is not an open relay |
| 80 | HTTP | Unencrypted web traffic — enforce HTTPS |
| 110 | POP3 | Unencrypted email — use POP3S |
| 135 | RPC | Common attack vector on Windows systems |
| 139 | NetBIOS | Often exploited for lateral movement |
| 443 | HTTPS | Good — verify certificate validity |
| 445 | SMB | Frequent ransomware target (WannaCry, NotPetya) |
| 1433 | MSSQL | Database exposed — restrict access immediately |
| 3306 | MySQL | Should not be publicly accessible |
| 3389 | RDP | High-value target — enable NLA and MFA |
| 5432 | PostgreSQL | Restrict to localhost or VPN only |
| 5900 | VNC | Often unencrypted — tunnel through VPN |
| 8080 | HTTP-Alt | Verify secondary web server is intentional |
| 8443 | HTTPS-Alt | Verify secondary secure server is intentional |

---

## How It Works

```
User Input (host + port range)
        │
        ▼
  Hostname Resolution
  socket.gethostbyname()
        │
        ▼
  Multi-threaded Port Scan
  ThreadPoolExecutor (150 workers)
  socket.connect_ex() per port
        │
        ▼
  Open Port Collection
  Service name lookup via
  socket.getservbyport()
        │
        ▼
  Risk Flag Evaluation
  Match against RISKY_PORTS dict
        │
        ▼
  Report Generation
  Console output + optional .txt save
```

**Scan method:** TCP Connect Scan — attempts a full TCP handshake on each port. If the connection succeeds (returns 0), the port is open. This is the most reliable and detectable form of port scanning. It does not use raw sockets or SYN packets, so no root/admin privileges are required.

**Threading:** Uses Python's `ThreadPoolExecutor` with 150 concurrent workers, significantly reducing scan time compared to sequential scanning.

---

## Safe Testing Targets

Always get written permission before scanning any system you don't own. The following are publicly available legal test targets:

| Target | Notes |
|---|---|
| `localhost` / `127.0.0.1` | Your own machine — always safe |
| Your home router (e.g. `192.168.1.1`) | Your own network — safe |
| `scanme.nmap.org` | Nmap's official legal test host |

---

## Roadmap

Planned future improvements:

- [ ] UDP port scanning support
- [ ] OS fingerprinting (TTL-based)
- [ ] CVE lookup integration for flagged services
- [ ] HTML report export
- [ ] Command-line argument support (`--host`, `--range`, `--output`)
- [ ] Verbose mode with connection timing
- [ ] JSON output for pipeline integration

---

## Legal Disclaimer

This tool is provided for **educational and authorized security testing purposes only.**

- ❌ Do **not** scan networks, hosts, or systems without explicit written permission from the owner
- ❌ Do **not** use this tool against cloud infrastructure (AWS, Azure, GCP) without following their specific security testing policies
- ✅ Always obtain written authorization before conducting any security assessment
- ✅ Consult local laws — unauthorized port scanning may be illegal in your jurisdiction regardless of intent

The author assumes **no liability** for misuse of this tool.

---

## Author

**Kevin Leverett**
Security Specialist → Cybersecurity Consultant
Charlotte, NC

- 📧 k.leverett32@gmail.com
- 💼 [LinkedIn](https://linkedin.com/in/kevin-leverett-8b1828128)
- 🔐 CompTIA Security+ | CySA+ | B.S. Cybersecurity (In Progress)

---

*Part of an ongoing cybersecurity portfolio. Built to demonstrate practical Python scripting, network fundamentals, and security assessment methodology.*
