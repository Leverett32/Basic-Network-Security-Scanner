#!/usr/bin/env python3
"""
========================================
  Basic Network Security Scanner v1.0
  Portfolio Project - Cybersecurity Tool
  For AUTHORIZED testing only
========================================

How to run:
    python3 security_scanner.py

Requirements:
    No external libraries needed — uses Python's built-in modules only.

What it does:
    1. Scans a target host for open ports
    2. Identifies services running on those ports
    3. Flags potentially risky open ports with warnings
    4. Generates a text-based security report you can save

Great for:
    - Portfolio demonstrations
    - Learning how port scanning works
    - Basic recon on systems you own or have permission to test
"""

import socket
import sys
import datetime
from concurrent.futures import ThreadPoolExecutor


# ─────────────────────────────────────────────
#  RISKY PORT DEFINITIONS
#  These are common ports attackers target.
#  Flagging them helps clients understand risk.
# ─────────────────────────────────────────────
RISKY_PORTS = {
    21:   "FTP — Unencrypted file transfer. Consider switching to SFTP.",
    22:   "SSH — Secure Shell. Ensure strong passwords or key-based auth.",
    23:   "Telnet — Completely unencrypted. Replace with SSH immediately.",
    25:   "SMTP — Mail server. Ensure it's not an open relay.",
    80:   "HTTP — Unencrypted web traffic. Consider enforcing HTTPS.",
    110:  "POP3 — Unencrypted email retrieval. Use POP3S instead.",
    135:  "RPC — Common attack vector on Windows systems.",
    139:  "NetBIOS — Often exploited for lateral movement.",
    443:  "HTTPS — Encrypted web (good). Ensure valid certificate.",
    445:  "SMB — File sharing. Frequent ransomware target (e.g. WannaCry).",
    1433: "MSSQL — Database exposed. Restrict access immediately.",
    3306: "MySQL — Database exposed. Should not be publicly accessible.",
    3389: "RDP — Remote Desktop. High-value target, enable NLA and MFA.",
    5432: "PostgreSQL — Database exposed. Restrict to localhost or VPN.",
    5900: "VNC — Remote desktop, often unencrypted. Use with a VPN.",
    8080: "HTTP-Alt — Secondary web server. Verify it's intentional.",
    8443: "HTTPS-Alt — Secondary secure server. Verify if expected.",
}


def scan_port(host, port):
    """
    Try to connect to a single port.
    Returns the port number if open, None if closed.
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout per port
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return port  # Port is open
    except socket.error:
        pass
    return None  # Port is closed or filtered


def get_service_name(port):
    """
    Try to identify the service name for a given port.
    Falls back to 'Unknown' if not found.
    """
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def resolve_host(host):
    """
    Resolve a hostname to an IP address.
    Returns the IP or exits if the host can't be reached.
    """
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f"\n[-] ERROR: Could not resolve host '{host}'")
        print("    Check the hostname or IP and try again.")
        sys.exit(1)


def scan_host(ip, port_range):
    """
    Scan all ports in the given range using multi-threading for speed.
    Returns a list of (port, service_name) tuples for open ports.
    """
    start_port, end_port = port_range
    total_ports = end_port - start_port + 1
    ports_to_scan = range(start_port, end_port + 1)

    print(f"\n[*] Target IP    : {ip}")
    print(f"[*] Port Range   : {start_port} - {end_port} ({total_ports} ports)")
    print(f"[*] Scan Started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n{'─' * 50}")
    print(f"  {'PORT':<10} {'STATE':<10} {'SERVICE'}")
    print(f"{'─' * 50}")

    open_ports = []

    # ThreadPoolExecutor scans multiple ports simultaneously (much faster)
    with ThreadPoolExecutor(max_workers=150) as executor:
        results = list(executor.map(lambda p: scan_port(ip, p), ports_to_scan))

    for port in results:
        if port is not None:
            service = get_service_name(port)
            open_ports.append((port, service))
            marker = "[!]" if port in RISKY_PORTS else "[+]"
            print(f"  {marker} {port:<7} {'OPEN':<10} {service}")

    print(f"{'─' * 50}")
    return open_ports


def generate_report(host, ip, open_ports, port_range):
    """
    Build a formatted security report string.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []

    lines.append("=" * 60)
    lines.append("           NETWORK SECURITY SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"  Target Host  : {host}")
    lines.append(f"  Resolved IP  : {ip}")
    lines.append(f"  Port Range   : {port_range[0]} - {port_range[1]}")
    lines.append(f"  Scan Date    : {now}")
    lines.append(f"  Open Ports   : {len(open_ports)}")
    lines.append("=" * 60)

    if not open_ports:
        lines.append("\n  No open ports detected in the scanned range.")
    else:
        lines.append("\nOPEN PORTS SUMMARY")
        lines.append("─" * 40)
        lines.append(f"  {'PORT':<10} {'SERVICE'}")
        lines.append("─" * 40)
        for port, service in open_ports:
            lines.append(f"  {port:<10} {service}")

        # Security warnings section
        flagged = [(p, s) for p, s in open_ports if p in RISKY_PORTS]
        if flagged:
            lines.append("\n")
            lines.append("SECURITY WARNINGS")
            lines.append("─" * 40)
            for port, service in flagged:
                lines.append(f"\n  [!] Port {port} ({service})")
                lines.append(f"      → {RISKY_PORTS[port]}")

        # Risk level summary
        lines.append("\n")
        lines.append("RISK ASSESSMENT")
        lines.append("─" * 40)
        risk_count = len(flagged)
        if risk_count == 0:
            lines.append("  ✓ No high-risk ports detected.")
        elif risk_count <= 2:
            lines.append(f"  ⚠ LOW-MEDIUM RISK: {risk_count} potentially risky port(s) open.")
        elif risk_count <= 5:
            lines.append(f"  ⚠ MEDIUM-HIGH RISK: {risk_count} risky ports detected.")
        else:
            lines.append(f"  ✗ HIGH RISK: {risk_count} risky ports open. Immediate review recommended.")

    lines.append("\n" + "=" * 60)
    lines.append("  DISCLAIMER: Only scan systems you own or have explicit")
    lines.append("  written permission to test. Unauthorized scanning is")
    lines.append("  illegal under the CFAA and similar laws worldwide.")
    lines.append("=" * 60)

    return "\n".join(lines)


def get_port_range():
    """
    Prompt user for a port range with a sensible default.
    """
    print("\n  Common ranges:")
    print("    1-1024   = Well-known ports (default, recommended)")
    print("    1-65535  = Full scan (slower)")
    print("    80-443   = Web ports only")

    choice = input("\nEnter port range (e.g. 1-1024) or press Enter for default: ").strip()

    if not choice:
        return (1, 1024)

    try:
        parts = choice.split("-")
        start = int(parts[0])
        end = int(parts[1])
        if start < 1 or end > 65535 or start > end:
            raise ValueError
        return (start, end)
    except (ValueError, IndexError):
        print("[-] Invalid input. Using default range 1-1024.")
        return (1, 1024)


def main():
    # Banner
    print("\n" + "=" * 50)
    print("    Basic Network Security Scanner v1.0")
    print("    ⚠  For authorized use only  ⚠")
    print("=" * 50)

    # Get target
    host = input("\nEnter target IP or hostname: ").strip()
    if not host:
        print("[-] No host entered. Exiting.")
        sys.exit(1)

    # Resolve hostname
    ip = resolve_host(host)
    if host != ip:
        print(f"[*] Resolved '{host}' → {ip}")

    # Get port range
    port_range = get_port_range()

    # Run scan
    open_ports = scan_host(ip, port_range)

    # Summary
    print(f"\n[*] Scan complete. {len(open_ports)} open port(s) found.")

    # Generate and display report
    report = generate_report(host, ip, open_ports, port_range)
    print("\n" + report)

    # Offer to save
    save = input("\nSave report to file? (y/n): ").strip().lower()
    if save == "y":
        filename = f"scan_{host.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w") as f:
            f.write(report)
        print(f"[+] Report saved to: {filename}")
    else:
        print("[*] Report not saved.")

    print("\n[*] Done. Stay ethical, stay legal.\n")


if __name__ == "__main__":
    main()
