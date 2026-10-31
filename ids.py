#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 4: Network Intrusion Detection System (NIDS)
A feature-rich NIDS using Python and Scapy to detect port scans, floods, brute-force attempts,
and malicious payload signatures, complete with real-time alerts, automated IP blocking, and CSV/log exports.
"""

import argparse
import csv
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Global Statistics & Tracking
total_packets = 0
alert_counter = Counter()
blocked_ips = set()
packet_timestamps = defaultdict(deque)  # Tracks IP packet rates for floods
port_scan_tracker = defaultdict(lambda: deque())  # Tracks (timestamp, dport) for port scanning
brute_force_tracker = defaultdict(deque)  # Tracks authentication port connections

# Signature patterns for web attack / injection payloads
SUSPICIOUS_PATTERNS = [
    (re.compile(r"(?i)(union\s+select|select\s+.*\s+from|or\s+1=1|drop\s+table)", re.IGNORECASE), "SQL Injection Attempt"),
    (re.compile(r"(?i)(<script>|javascript:|alert\()", re.IGNORECASE), "Cross-Site Scripting (XSS)"),
    (re.compile(r"(?i)(/etc/passwd|/etc/shadow|cmd\.exe|powershell)", re.IGNORECASE), "Directory Traversal / Command Injection"),
    (re.compile(r"(?i)(admin|login|passwd|password)\b", re.IGNORECASE), "Sensitive Keyword Exposure"),
]

# Sensitive authentication ports (SSH, FTP, Telnet, RDP, Web Login)
AUTH_PORTS = {21, 22, 23, 3389, 80, 443, 8080}


def trigger_alert(attacker_ip, target_ip, attack_type, severity, details, config):
    """Logs alerts, triggers IP blocking, and saves statistics."""
    global blocked_ips
    alert_counter[attack_type] += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Print formatted alert to terminal
    print(f"\n[ALERT] [{timestamp}] [{severity}] {attack_type}")
    print(f"        Attacker: {attacker_ip} --> Target: {target_ip}")
    print(f"        Details : {details}")

    # 2. Write alert to standard log file
    log_file = config["log_file"]
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] [{severity}] {attack_type} | Attacker: {attacker_ip} | Target: {target_ip} | Details: {details}\n")

    # 3. Write alert to CSV log file
    csv_file = config["csv_file"]
    file_exists = os.path.exists(csv_file)
    with open(csv_file, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Severity", "Attack_Type", "Attacker_IP", "Target_IP", "Details"])
        writer.writerow([timestamp, severity, attack_type, attacker_ip, target_ip, details])

    # 4. Response Mechanism: Blacklist & iptables blocking
    if attacker_ip not in blocked_ips and attacker_ip != "127.0.0.1":
        blocked_ips.add(attacker_ip)

        # Write to blacklist file
        with open("blacklist.txt", "a") as bf:
            bf.write(f"{timestamp} - {attacker_ip} ({attack_type})\n")
        print(f"  [+] {attacker_ip} added to blacklist.txt")

        # Block via Linux iptables if enabled
        if config["enable_block"]:
            try:
                subprocess.run(
                    ["iptables", "-A", "INPUT", "-s", attacker_ip, "-j", "DROP"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"  [FIREWALL] Successfully blocked {attacker_ip} via iptables!")
            except Exception as e:
                print(f"  [!] Failed to execute iptables rule: {e}")


def cleanup_tracker(tracker, current_time, window_seconds):
    """Removes records older than the sliding window threshold."""
    while tracker and (current_time - tracker[0]) > window_seconds:
        tracker.popleft()


def analyze_packet(packet, config):
    """Analyzes each captured packet against NIDS signatures and rate rules."""
    global total_packets
    total_packets += 1
    current_time = time.time()

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    threshold_mult = config["threshold"]

    # -------------------------------------------------------------
    # Rule 1: ICMP Ping Flood Detection
    # -------------------------------------------------------------
    if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
        key = f"icmp_{src_ip}"
        packet_timestamps[key].append(current_time)
        cleanup_tracker(packet_timestamps[key], current_time, window_seconds=2)

        icmp_threshold = int(20 * threshold_mult)
        if len(packet_timestamps[key]) > icmp_threshold:
            trigger_alert(
                src_ip, dst_ip, "ICMP / Ping Flood", "HIGH",
                f"Rate exceeded: {len(packet_timestamps[key])} ICMP packets in 2s (Threshold: {icmp_threshold})",
                config
            )
            packet_timestamps[key].clear()

    # -------------------------------------------------------------
    # Rule 2: TCP SYN Flood / DoS Detection
    # -------------------------------------------------------------
    if TCP in packet:
        # Check SYN flag (SYN=2) without ACK flag
        if packet[TCP].flags == "S":
            key = f"syn_{src_ip}"
            packet_timestamps[key].append(current_time)
            cleanup_tracker(packet_timestamps[key], current_time, window_seconds=3)

            syn_threshold = int(25 * threshold_mult)
            if len(packet_timestamps[key]) > syn_threshold:
                trigger_alert(
                    src_ip, dst_ip, "SYN Flood (DoS)", "CRITICAL",
                    f"Rate exceeded: {len(packet_timestamps[key])} SYN requests in 3s (Threshold: {syn_threshold})",
                    config
                )
                packet_timestamps[key].clear()

        # -------------------------------------------------------------
        # Rule 3: Port Scanning Detection
        # -------------------------------------------------------------
        dport = packet[TCP].dport
        ps_tracker = port_scan_tracker[src_ip]
        ps_tracker.append((current_time, dport))
        
        # Cleanup ports older than 5 seconds
        while ps_tracker and (current_time - ps_tracker[0][0]) > 5:
            ps_tracker.popleft()

        unique_ports = {port for _, port in ps_tracker}
        port_threshold = int(10 * threshold_mult)
        if len(unique_ports) > port_threshold:
            trigger_alert(
                src_ip, dst_ip, "Port Scanning", "HIGH",
                f"Accessed {len(unique_ports)} unique ports within 5s (Threshold: {port_threshold})",
                config
            )
            ps_tracker.clear()

        # -------------------------------------------------------------
        # Rule 4: Brute Force Attempt Detection
        # -------------------------------------------------------------
        if dport in AUTH_PORTS and packet[TCP].flags == "S":
            bf_key = f"bf_{src_ip}"
            brute_force_tracker[bf_key].append(current_time)
            cleanup_tracker(brute_force_tracker[bf_key], current_time, window_seconds=10)

            bf_threshold = int(12 * threshold_mult)
            if len(brute_force_tracker[bf_key]) > bf_threshold:
                trigger_alert(
                    src_ip, dst_ip, "Brute Force Connection Attempt", "MEDIUM",
                    f"{len(brute_force_tracker[bf_key])} attempts on auth port {dport} in 10s (Threshold: {bf_threshold})",
                    config
                )
                brute_force_tracker[bf_key].clear()

    # -------------------------------------------------------------
    # Rule 5: Malicious Payload Signature Inspection
    # -------------------------------------------------------------
    if Raw in packet:
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            for pattern, attack_name in SUSPICIOUS_PATTERNS:
                if pattern.search(payload):
                    # Clean payload snippet for safe display
                    clean_snippet = payload.strip().replace("\n", " ").replace("\r", "")[:50]
                    trigger_alert(
                        src_ip, dst_ip, attack_name, "CRITICAL",
                        f"Signature match found in payload: '{clean_snippet}...'",
                        config
                    )
                    break
        except Exception:
            pass


def print_dashboard():
    """Displays real-time NIDS statistics dashboard on exit or demand."""
    print("\n" + "=" * 65)
    print("               NIDS LIVE DETECTION DASHBOARD SUMMARY              ")
    print("=" * 65)
    print(f" Total Network Packets Inspected : {total_packets}")
    print(f" Total Security Alerts Raised   : {sum(alert_counter.values())}")
    print(f" Unique Attackers Blacklisted   : {len(blocked_ips)}")
    print("-" * 65)
    print(" ATTACK BREAKDOWN:")
    if alert_counter:
        for attack, count in alert_counter.items():
            print(f"  - {attack:<30} : {count} incident(s)")
    else:
        print("  - No malicious activity detected.")
    print("-" * 65)
    print(" BLACKLISTED IPs:")
    if blocked_ips:
        for ip in blocked_ips:
            print(f"  - {ip}")
    else:
        print("  - None")
    print("=" * 65)


def visualize_attacks():
    """Generates a Matplotlib bar/pie chart of detected attack types."""
    try:
        import matplotlib.pyplot as plt

        if not alert_counter:
            print("[*] No attacks detected. Skipping chart generation.")
            return

        categories = list(alert_counter.keys())
        counts = list(alert_counter.values())

        plt.figure(figsize=(10, 5))

        # Bar chart
        plt.subplot(1, 2, 1)
        plt.bar(categories, counts, color="crimson")
        plt.title("Detected Attack Distribution")
        plt.xlabel("Attack Type")
        plt.ylabel("Incident Count")
        plt.xticks(rotation=45, ha="right")

        # Pie chart
        plt.subplot(1, 2, 2)
        plt.pie(counts, labels=categories, autopct="%1.1f%%", colors=["#ff9999","#66b3ff","#99ff99","#ffcc99"])
        plt.title("Attack Type Share")

        plt.tight_layout()
        chart_filename = "nids_attack_summary.png"
        plt.savefig(chart_filename)
        print(f"[*] Visual attack summary saved to '{chart_filename}'")
        plt.show()
    except ImportError:
        print("[!] Matplotlib is not installed. Install with 'pip install matplotlib' to view charts.")
    except Exception as e:
        print(f"[!] Chart display failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Task 4: Network Intrusion Detection System (NIDS)")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface to sniff (e.g. eth0, wlan0).")
    parser.add_argument("-t", "--threshold", type=float, default=1.0, help="Sensitivity multiplier (default 1.0; lower = more sensitive).")
    parser.add_argument("-l", "--log", type=str, default="nids_alerts.log", help="Output text log file path (default: nids_alerts.log).")
    parser.add_argument("--csv", type=str, default="nids_alerts.csv", help="Output CSV log file path (default: nids_alerts.csv).")
    parser.add_argument("--block", action="store_true", help="Enable automatic iptables IP blocking for detected attackers.")
    parser.add_argument("--visualize", action="store_true", help="Show matplotlib attack charts upon exit.")

    args = parser.parse_args()

    config = {
        "threshold": args.threshold,
        "log_file": args.log,
        "csv_file": args.csv,
        "enable_block": args.block
    }

    print("[*] Starting NIDS Engine...")
    print(f"[*] Sniffing Interface : {args.interface if args.interface else 'Default system interface'}")
    print(f"[*] Log File          : {args.log}")
    print(f"[*] CSV Export        : {args.csv}")
    print(f"[*] Auto IP Blocking  : {'ENABLED (iptables)' if args.block else 'DISABLED'}")
    print("[*] Rules active      : Port Scan, SYN Flood, Ping Flood, Brute Force, Payload Injection")
    print("-" * 65)
    print("[*] Press Ctrl+C to stop the NIDS and view summary stats.")

    try:
        sniff(
            iface=args.interface,
            prn=lambda pkt: analyze_packet(pkt, config),
            store=False
        )
    except KeyboardInterrupt:
        print("\n[*] Stopping NIDS engine...")
    except PermissionError:
        print("\n[!] Error: Superuser/Root permissions required for packet capture & iptables.")
        print("    Run with: sudo python3 nids.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")
    finally:
        print_dashboard()
        if args.visualize:
            visualize_attacks()


if __name__ == "__main__":
    main()
