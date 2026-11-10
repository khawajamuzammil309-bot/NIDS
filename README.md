# Network Intrusion Detection System - NIDS

A Python-based Network Intrusion Detection System made for learning and internship purpose only.

Disclaimer: This is a SAFE LAB VERSION by M. It is for detecting attacks on your own lab network only. It was tested only on my own Kali Linux machine.

## What I Learned

- How Intrusion Detection Systems work
- How to detect Port Scanning, SYN Flood, Ping Flood and Brute Force attacks
- How to inspect packets for SQL Injection and XSS signatures
- How to block attacker IP and save alerts in log and CSV

## Features

- Real-time packet sniffing with Scapy
- Port Scan Detection
- SYN Flood and ICMP Ping Flood Detection
- Brute Force Connection Detection
- Malicious Payload Signature Detection
- Auto IP Blocking with iptables
- Alerts saved in log file and CSV file
- Blacklist file for attackers
- Attack summary dashboard and chart

## How It Works

1. NIDS starts sniffing packets on selected interface
2. Every packet is checked against detection rules
3. If attack is found, alert is printed and saved in log and CSV
4. Attacker IP is added to blacklist.txt
5. If block mode is ON, attacker IP is blocked with iptables
6. Press Ctrl + C to stop and see summary dashboard

## How To Run

Run with root permission: sudo python3 nids.py
Run with interface: sudo python3 nids.py -i eth0
Run with auto block: sudo python3 nids.py --block
Run with chart: sudo python3 nids.py --visualize

## Files Created

nids_alerts.log - Text alerts log
nids_alerts.csv - CSV alerts log
blacklist.txt - Blocked attacker IPs
nids_attack_summary.png - Attack chart

## How To Stay Safe

- Use firewall and IDS on your network
- Keep system updated
- Use strong passwords and 2FA
- Monitor unusual network traffic

## Author

Khawaja Muzammil
Cyber Security Intern
