def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection System (NIDS)")
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
