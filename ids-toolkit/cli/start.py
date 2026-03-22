import argparse
import sys
import time
from pathlib import Path


base_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(base_dir))

from core.sniffer import PacketSniffer
from core.analyzer import Analyzer
from cli.dashboard import Dashboard
from utils.colors import CLIColors

def main():
    parser = argparse.ArgumentParser(description="Samuel Network Intrusion Detection System (IDS)")
    parser.add_argument("--interface", type=str, help="Network interface to sniff on (e.g., eth0, wlan0)", default=None)
    parser.add_argument("--log-level", type=str, help="Log level (verbose, info)", default="info")
    
    args = parser.parse_args()
    
    CLIColors.print_info("Initializing Samuel IDS...")
    
    if args.interface:
        CLIColors.print_info(f"Using interface: {args.interface}")
    else:
        CLIColors.print_warning("No interface specified, relying on scapy default.")

    dashboard = Dashboard()
    
    analyzer = Analyzer(callback=dashboard.add_event)
    sniffer = PacketSniffer(interface=args.interface, analyzer=analyzer)
    
    CLIColors.print_success("Starting packet sniffer...")
    sniffer.start()
    
    CLIColors.print_info("Launching dashboard. Press Ctrl+C to stop.")
    time.sleep(1)
    
    try:
        dashboard.run()
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        CLIColors.print_info("IDS shut down cleanly.")

if __name__ == "__main__":
    main()
