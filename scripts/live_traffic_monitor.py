#!/usr/bin/env python3
"""
Passive DNS & HTTP/HTTPS Traffic Monitor for Meta Portal Diagnostics
Listens on bridge100 (Mac Hotspot) for all traffic from Portal (192.168.2.3).
"""

import sys
import os
import subprocess
import re
import datetime

PORTAL_IP = "192.168.2.3"
LOG_FILE = "/Users/kahnmndez/Documents/Portal/scripts/captured_traffic.log"

def main():
    print("=" * 75)
    print(f"[*] LISTENING ON HOTSPOT INTERFACE: bridge100 (Subnet 192.168.2.x)")
    print(f"[*] TARGET PORTAL DETECTED AT:      {PORTAL_IP} (Portal-F746F24816DF)")
    print(f"[*] LOG FILE:                       {LOG_FILE}")
    print("=" * 75)
    
    with open(LOG_FILE, "w") as f:
        f.write(f"=== Portal Traffic Capture on bridge100 Started at {datetime.datetime.now()} ===\n")

    # tcpdump on bridge100 capturing all packets to/from 192.168.2.3
    cmd = [
        "sudo", "tcpdump", "-i", "bridge100", "-n", "-l", "-s", "0",
        f"host {PORTAL_IP}"
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with open(LOG_FILE, "a", buffering=1) as f:
            for line in proc.stdout:
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                # Parse DNS Query
                if " A? " in line or " AAAA? " in line:
                    match = re.search(r'A\??\s+([a-zA-Z0-9\.\-_]+)', line)
                    if match:
                        domain = match.group(1)
                        entry = f"[{ts}] [PORTAL DNS QUERY] -> Domain: {domain}"
                        print(f"\033[93m{entry}\033[0m")
                        f.write(entry + "\n")
                # Parse TCP Connections (HTTPS / HTTP)
                elif "Flags [S]" in line:
                    match = re.search(r'([0-9\.]+)\.([0-9]+) > ([0-9\.]+)\.([0-9]+)', line)
                    if match:
                        src_ip, src_p, dst_ip, dst_p = match.groups()
                        entry = f"[{ts}] [PORTAL TCP CONNECT] Outbound -> {dst_ip}:{dst_p}"
                        print(f"\033[96m{entry}\033[0m")
                        f.write(entry + "\n")
                # Other packets
                else:
                    f.write(f"[{ts}] {line}\n")
    except KeyboardInterrupt:
        print("\n[*] Stopping monitor.")

if __name__ == "__main__":
    main()
