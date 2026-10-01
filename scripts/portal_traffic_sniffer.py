#!/usr/bin/env python3
"""
Meta Portal Real-Time Network Traffic Inspector
------------------------------------------------
Captures and decodes DNS requests, TLS Handshakes (SNI), and HTTP traffic
from the 10-inch Portal to see exactly what servers it is trying to reach.
"""

import sys
import os
import subprocess
import re

def main():
    print("=" * 70)
    print("        META PORTAL REAL-TIME NETWORK TRAFFIC INSPECTOR")
    print("=" * 70)
    
    # Check interfaces
    if len(sys.argv) > 1:
        iface = sys.argv[1]
    else:
        # Default to bridge100 (Mac Hotspot) or en0 (Wi-Fi)
        out = subprocess.getoutput("ifconfig -l")
        if "bridge100" in out:
            iface = "bridge100"
        else:
            iface = "en0"

    print(f"[*] Listening on interface: {iface}")
    print("[*] Filtering for DNS queries, HTTP calls, and TLS handshakes...")
    print("[*] Trigger the action on your 10-inch Portal now (tap 'Next'/Room).")
    print("-" * 70)

    # tcpdump command
    # Filter: DNS (port 53) or HTTP (port 80) or HTTPS (port 443)
    cmd = [
        "sudo", "tcpdump", "-i", iface, "-n", "-l", "-s", "0",
        "udp port 53 or tcp port 80 or (tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16))"
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in proc.stdout:
            line = line.strip()
            # Parse DNS Query
            if " A? " in line or " AAAA? " in line:
                match = re.search(r'A\??\s+([a-zA-Z0-9\.\-_]+)', line)
                if match:
                    print(f"\033[93m[DNS LOOKUP]\033[0m Request for domain: \033[1m{match.group(1)}\033[0m")
            # Parse General packet summary
            elif "443" in line and "Flags [S]" in line:
                match = re.search(r'([0-9\.]+)\.[0-9]+ > ([0-9\.]+)\.443', line)
                if match:
                    print(f"\033[96m[HTTPS CONNECT]\033[0m Client {match.group(1)} -> Server {match.group(2)}:443")
            elif "80" in line and "Flags [S]" in line:
                match = re.search(r'([0-9\.]+)\.[0-9]+ > ([0-9\.]+)\.80', line)
                if match:
                    print(f"\033[92m[HTTP CONNECT]\033[0m Client {match.group(1)} -> Server {match.group(2)}:80")
    except KeyboardInterrupt:
        print("\n[*] Stopping traffic capture...")
        if proc:
            proc.terminate()

if __name__ == "__main__":
    main()
