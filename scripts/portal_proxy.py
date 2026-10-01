#!/usr/bin/env python3
"""
Simple HTTP/HTTPS Proxy for Meta Portal Traffic Analysis
Logs every single HTTP request and CONNECT domain the Portal visits.
"""

import http.server
import socketserver
import urllib.request
import select
import socket
import datetime

PORT = 8080

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_CONNECT(self):
        # HTTPS Tunneling
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        client_ip = self.client_address[0]
        host, port = self.path.split(":")
        port = int(port)
        print(f"\033[96m[{ts}] [HTTPS VIA PROXY]\033[0m From {client_ip} -> \033[1m{host}:{port}\033[0m")
        
        try:
            s = socket.create_connection((host, port), timeout=10)
            self.send_response(200, "Connection Established")
            self.end_headers()
            
            conns = [self.connection, s]
            while True:
                r, w, x = select.select(conns, [], conns, 10)
                if x or not r:
                    break
                for c in r:
                    other = s if c is self.connection else self.connection
                    data = c.recv(8192)
                    if not data:
                        return
                    other.sendall(data)
        except Exception as e:
            print(f"[-] Connection to {host}:{port} failed: {e}")
            self.send_error(502)

    def do_GET(self):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        client_ip = self.client_address[0]
        print(f"\033[92m[{ts}] [HTTP VIA PROXY]\033[0m From {client_ip} -> \033[1m{self.path}\033[0m")
        try:
            req = urllib.request.Request(self.path, headers=dict(self.headers))
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.send_response(resp.status)
                for k, v in resp.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.read())
        except Exception as e:
            self.send_error(502)

def main():
    print("=" * 70)
    print(f"[*] PORTAL HTTP/HTTPS PROXY RUNNING ON PORT {PORT}")
    print(f"[*] On the Portal, set Wi-Fi Proxy to Manual:")
    print(f"    Proxy Host: (Your Mac's IP)")
    print(f"    Proxy Port: {PORT}")
    print("=" * 70)
    with socketserver.ThreadingTCPServer(("", PORT), ProxyHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping Proxy...")

if __name__ == "__main__":
    main()
