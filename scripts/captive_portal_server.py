#!/usr/bin/env python3
"""
Captive Portal Trigger & Escape Hub for Android 9 / Meta Portal
---------------------------------------------------------------
1. Redirects all port 80 traffic on bridge100 directly to 192.168.2.1:80
2. Blocks port 853 (DNS-over-TLS) so Android cannot bypass local routing
3. Responds with HTTP 302 to force Android into CaptivePortalLoginActivity
4. Serves HTML5 Fullscreen Video and System Navigation test harness on port 8080
"""

import sys
import os
import atexit
import signal
import subprocess
import threading
import http.server
import socketserver

MAC_IP = "192.168.2.1"
HTTP_PORT = 80
WEB_PORT = 8080
LOG_FILE = "/Users/kahnmndez/Documents/Portal/scripts/captive_portal.log"

def log(msg):
    print(msg, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")
            f.flush()
    except Exception:
        pass

def setup_pf():
    rules = (
        f"rdr pass on bridge100 inet proto tcp from any to any port 80 -> {MAC_IP} port {HTTP_PORT}\n"
        f"block drop quick on bridge100 proto tcp to any port 853\n"
    )
    try:
        subprocess.run(["pfctl", "-a", "captive_portal", "-f", "-"], input=rules, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pfctl", "-e"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("[+] Firewall active: Intercepting ALL Port 80 HTTP & disabling Port 853 DoT")
    except Exception as e:
        log(f"[-] Firewall setup error: {e}")

def cleanup_pf():
    try:
        subprocess.run(["pfctl", "-a", "captive_portal", "-F", "all"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("[+] Firewall rules cleaned up.")
    except Exception:
        pass

atexit.register(cleanup_pf)

HTML_PAYLOAD = """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Sign-In & Diagnostics</title>
    <style>
        body { font-family: -apple-system, Roboto, sans-serif; padding: 20px; background: #111; color: #fff; }
        .card { background: #222; padding: 15px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #333; }
        h2 { color: #4af; margin-top: 0; }
        video { width: 100%; max-height: 240px; background: #000; border-radius: 8px; }
        button, a.btn { display: inline-block; background: #007aff; color: #fff; padding: 12px 20px; border-radius: 8px; text-decoration: none; font-weight: bold; margin: 5px 0; border: none; font-size: 16px; }
        .text-box { background: #333; padding: 10px; border-radius: 6px; user-select: all; -webkit-user-select: all; font-size: 16px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Portal Diagnostics Console</h1>

    <div class="card">
        <h2>Vector 1: Fullscreen Video (Immersive Mode Escape)</h2>
        <p>Tap the Play button, then tap the <b>Fullscreen icon (⛶)</b>. Once fullscreen, swipe from the top or bottom edge to force the Android Status Bar and Navigation Bar (Home/Back) to appear.</p>
        <video controls autoplay loop playsinline>
            <source src="https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4" type="video/mp4">
        </video>
    </div>

    <div class="card">
        <h2>Vector 2: Text Selection & System Sharesheet</h2>
        <p>Long-press and highlight the text below. If the floating toolbar appears, tap <b>Share</b> to open the native Android Sharesheet:</p>
        <div class="text-box" contenteditable="true">
            Highlight this text and tap Share to open Android Settings or App Info
        </div>
    </div>

    <div class="card">
        <h2>Vector 3: External Links</h2>
        <p><a class="btn" href="https://www.google.com">Open Google</a></p>
        <p><a class="btn" href="https://support.google.com">Google Support (Search Box)</a></p>
    </div>
</body>
</html>
"""

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        log(f"\033[92m[CAPTIVE HIT!]\033[0m Portal requested: {self.headers.get('Host', '')}{self.path} -> Sending 302 Redirect")
        self.send_response(302)
        self.send_header("Location", f"http://{MAC_IP}:{WEB_PORT}/")
        self.end_headers()

class WebHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        log(f"\033[96m[PORTAL BROWSER OPENED]\033[0m Portal loaded diagnostic console: {self.path}")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_PAYLOAD.encode("utf-8"))

def signal_handler(sig, frame):
    log("\n[*] Interrupted. Cleaning up firewall and exiting...")
    cleanup_pf()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    with open(LOG_FILE, "w") as f:
        f.write("=== Captive Portal Server Log Started ===\n")

    log("=" * 70)
    log("       META PORTAL HARDWARE CAPTIVE ESCAPE SERVER")
    log("=" * 70)
    log(f"[*] 1. HTTP Interceptor on port {HTTP_PORT}")
    log(f"[*] 2. Diagnostics Console on port {WEB_PORT}")
    log(f"[*] 3. Kernel PF Redirection on bridge100")
    log("=" * 70)

    setup_pf()

    def run_web():
        with socketserver.ThreadingTCPServer(("", WEB_PORT), WebHandler) as httpd:
            httpd.serve_forever()
    t_web = threading.Thread(target=run_web, daemon=True)
    t_web.start()

    with socketserver.ThreadingTCPServer(("", HTTP_PORT), RedirectHandler) as httpd:
        try:
            log("[+] ALL SYSTEMS ARMED. Waiting for Portal connection...")
            httpd.serve_forever()
        except KeyboardInterrupt:
            log("[*] Stopping servers...")
            cleanup_pf()

if __name__ == "__main__":
    main()
