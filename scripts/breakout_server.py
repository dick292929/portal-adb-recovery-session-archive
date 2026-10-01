#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys

PORT = 8000
MAC_IP = "192.168.2.1"

HTML_CONTENT = """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>Explicit Package Intents</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, Roboto, sans-serif; background: #0f172a; color: #fff; padding: 16px; text-align: center; }
        h1 { font-size: 20px; color: #38bdf8; margin-bottom: 6px; }
        p { color: #94a3b8; font-size: 13px; margin-bottom: 16px; }
        .card { background: #1e293b; border-radius: 8px; padding: 12px; margin-bottom: 12px; border: 1px solid #334155; text-align: left; }
        .card h2 { font-size: 15px; margin-bottom: 6px; }
        a.btn { display: block; width: 100%; padding: 14px; border-radius: 6px; font-size: 16px; font-weight: bold; text-decoration: none; text-align: center; color: #fff; margin-top: 6px; }
        .b1 { background: #2563eb; }
        .b2 { background: #059669; }
        .b3 { background: #7c3aed; }
        .b4 { background: #d97706; }
        .b5 { background: #dc2626; }
        .b6 { background: #0891b2; }
    </style>
</head>
<body>
    <h1>EXPLICIT PACKAGE INTENT SUITE</h1>
    <p>Testing Chrome Intent URI variants with explicit target packages</p>

    <!-- Test 1: Full Chrome Intent to com.android.settings -->
    <div class="card">
        <h2>1. Standard Settings Intent</h2>
        <a class="btn b1" href="intent://#Intent;scheme=android-app;package=com.android.settings;action=android.settings.SETTINGS;end">intent:// scheme + package</a>
    </div>

    <!-- Test 2: Direct Component Intent -->
    <div class="card">
        <h2>2. Direct Component Launch</h2>
        <a class="btn b2" href="intent://#Intent;package=com.android.settings;component=com.android.settings/.Settings;end">intent:// component Settings</a>
    </div>

    <!-- Test 3: Android App Scheme -->
    <div class="card">
        <h2>3. android-app:// URI Scheme</h2>
        <a class="btn b3" href="android-app://com.android.settings">android-app://com.android.settings</a>
    </div>

    <!-- Test 4: Developer Options with Package -->
    <div class="card">
        <h2>4. Developer Options (ADB)</h2>
        <a class="btn b4" href="intent://#Intent;package=com.android.settings;action=android.settings.APPLICATION_DEVELOPMENT_SETTINGS;end">Developer Options Intent</a>
    </div>

    <!-- Test 5: Meta Aloha Settings Package -->
    <div class="card">
        <h2>5. Meta Settings App</h2>
        <a class="btn b5" href="intent://#Intent;package=com.facebook.aloha.system.settings;action=com.facebook.aloha.action.ACCOUNT_LOGIN;end">Meta Settings Login Intent</a>
    </div>

    <!-- Test 6: Passcode Enrollment in Aloha Users -->
    <div class="card">
        <h2>6. Passcode Enrollment (Lockscreen)</h2>
        <a class="btn b6" href="intent://#Intent;package=com.facebook.aloha.system.alohausers;action=com.facebook.aloha.action.PASSCODE_ENROLLMENT;end">Passcode Enrollment Intent</a>
    </div>
</body>
</html>
"""

class BreakoutHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        client_ip = self.client_address[0]
        print(f"[+] Request: {self.path} from {client_ip}", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(HTML_CONTENT.encode("utf-8"))

def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((MAC_IP, PORT), BreakoutHandler) as httpd:
        print(f"[*] EXPLICIT INTENT SERVER READY on http://{MAC_IP}:{PORT}/", flush=True)
        httpd.serve_forever()

if __name__ == "__main__":
    main()
