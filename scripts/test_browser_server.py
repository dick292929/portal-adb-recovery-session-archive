#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys

PORT = 8080
MAC_IP = "192.168.2.1"

HTML_CONTENT = """<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portal Diagnostic Console</title>
    <style>
        body { font-family: -apple-system, Roboto, sans-serif; background: #1a1a2e; color: #fff; padding: 20px; text-align: center; }
        h1 { color: #4ecca3; font-size: 28px; }
        .card { background: #162447; border-radius: 12px; padding: 20px; margin: 20px auto; max-width: 500px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        button, a.btn, label.btn { display: block; width: 100%; background: #e94560; color: white; border: none; padding: 16px; border-radius: 8px; font-size: 18px; font-weight: bold; margin: 12px 0; cursor: pointer; text-decoration: none; box-sizing: border-box; }
        label.btn { background: #0f3460; border: 2px solid #4ecca3; }
        input[type="file"] { display: none; }
    </style>
</head>
<body>
    <h1>Portal Diagnostic Console</h1>
    <p>Connected to Mac at 192.168.2.1</p>

    <div class="card">
        <h3>Option 1: System Print Spooler</h3>
        <p>Invokes Android Print Spooler & PDF Storage Manager</p>
        <button onclick="window.print()">Trigger window.print()</button>
    </div>

    <div class="card">
        <h3>Option 2: System File Picker</h3>
        <p>Launches native DocumentsUI document picker</p>
        <label class="btn">
            Tap to Open System Files
            <input type="file" id="fileInput" onchange="alert('Selected: ' + this.files[0].name)">
        </label>
    </div>

    <div class="card">
        <h3>Option 3: Camera / Media Capture</h3>
        <label class="btn" style="background: #53354a;">
            Tap to Open Camera / Image Picker
            <input type="file" accept="image/*" capture="camera">
        </label>
    </div>

    <div class="card">
        <h3>Option 4: Package Download</h3>
        <p>Triggers package download and installation prompt</p>
        <a href="/test.apk" download class="btn" style="background: #23374d;">Download Test Package</a>
    </div>
</body>
</html>
"""

class DiagnosticHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "Unknown")
        print(f"\n[+] HTTP GET: {self.path} from {client_ip}")
        print(f"    User-Agent: {user_agent}")
        sys.stdout.flush()

        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_CONTENT.encode("utf-8"))
        elif self.path == "/test.apk":
            apk_bytes = b"PK\x03\x04" + b"\x00" * 100
            self.send_response(200)
            self.send_header("Content-type", "application/vnd.android.package-archive")
            self.send_header("Content-Disposition", 'attachment; filename="setup_helper.apk"')
            self.end_headers()
            self.wfile.write(apk_bytes)
        else:
            self.send_response(404)
            self.end_headers()

def main():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((MAC_IP, PORT), DiagnosticHandler) as httpd:
        print(f"======================================================================")
        print(f"[*] DIAGNOSTIC TEST SERVER ACTIVE on http://{MAC_IP}:{PORT}")
        print(f"======================================================================")
        print(f"Ready for incoming browser requests...")
        sys.stdout.flush()
        httpd.serve_forever()

if __name__ == "__main__":
    main()
