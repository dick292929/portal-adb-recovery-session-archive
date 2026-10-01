#!/usr/bin/env python3
"""Serve a static page for a controlled captive-portal User-Agent check.

This helper does not configure DNS, routing, PF, or Wi-Fi. It does not fetch
remote resources, accept uploads, or write request data to disk. It prints only
the request path and User-Agent to stdout.
"""

import argparse
import http.server
import ipaddress
import socketserver


PAGE = b"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal browser check</title>
<style>
  body { font: 16px system-ui, sans-serif; margin: 2rem; max-width: 48rem; }
  code { overflow-wrap: anywhere; }
</style>
<h1>Portal browser check</h1>
<p>This static page only displays the browser version string.</p>
<p id="ua"><code>Reading User-Agent...</code></p>
<script>
  document.getElementById("ua").textContent = navigator.userAgent;
</script>
</html>
"""


class FingerprintHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PortalUAProbe/1.0"
    sys_version = ""

    def log_message(self, _format, *_args):
        # Avoid BaseHTTPRequestHandler's default client-address logging.
        return

    def _send_page(self, include_body):
        user_agent = self.headers.get("User-Agent", "<missing>")
        print(f"path={self.path!r} user_agent={user_agent!r}", flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
        )
        self.end_headers()
        if include_body:
            self.wfile.write(PAGE)

    def do_GET(self):
        self._send_page(include_body=True)

    def do_HEAD(self):
        self._send_page(include_body=False)

    def do_POST(self):
        self.send_error(405, "POST is not supported")

    def do_PUT(self):
        self.send_error(405, "PUT is not supported")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind",
        required=True,
        help="IP address of the controlled hotspot interface to bind to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=80,
        help="HTTP port (default: 80; use 8080 if the hotspot forwards to it)",
    )
    args = parser.parse_args()

    try:
        bind_ip = ipaddress.IPv4Address(args.bind)
    except ipaddress.AddressValueError:
        parser.error("--bind must be an IPv4 address assigned to the hotspot interface")
    if bind_ip.is_unspecified:
        parser.error("bind to the hotspot's specific IPv4 address, not all interfaces")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    class ReusableTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with ReusableTCPServer((args.bind, args.port), FingerprintHandler) as server:
        print(
            f"Static UA probe listening on http://{args.bind}:{args.port}/; "
            "Ctrl-C stops it. No DNS, firewall, or Wi-Fi settings changed.",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Stopped.", flush=True)


if __name__ == "__main__":
    main()
