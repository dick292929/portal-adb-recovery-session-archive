#!/usr/bin/env python3
"""Serve a one-tap Android Settings intent-routing check to the Portal login WebView.

The page is served once, only for the captured Portal build token and the
CaptivePortalLogin X-Requested-With header on /generate_204. One explicit user
tap asks Android to open the ordinary Settings screen. No setting is changed,
and no other app action, data read, or device command is attempted.

When run through sudo to bind port 80, the server drops to the invoking user
before accepting requests.
"""

import argparse
import http.server
import ipaddress
import socketserver
import threading
from urllib.parse import urlsplit

from portal_probe_runtime import drop_privileges_after_bind


ATTEMPT_BODY = b"settings"
CAPTIVE_HINT = (
    b"<!doctype html><html><meta charset=utf-8>"
    b"<title>Network sign-in required</title>"
    b"<p>Open the network sign-in notification to continue.</p></html>"
)
PAGE = b"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal intent-routing check</title>
<style>
  body { font: 17px system-ui, sans-serif; margin: 1rem; max-width: 38rem; }
  button { font: inherit; padding: 0.8rem 1rem; }
  #status { min-height: 3rem; white-space: pre-wrap; }
</style>
<h1>One-tap intent-routing check</h1>
<p>Tap once to request the normal Android Settings screen. This page does not
change settings. If Settings opens, return to this screen without changing
anything.</p>
<button id="open" type="button">Request Android Settings</button>
<p id="status" role="status">Waiting for your tap.</p>
<script>
(() => {
  const button = document.getElementById("open");
  const status = document.getElementById("status");
  let attempted = false;
  button.addEventListener("click", () => {
    if (attempted) return;
    attempted = true;
    button.disabled = true;
    status.textContent = "Recording the single tap, then requesting Settings...";
    try {
      navigator.sendBeacon(
        "/intent-attempt",
        new Blob(["settings"], { type: "text/plain" })
      );
    } catch (_error) {
      // The visible outcome is still the main test result if reporting fails.
    }
    status.textContent = "Request sent. Did Android Settings open?";
    location.href =
      "intent://settings/#Intent;scheme=android-app;" +
      "package=com.android.settings;" +
      "action=android.settings.SETTINGS;end";
  });
})();
</script>
</html>
"""


class IntentProbeHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PortalIntentProbe/1.0"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def _is_portal_build(self):
        return self.server.portal_ua_token in self.headers.get("User-Agent", "")

    def _is_login_webview(self):
        return (
            self.headers.get("X-Requested-With", "")
            == "com.android.captiveportallogin"
        )

    def _client_key(self):
        return (
            self.client_address[0],
            self.headers.get("User-Agent", ""),
        )

    def _log_request(self, event):
        print(
            f"{event} "
            f"path={self.path[:160]!r} "
            f"host={self.headers.get('Host', '<missing>')[:120]!r} "
            f"x_requested_with={self.headers.get('X-Requested-With', '<missing>')[:120]!r} "
            f"user_agent={self.headers.get('User-Agent', '<missing>')[:256]!r}",
            flush=True,
        )

    def _send(self, status, body=b"", content_type=None):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_captive_hint(self):
        self._send(200, CAPTIVE_HINT, "text/html; charset=utf-8")

    def _send_probe_page(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'",
        )
        self.end_headers()
        self.wfile.write(PAGE)

    def do_GET(self):
        path = urlsplit(self.path).path
        is_target = self._is_portal_build() and self._is_login_webview()

        if path == "/generate_204":
            self._log_request("connectivity_check")
            if not is_target:
                self._send_captive_hint()
                return
            with self.server.state_lock:
                if self.server.page_served:
                    self._send_captive_hint()
                    return
                self.server.page_served = True
                self.server.probe_client = self._client_key()
            print(
                "intent_probe_page=served_once to confirmed Portal login WebView",
                flush=True,
            )
            self._send_probe_page()
            return

        if is_target:
            self._log_request("portal_login_request")
        self._send(204)

    def do_POST(self):
        if urlsplit(self.path).path != "/intent-attempt":
            self._send(404)
            return

        client = self._client_key()
        with self.server.state_lock:
            authorized_client = client == self.server.probe_client
            already_reported = self.server.attempt_reported
        if not authorized_client or already_reported:
            self._send(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length != len(ATTEMPT_BODY):
            self._send(413)
            return
        if not self.headers.get("Content-Type", "").lower().startswith("text/plain"):
            self._send(415)
            return
        if self.rfile.read(length) != ATTEMPT_BODY:
            self._send(400)
            return

        with self.server.state_lock:
            if self.server.attempt_reported or client != self.server.probe_client:
                self._send(404)
                return
            self.server.attempt_reported = True

        print("settings_intent_attempted=true; no setting-change request sent", flush=True)
        self._send(204)

    def do_HEAD(self):
        if urlsplit(self.path).path == "/generate_204":
            self._send(200, content_type="text/html; charset=utf-8")
        else:
            self._send(204)

    def do_PUT(self):
        self._send(405)

    def do_DELETE(self):
        self._send(405)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind",
        required=True,
        help="IPv4 address of the controlled hotspot interface",
    )
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument(
        "--portal-ua-token",
        default="Build/PKQ1.191202.001",
        help="User-Agent substring required before serving the one-shot page",
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
    if not args.portal_ua_token:
        parser.error("--portal-ua-token cannot be empty")

    class ReusableTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with ReusableTCPServer((str(bind_ip), args.port), IntentProbeHandler) as server:
        drop_privileges_after_bind()
        server.portal_ua_token = args.portal_ua_token
        server.state_lock = threading.Lock()
        server.page_served = False
        server.probe_client = None
        server.attempt_reported = False
        print(
            f"One-shot Portal intent-routing probe listening on "
            f"http://{bind_ip}:{args.port}/; only a confirmed Portal "
            "CaptivePortalLogin request receives the page. One user tap can "
            "request the ordinary Android Settings screen; no setting is changed. "
            "Ctrl-C stops the helper.",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Stopped.", flush=True)


if __name__ == "__main__":
    main()
