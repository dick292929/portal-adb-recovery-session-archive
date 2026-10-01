# Portal captive-portal User-Agent check

This bounded check captures the browser build used by the Portal's
captive-login WebView. It does not test a vulnerability or try to escape the
browser sandbox.

The owner has already demonstrated that captive-portal interception can open
`CaptivePortalLoginActivity`; this probe does not repeat the old intent,
toolbar, fullscreen, or settings escape attempts. The prior Chrome 106 result
belongs to the separate Terms-of-Service browser and does not identify the
captive-login WebView's version.

## Helper

[`scripts/captive_portal_ua_probe.py`](../scripts/captive_portal_ua_probe.py)
serves one static page, displays `navigator.userAgent`, and prints each request
path and HTTP `User-Agent` to the terminal. It does not configure Wi-Fi, DNS,
routing, PF, or other firewall rules. It does not save logs, load remote
content, or accept POST/PUT requests.

The repository already has other captive-portal scripts, but they are not used
for this check: `scripts/captive_portal_server.py` changes PF rules and blocks
DNS-over-TLS, while `scripts/test_browser_server.py` offers native-app actions
and a dummy APK endpoint. This helper avoids those behaviors.

## Procedure

1. Use the controlled Internet Sharing hotspot and stop any prior captive
   portal server. With the hotspot at `192.168.2.1` on `bridge100`, load this
   temporary rule from a separate Terminal. It redirects plaintext HTTP only
   from the hotspot subnet; it does not block DNS-over-TLS or touch other
   interfaces:

   ```sh
   sudo /sbin/pfctl -a com.apple/portal_ua_probe -f - <<'PF'
   rdr pass on bridge100 inet proto tcp from 192.168.2.0/24 to any port 80 -> 192.168.2.1 port 80
   PF
   ```

   This uses the PF redirect anchor in `/etc/pf.conf`; Internet Sharing must
   have PF enabled. The helper itself does not configure PF.
2. Find the active hotspot interface address and start the helper bound only to
   that address. Port 80 is the default and requires `sudo`:

   ```sh
   HOTSPOT_IP=192.168.2.1  # replace if the active hotspot address differs
   sudo /opt/homebrew/bin/python3 /Users/kahnmndez/Documents/Portal/scripts/captive_portal_ua_probe.py --bind "$HOTSPOT_IP"
   ```

3. Reconnect the Portal to the controlled hotspot to trigger a fresh captive
   check. Use the OOBE/Wi-Fi path that previously opened the captive-login view. Read
   the visible User-Agent from the page and match it to the request line in the
   terminal. Do not use the separate Terms-of-Service browser for this check.
4. Stop the helper with Ctrl-C, then remove only this PF anchor:

   ```sh
   sudo /sbin/pfctl -a com.apple/portal_ua_probe -F all
   ```

   Record only whether the WebView opened and the browser/version string. Do
   not proceed to exploit content from this check.

If the view does not open, record that result and stop; it means this public
route has not yet been shown reachable from the current onboarding flow.
