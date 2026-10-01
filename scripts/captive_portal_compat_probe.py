#!/usr/bin/env python3
"""Serve a benign, local-only browser capability check to the Portal WebView.

The page runs a tiny WebAssembly add function, checks a small WebAssembly
memory grow, reads WebGL renderer strings when available, and inspects global
property descriptors for possible host interfaces without invoking them.
It does not navigate, load remote resources, persist data, or change network
settings. Only a Portal-build request with the confirmed Android
CaptivePortalLogin header receives the page; the path is logged for comparison
with PurrTol. One small JSON feature report is printed to stdout and never
saved.
When started with sudo to bind port 80, it drops to the invoking user after
binding and before handling requests.
"""

import argparse
import http.server
import ipaddress
import json
import math
import socketserver
import threading
from urllib.parse import urlsplit

from portal_probe_runtime import drop_privileges_after_bind


MAX_REPORT_BYTES = 4096
REPORT_FIELDS = {
    "userAgent",
    "platform",
    "userAgentDataSupported",
    "uaArchitecture",
    "uaBitness",
    "uaModel",
    "uaPlatformVersion",
    "uaFullVersionList",
    "uaHintsError",
    "hardwareConcurrency",
    "deviceMemoryGB",
    "jsHeapSizeLimit",
    "jsHeapTotalSize",
    "jsHeapUsedSize",
    "bigInt",
    "bigInt64Array",
    "bigInt64RoundTrip",
    "littleEndian",
    "pageHost",
    "pagePath",
    "nativeBridgeCandidateSurface",
    "enumerableWindowObjectCandidateCount",
    "enumerableWindowObjectCandidateNames",
    "webAssembly",
    "wasmAdd42",
    "wasmMemoryGrow",
    "sharedArrayBuffer",
    "crossOriginIsolated",
    "webglVersion",
    "webglVendor",
    "webglRenderer",
    "webglUnmaskedVendor",
    "webglUnmaskedRenderer",
    "error",
}

PAGE = b"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal WebView compatibility check</title>
<style>
  body { font: 16px system-ui, sans-serif; margin: 1rem; max-width: 48rem; }
  pre { white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
<h1>Portal WebView compatibility check</h1>
<p>This local page checks browser features and reads global property descriptors. It does not invoke host interfaces or test an exploit.</p>
<pre id="result">Running small compatibility checks...</pre>
<script>
(async () => {
  const result = {
    userAgent: navigator.userAgent || null,
    platform: navigator.platform || null,
    userAgentDataSupported: Boolean(navigator.userAgentData),
    uaArchitecture: null,
    uaBitness: null,
    uaModel: null,
    uaPlatformVersion: null,
    uaFullVersionList: null,
    uaHintsError: null,
    hardwareConcurrency: Number.isFinite(navigator.hardwareConcurrency)
      ? navigator.hardwareConcurrency : null,
    deviceMemoryGB: Number.isFinite(navigator.deviceMemory)
      ? navigator.deviceMemory : null,
    jsHeapSizeLimit: null,
    jsHeapTotalSize: null,
    jsHeapUsedSize: null,
    bigInt: typeof BigInt === "function",
    bigInt64Array: typeof BigInt64Array === "function",
    bigInt64RoundTrip: false,
    littleEndian: null,
    pageHost: location.host || null,
    pagePath: location.pathname || null,
    nativeBridgeCandidateSurface: "",
    enumerableWindowObjectCandidateCount: 0,
    enumerableWindowObjectCandidateNames: "",
    webAssembly: typeof WebAssembly === "object",
    wasmAdd42: false,
    wasmMemoryGrow: false,
    sharedArrayBuffer: typeof SharedArrayBuffer === "function",
    crossOriginIsolated: Boolean(self.crossOriginIsolated),
    webglVersion: null,
    webglVendor: null,
    webglRenderer: null,
    webglUnmaskedVendor: null,
    webglUnmaskedRenderer: null,
    error: null
  };

  // Inspect property descriptors only. Do not invoke getters, enumerate methods
  // on bridge objects, call bridge functions, or read their return values.
  try {
    const candidates = [];
    const candidateName = /android|captive|portal|bridge|native|jsinterface/i;
    const inspectSurface = function(label, target, maxDepth) {
      let current = target;
      for (let depth = 0; current && depth <= maxDepth && candidates.length < 32; depth += 1) {
        let names;
        try {
          names = Object.getOwnPropertyNames(current);
        } catch (_error) {
          candidates.push(label + "[" + depth + "]:scan_unavailable");
          break;
        }
        for (const name of names) {
          if (!candidateName.test(name) || /^HTML/i.test(name)) continue;
          let kind = "descriptor_unavailable";
          try {
            const descriptor = Object.getOwnPropertyDescriptor(current, name);
            if (descriptor) {
              if (!Object.prototype.hasOwnProperty.call(descriptor, "value")) {
                kind = "accessor";
              } else {
                const value = descriptor.value;
                kind = value === null ? "null" : typeof value;
              }
            }
          } catch (_error) {
            kind = "descriptor_unavailable";
          }
          candidates.push(label + "[" + depth + "]." + name.slice(0, 64) + ":" + kind);
          if (candidates.length >= 32) break;
        }
        try {
          current = Object.getPrototypeOf(current);
        } catch (_error) {
          break;
        }
      }
    };
    inspectSurface("window", window, 4);
    inspectSurface("document", document, 2);
    inspectSurface("navigator", navigator, 2);
    result.nativeBridgeCandidateSurface = candidates.join(",").slice(0, 512);
  } catch (_error) {
    result.nativeBridgeCandidateSurface = "scan_unavailable";
  }

  // Look for enumerable object/function globals without inspecting their
  // members. A short allowlist removes common browser names, but ordinary
  // browser properties can remain. Non-enumerable or differently exposed
  // interfaces will not appear here.
  try {
    const standardGlobals = new Set((
      "window self frames top parent opener document location navigator screen history " +
      "performance console crypto localStorage sessionStorage indexedDB caches " +
      "customElements visualViewport CSS WebAssembly Intl Atomics Math JSON Reflect " +
      "Proxy Promise Map Set WeakMap WeakSet WeakRef FinalizationRegistry Array " +
      "ArrayBuffer SharedArrayBuffer DataView BigInt BigInt64Array BigUint64Array " +
      "Boolean Date Error EvalError Float32Array Float64Array Function Generator " +
      "Int8Array Int16Array Int32Array Number Object RangeError ReferenceError " +
      "RegExp String Symbol SyntaxError TypeError URIError Uint8Array Uint8ClampedArray " +
      "Uint16Array Uint32Array WebAssembly WebGLRenderingContext WebGL2RenderingContext " +
      "Node Element HTMLElement Document HTMLDocument Window Event EventTarget " +
      "MutationObserver IntersectionObserver ResizeObserver XMLHttpRequest " +
      "fetch Request Response Headers URL URLSearchParams Blob File FormData " +
      "Image ImageData Audio AudioContext MediaStream MediaRecorder " +
      "Worker SharedWorker MessageChannel MessagePort BroadcastChannel " +
      "Storage StorageManager Notification Permissions Geolocation " +
      "requestAnimationFrame cancelAnimationFrame setTimeout clearTimeout " +
      "setInterval clearInterval queueMicrotask postMessage addEventListener " +
      "removeEventListener dispatchEvent alert confirm prompt open close " +
      "encodeURI encodeURIComponent decodeURI decodeURIComponent isFinite isNaN " +
      "parseFloat parseInt eval undefined NaN Infinity globalThis chrome"
    ).split(/\\s+/));
    const names = [];
    let count = 0;
    for (const name of Object.getOwnPropertyNames(window)) {
      if (standardGlobals.has(name) || /^on[a-z]/i.test(name)) continue;
      let descriptor;
      try {
        descriptor = Object.getOwnPropertyDescriptor(window, name);
      } catch (_error) {
        continue;
      }
      if (!descriptor || !descriptor.enumerable ||
          !Object.prototype.hasOwnProperty.call(descriptor, "value")) continue;
      const kind = descriptor.value === null ? "null" : typeof descriptor.value;
      if (kind !== "object" && kind !== "function") continue;
      count += 1;
      if (names.length < 64) {
        const safeName = name.replace(/[^A-Za-z0-9_$.-]/g, "_").slice(0, 64);
        names.push(safeName + ":" + kind);
      }
    }
    result.enumerableWindowObjectCandidateCount = count;
    result.enumerableWindowObjectCandidateNames = names.join(",").slice(0, 1024);
  } catch (_error) {
    result.enumerableWindowObjectCandidateNames = "scan_unavailable";
  }

  // UA Client Hints may be unavailable in the captive portal's HTTP context.
  // When present, ask only for architecture/version hints and never persist them.
  try {
    const uaData = navigator.userAgentData;
    if (uaData && typeof uaData.getHighEntropyValues === "function") {
      const hints = await uaData.getHighEntropyValues([
        "architecture", "bitness", "model", "platformVersion", "fullVersionList"
      ]);
      result.uaArchitecture = typeof hints.architecture === "string"
        ? hints.architecture.slice(0, 80) : null;
      result.uaBitness = typeof hints.bitness === "string"
        ? hints.bitness.slice(0, 16) : null;
      result.uaModel = typeof hints.model === "string"
        ? hints.model.slice(0, 120) : null;
      result.uaPlatformVersion = typeof hints.platformVersion === "string"
        ? hints.platformVersion.slice(0, 40) : null;
      if (Array.isArray(hints.fullVersionList)) {
        result.uaFullVersionList = hints.fullVersionList
          .filter(item => item && typeof item.brand === "string" &&
            typeof item.version === "string")
          .map(item => item.brand.slice(0, 40) + "/" + item.version.slice(0, 40))
          .join(", ").slice(0, 512);
      }
    }
  } catch (error) {
    result.uaHintsError = String(error).slice(0, 160);
  }

  // These checks validate the exploit sample's BigInt typed-array assumptions
  // without allocating meaningful memory or touching engine internals.
  try {
    if (result.bigInt64Array) {
      const bytes = new ArrayBuffer(8);
      const word = 0x1122334455667788n;
      new BigInt64Array(bytes)[0] = word;
      result.bigInt64RoundTrip = new BigInt64Array(bytes)[0] === word;
      result.littleEndian = new Uint8Array(bytes)[0] === 0x88;
    }
  } catch (_error) {
    result.bigInt64RoundTrip = false;
  }

  // Chrome exposes this non-standard object on some builds. Its heap limit is
  // only a runtime hint; it does not establish process bitness or ABI.
  try {
    const memory = performance && performance.memory;
    if (memory) {
      for (const key of ["jsHeapSizeLimit", "totalJSHeapSize", "usedJSHeapSize"]) {
        const value = memory[key];
        if (Number.isFinite(value) && value >= 0) {
          const field = key === "totalJSHeapSize" ? "jsHeapTotalSize" :
            key === "usedJSHeapSize" ? "jsHeapUsedSize" : key;
          result[field] = Math.floor(value);
        }
      }
    }
  } catch (_error) {
    // These values are optional and are not needed for the compatibility page.
  }

  try {
    if (result.webAssembly) {
      const bytes = new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00,
        0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
        0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
      ]);
      const loaded = await WebAssembly.instantiate(bytes);
      result.wasmAdd42 = loaded.instance.exports.add(19, 23) === 42;

      const memory = new WebAssembly.Memory({ initial: 1, maximum: 2 });
      new Uint8Array(memory.buffer)[0] = 0x5a;
      const oldPages = memory.grow(1);
      result.wasmMemoryGrow = oldPages === 1 &&
        memory.buffer.byteLength === 131072 &&
        new Uint8Array(memory.buffer)[0] === 0x5a;
    }
  } catch (error) {
    result.error = "wasm: " + String(error).slice(0, 160);
  }

  try {
    const canvas = document.createElement("canvas");
    const gl2 = canvas.getContext("webgl2");
    const gl = gl2 || canvas.getContext("webgl") ||
      canvas.getContext("experimental-webgl");
    if (gl) {
      result.webglVersion = gl2 ? "WebGL 2" : "WebGL 1";
      result.webglVendor = gl.getParameter(gl.VENDOR);
      result.webglRenderer = gl.getParameter(gl.RENDERER);
      const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
      if (debugInfo) {
        result.webglUnmaskedVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
        result.webglUnmaskedRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
      }
    } else {
      result.webglVersion = "unavailable";
    }
  } catch (error) {
    result.webglVersion = "error";
    result.error = (result.error ? result.error + "; " : "") +
      "webgl: " + String(error).slice(0, 160);
  }

  document.getElementById("result").textContent = JSON.stringify(result, null, 2);
  try {
    await fetch("/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(result),
      cache: "no-store",
      credentials: "omit"
    });
  } catch (_error) {
    // The on-page result remains available if the local report cannot be sent.
  }
})();
</script>
</html>
"""

CAPTIVE_HINT = (
    b"<!doctype html><html><meta charset=utf-8>"
    b"<title>Network sign-in required</title>"
    b"<p>Open the network sign-in notification to continue.</p></html>"
)
PURRTOL_ROUTE_PATHS = {"/mobile/status.php", "/generate_204", "/gen_204"}


class CompatibilityHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PortalCompatProbe/1.0"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def _is_portal(self):
        return self.server.portal_ua_token in self.headers.get("User-Agent", "")

    def _is_login_webview(self):
        return (
            self.headers.get("X-Requested-With", "")
            == "com.android.captiveportallogin"
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

    def _send_empty(self, status):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_captive_hint(self, include_body=True):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(CAPTIVE_HINT)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if include_body:
            self.wfile.write(CAPTIVE_HINT)

    def _send_compatibility_page(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            # Chrome 86 uses unsafe-eval as the CSP opt-in for WebAssembly
            # compilation; this page contains no string-evaluated JS.
            "script-src 'unsafe-inline' 'unsafe-eval'; connect-src 'self'",
        )
        self.end_headers()
        self.wfile.write(PAGE)

    def do_GET(self):
        request_path = urlsplit(self.path).path

        is_portal_build = self._is_portal()
        is_login_webview = self._is_login_webview()

        # A successful connectivity check is normally HTTP 204. Return a tiny
        # static 200 page for the system probe, but allow the diagnostic page
        # below when the request is positively identified as the login WebView.
        if request_path == "/generate_204":
            self._log_request("connectivity_check")
            if not (is_portal_build and is_login_webview):
                self._send_captive_hint()
                return

        if is_portal_build and is_login_webview:
            self._log_request("portal_login_request")
            client = (self.client_address[0], self.headers.get("User-Agent", ""))
            with self.server.state_lock:
                if self.server.page_served:
                    self._send_captive_hint()
                    return
                self.server.page_served = True
                self.server.report_client = client

            route_match = request_path in PURRTOL_ROUTE_PATHS
            print(
                "portal_page_request "
                f"purrtol_route_match={str(route_match).lower()}; "
                "serving one compatibility page to confirmed login WebView",
                flush=True,
            )
            self._send_compatibility_page()
            return

        if is_portal_build:
            self._log_request("build_tag_request")

        self._send_empty(204)

    def do_POST(self):
        client = (self.client_address[0], self.headers.get("User-Agent", ""))
        with self.server.state_lock:
            authorized_client = self.server.report_client == client
            report_already_received = self.server.report_received
        if (
            self.path != "/report"
            or not authorized_client
            or report_already_received
        ):
            self._send_empty(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_REPORT_BYTES:
            self._send_empty(413)
            return
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            self._send_empty(415)
            return

        try:
            report = json.loads(self.rfile.read(length))
            if not isinstance(report, dict) or not set(report).issubset(REPORT_FIELDS):
                raise ValueError("unexpected report shape")
            if any(
                not isinstance(value, (str, bool, int, float, type(None)))
                or (isinstance(value, float) and not math.isfinite(value))
                for value in report.values()
            ):
                raise ValueError("unexpected report value")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._send_empty(400)
            return

        with self.server.state_lock:
            if self.server.report_received or self.server.report_client != client:
                self._send_empty(404)
                return
            self.server.report_received = True

        print("compatibility_report=" + json.dumps(report, ensure_ascii=True, sort_keys=True), flush=True)
        self._send_empty(204)

    def do_HEAD(self):
        if urlsplit(self.path).path == "/generate_204":
            self._log_request("connectivity_check_head")
            self._send_captive_hint(include_body=False)
        else:
            self._send_empty(204)

    def do_PUT(self):
        self._send_empty(405)

    def do_DELETE(self):
        self._send_empty(405)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind",
        required=True,
        help="IP address of the controlled hotspot interface to bind to",
    )
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument(
        "--portal-ua-token",
        default="Build/PKQ1.191202.001",
        help="User-Agent substring required before the diagnostic page is served; "
        "the CaptivePortalLogin X-Requested-With header is also required",
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

    with ReusableTCPServer((args.bind, args.port), CompatibilityHandler) as server:
        drop_privileges_after_bind()
        server.portal_ua_token = args.portal_ua_token
        server.state_lock = threading.Lock()
        server.page_served = False
        server.report_client = None
        server.report_received = False
        print(
            f"Local Portal compatibility probe listening on http://{args.bind}:{args.port}/; "
            "connectivity checks receive a static captive hint; the compatibility "
            "page is sent once only to the confirmed CaptivePortalLogin WebView. "
            "Ctrl-C stops it; reports are printed to stdout and not saved.",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Stopped.", flush=True)


if __name__ == "__main__":
    main()
