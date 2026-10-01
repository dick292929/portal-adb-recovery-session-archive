# PurrTol renderer proof and environment report

The local helper [`../scripts/captive_portal_purrtol_stage1_getpid.py`](../scripts/captive_portal_purrtol_stage1_getpid.py)
fetches PurrTol's retained Chrome 86 page from one pinned commit, verifies its
Git blob hash, then replaces all 254 in-memory payload words with a selected
ARM32 payload and NOP fill. The default `getpid` profile calls only `getpid`
and returns its PID. An `env` profile is available only after the getpid result
has been observed; it calls `getuid32` and reads at most 255 bytes of
`/proc/version`. The helper serves the transformed page at most once, and only
when the request path is one of PurrTol's captive endpoints:
`/mobile/status.php`, `/generate_204`, or `/gen_204`. Its original server
routes on path; this adapter logs Host for comparison but does not gate on it.
It also requires `X-Requested-With: com.android.captiveportallogin`, Android 9,
Chrome 86.0.4240.198, the known Portal build token, and the Android WebView
marker. Other requests receive only a static captive-portal hint or a harmless
mismatch page.

When invoked with sudo to bind port 80, the helper drops to the invoking user
immediately after binding and before fetching the pinned page or serving HTTP.

The default payload is assembled from [`purrtol_stage1_getpid.S`](purrtol_stage1_getpid.S).
It calls Linux ARM EABI `getpid`, writes the PID into the retained page's
iterations result word, and returns a fixed completion marker. The optional
payload is assembled from [`purrtol_stage1_envprobe.S`](purrtol_stage1_envprobe.S).
It records PID and UID and reads only `/proc/version` into the WebAssembly
mapping. The server prints those bounded values without saving them. It does
not read process maps or device nodes. Both profiles use PurrTol's original V8
trigger and `mprotect` stager. Neither profile runs the kernel race, changes
device state, launches another process, or persists data.

The public repository does not retain a separate historical v11b page: its
visible refs expose one `main` branch, no tags or releases, and no separate
v11b artifact. The current page's V8 trigger and primitive code are retained,
while its embedded epoll-race shellcode is replaced before the page is served.
The helper's one-shot gate blocks the source page's built-in reload path after
its first delivery.

**Limit:** these profiles establish renderer execution and collect narrow
process/kernel identity only. They do not provide Android root, ADB, or
persistence. The owner's direct compatibility capture confirmed
`CaptivePortalLogin` on `/generate_204` with `X-Requested-With`, Android 9,
build `PKQ1.191202.001`, and Chrome 106.0.5249.126. This helper is gated to
Chrome 86.0.4240.198 and must not be run unchanged on the owner's unit.
PurrTol's own Chrome 86 request capture is from a Portal+ 15.6-inch unit with
the same build token; its renderer trigger is not established for this
10-inch unit. See
[`CHROME106_V8_CANDIDATES.md`](CHROME106_V8_CANDIDATES.md) for the
alternate Chrome 106 leads and their current limits.

## Current decision

The compatibility probe on the owner's Portal confirmed Chrome 106 in the
actual login WebView. Do not run this Chrome 86 helper on that device: it keeps
the CVE-2020-16040 trigger and requires Chrome 86.0.4240.198. PurrTol's Chrome
86 captures establish a route and build-family comparison, not that its
renderer trigger works on this Portal. Continue with the Chrome 106 candidate
assessment in [`CHROME106_V8_CANDIDATES.md`](CHROME106_V8_CANDIDATES.md).

The Stage 1 runner remains available as a source reference. A revised renderer
test needs a separate, WebView-compatible trigger and a bounded execution
marker before it is served to the device.

Only after the server reports `renderer_getpid=success`, the optional narrow
environment profile can be used in a second one-shot session:

```sh
sudo /bin/sh /Users/kahnmndez/Documents/Portal/scripts/run_portal_purrtol_stage1.sh env --confirm-prior-getpid
```

The profile still requires the exact Chrome 86 request gate. Its success report
includes PID, UID, the bounded kernel-version string, and `/proc/version` read
status; success now requires a nonempty read and zero syscall status. The report
endpoint accepts data only from the IP address and exact User-Agent that
received the one-shot page. A renderer result or environment report is not root
or device access; it supplies runtime facts needed to assess a target-matched
kernel stage.
