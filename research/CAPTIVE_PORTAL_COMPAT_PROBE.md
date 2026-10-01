# Captive WebView compatibility probe

This probe records a small set of browser capabilities from the Portal's
captive-login WebView. It is a compatibility check for the PurrTol lead, not
an exploit test. The page runs a tiny WebAssembly `add(19, 23)` function,
checks a one-page WebAssembly memory grow, reads WebGL vendor/renderer strings
when available, and inspects selected global property descriptors without
invoking them. It performs no navigation, remote requests, file writes, exploit
trigger, or network configuration changes.
Its local CSP permits inline script and `'unsafe-eval'` so the older Chrome 86
WebView can compile the tiny Wasm module; the page has no remote script source.

Android 9's `CaptivePortalLogin` WebView initially loads `/generate_204`, and
the system treats HTTP 204 as success. The helper returns a tiny static HTTP
200 hint to connectivity-check requests that do not identify the login
WebView, keeping the network in captive state. If the request also carries the
Portal build token and
`X-Requested-With: com.android.captiveportallogin`, it instead serves the
benign compatibility page once. This distinguishes a WebView request from a
system connectivity check even when both use `/generate_204`.

## Owner-device capture (2026-09-29)

The owner ran this probe and confirmed the login WebView request by its
`X-Requested-With` header. It used `/generate_204` at
`connectivitycheck.gstatic.com` with Android 9, build `PKQ1.191202.001`, and
Chrome 106.0.5249.126. The one-shot benign page returned a report with
WebAssembly enabled, `wasmAdd42=true`, `wasmMemoryGrow=true`, WebGL 2, and an
unmasked Qualcomm Adreno 540 renderer. The browser reported
`navigator.platform=Linux armv8l`; that value does not establish the WebView
process ABI. This identifies the WebView build but does not demonstrate a V8
vulnerability or native execution. The prepared PurrTol Stage 1 requires
Chrome 86.0.4240.198 and does not match this capture.
`SharedArrayBuffer=false` and `crossOriginIsolated=false` do not explain that
mismatch: the pinned PurrTol page uses ordinary WebAssembly memory and does not
reference SharedArrayBuffer.

A later run used descriptor-only inspection on `window` and a short prototype
chain, plus `document` and `navigator`. It reported
`nativeBridgeCandidateSurface=""`. The enumerable-global inventory reported
26 properties: `atob`, `blur`, `btoa`, `cancelIdleCallback`, `captureEvents`,
`createImageBitmap`, `find`, `focus`, `getComputedStyle`, `getSelection`,
`matchMedia`, `moveBy`, `moveTo`, `print`, `releaseEvents`, `reportError`,
`requestIdleCallback`, `resizeBy`, `resizeTo`, `scroll`, `scrollBy`,
`scrollTo`, `stop`, `structuredClone`, `webkitCancelAnimationFrame`, and
`webkitRequestAnimationFrame`. These are ordinary browser window functions;
the partial standard-name filter did not exclude all of them. The inventory
does not inspect members or invoke bridge methods, and cannot rule out a
non-enumerable or differently exposed host interface. The embedded JavaScript
regex escape warning was fixed before this run; the output contained no
Python `SyntaxWarning`.

PurrTol's server routes by path and accepts `/mobile/status.php`,
`/generate_204`, and `/gen_204`; it does not require a particular Host. Its
request logs show the confirmed WebView on `/mobile/status.php` at
`portal.fb.com` and on `/generate_204` at `connectivitycheck.gstatic.com`.
The helper marks `purrtol_route_match=true` for any of those three paths,
including Android 9's `connectivitycheck.android.com/generate_204`, regardless
of Host. It logs path, Host, `X-Requested-With`, and User-Agent so the observed
request can still be compared with PurrTol's captures. A single bounded JSON
report is accepted only from the same
source IP and exact User-Agent that received the page; it is printed to the
terminal and is not saved. The report includes the User-Agent, platform string,
WebAssembly test
results, SharedArrayBuffer/cross-origin-isolation availability, and WebGL
renderer strings when exposed, plus the page host and path. These values
describe browser capabilities; they do not establish a vulnerable or patched
kernel driver. Android 9 behavior is visible in the [AOSP
CaptivePortalLogin source](https://android.googlesource.com/platform/frameworks/base/%2B/5344a4a/packages/CaptivePortalLogin/src/com/android/captiveportallogin/CaptivePortalLoginActivity.java)
and [probe result definition](https://android.googlesource.com/platform/frameworks/base/%2B/android-9.0.0_r8/core/java/android/net/captiveportal/CaptivePortalProbeResult.java).

## Run

Stop any previous helper with Ctrl-C first. The runner checks that
`bridge100` still owns `192.168.2.1`, that port 80 is free, and PF is already
enabled. If the dedicated `com.apple/portal_ua_probe` anchor is empty, it loads
only the local HTTP redirect there and clears that rule on exit. If the anchor
already contains exactly the same single redirect, it reuses it and leaves it
in place on exit. It refuses filter rules or any different/additional NAT rule.
The Python server drops to the invoking macOS user after binding port 80, so it
handles requests without root privileges. The runner never alters PF's global
ruleset.

```sh
sudo /bin/sh /Users/kahnmndez/Documents/Portal/scripts/run_portal_compat_probe.sh
```

Reconnect the Portal to the controlled hotspot and repeat the onboarding path
that caused the captive-login check. If Android shows a "Sign in to network"
notification or prompt, open it to load `CaptivePortalLogin`. A `/generate_204`
request without the `X-Requested-With` login-app marker is only the
connectivity check. Look for `portal_login_request` to identify the actual
login WebView and compare its path and User-Agent with PurrTol's captured
requests; Host is useful context but is not a route gate. PurrTol reports
Chrome 86 on both `/mobile/status.php` and `/generate_204` requests for the
same build tag. The confirmed login-WebView capture on this Portal reports
Chrome 106, so it does not match the PurrTol Stage 1 browser gate. Look for
`connectivity_check`, `portal_login_request`, `portal_page_request`, and
`compatibility_report=` lines. The `purrtol_route_match` flag describes whether
the page was served on the same recorded route. If the page request appears
without a report, the WebView may not have executed the script or the POST may
not have returned; do not infer JavaScript or WebAssembly failure from that
alone. The on-page output remains visible if the POST fails.

Stop the runner with Ctrl-C after the captive check; its cleanup trap removes
the temporary redirect. If the shell is forcibly terminated before cleanup,
remove only the dedicated anchor manually:

```sh
sudo /sbin/pfctl -a com.apple/portal_ua_probe -F all
```

## Interpretation

- A successful Wasm add and memory grow establish ordinary WebAssembly support
  and basic behavior only. They do not validate PurrTol's V8 exploit.
- An empty bridge-name report means this bounded descriptor scan found no
  matching visible names. The enumerable-global inventory is heuristic and may
  include ordinary browser APIs; neither result proves that no native
  interface exists.
- A WebGL renderer can identify the exposed graphics stack, but the value may
  be masked or unavailable. It does not show which KGSL/Adreno fixes are
  installed.
- The page's `navigator.platform` is only a browser-reported hint. It does not
  prove whether CaptivePortalLogin runs as a 32-bit or 64-bit process. PurrTol's
  journal says its tested Chrome 86 WebView was 32-bit ARM, so that ABI remains
  a separate transfer question.
- A Chrome UA on `/generate_204` without the login-app header does not establish
  the version of the `CaptivePortalLogin` WebView. If that WebView reports
  Chrome 86 and the request uses one of PurrTol's accepted paths, the renderer
  lead becomes a close build and route match. Host is not part of PurrTol's
  routing condition. Its reported exploit and later kernel stage still require
  independent validation.
- A successful Wasm or WebGL report does not demonstrate renderer compromise,
  sandbox escape, kernel access, or root.
