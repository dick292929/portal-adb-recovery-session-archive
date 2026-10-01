# Chrome 106 V8 candidates for the Portal

**Assessment date:** 2026-09-29  
**Target:** Portal 10-inch, 1st generation; captive-portal WebView  
**Status:** owner-reported CVE-2022-4262 renderer primitive candidate; no native execution or Android access

## Target evidence

The owner's compatibility-probe log now confirms the actual
`CaptivePortalLogin` WebView: `GET /generate_204`,
`Host: connectivitycheck.gstatic.com`,
`X-Requested-With: com.android.captiveportallogin`, Android 9 build
`PKQ1.191202.001`, and `Chrome/106.0.5249.126`. It received the benign
compatibility page once. The report showed WebAssembly, the small Wasm function
and memory-grow check all succeeded; WebGL 2 exposed Qualcomm Adreno 540.
`navigator.platform=Linux armv8l` is only a browser hint and does not establish
the WebView process ABI or the underlying kernel architecture.

PurrTol's own setup journal and request log report a more specific request:
`GET /mobile/status.php`, `Host: portal.fb.com`,
`X-Requested-With: com.android.captiveportallogin`, Chrome 86.0.4240.198, and
the same Android 9 build token. That capture is from a Portal+ 15.6-inch unit;
the owner has a Portal 10-inch Gen 1. It remains a useful same-build-family
comparison, while the direct 10-inch capture establishes Chrome 106 for this
unit's login WebView.

The prepared PurrTol helper is pinned to its `rce_chrome86.html` page and serves
it only for Chrome 86.0.4240.198. Its `getpid` and `env` profiles replace the
original race payload, but retain that page's CVE-2020-16040 renderer trigger.
The confirmed Chrome 106 WebView fails that exact gate, so the PurrTol Stage 1
page must not be run unchanged. The compatibility page was the only page
served in this capture; no exploit trigger or native payload was sent.
The local adapter includes ARM32 `getpid` and optional bounded environment
payloads in [`purrtol_stage1_getpid.S`](purrtol_stage1_getpid.S) and
[`purrtol_stage1_envprobe.S`](purrtol_stage1_envprobe.S). These form a native
renderer proof for the separate Chrome 86 path, not a tested Chrome 106 Portal
result. See the [code inventory](RENDERER_TO_DEVICE_ACCESS_HANDOFF.md).

## Candidate A: CVE-2022-3723

Project Zero lists CVE-2022-3723 as affecting Chrome 107.0.5304.62 and
previous, with the first patched version 107.0.5304.87. The captured Portal
Chrome 106 version is within that upstream version range. Project Zero's
root-cause analysis describes a TurboFan JIT type confusion caused by a stale
field-type assumption after garbage collection. Its published reproducer
requires V8-only intrinsics such as `%OptimizeFunctionOnNextCall`,
`%HeapObjectVerify`, and `gc()`; those are not available in a captive browser
page. Project Zero lists no exploit sample.

Google TAG documented CVE-2022-3723 in an Android chain alongside an Android
Chrome GPU sandbox bypass and an ARM Mali driver issue. TAG says that chain
targeted ARM-GPU phones running Chrome versions before 106. The Portal's
reported version is 106.0.5249.126, so it does not match that exact reported
campaign boundary. The observed Adreno 540 is a Qualcomm renderer, not the Mali
driver in that chain. The Android/Mali chain cannot be transferred to this
Portal by version similarity alone; its GPU and kernel conditions do not
match the evidence collected here.

## Candidate B: CVE-2022-4262

Project Zero lists CVE-2022-4262 as affecting Chrome through 108.0.5359.71,
with the first fixed version 108.0.5359.94. Google's release note identifies
the fix as a high-severity V8 type-confusion correction and says exploitation
was observed in the wild. Chrome for Android 108 was released with the same
security fixes as the corresponding desktop release. If the Portal's reported
106 engine version reflects its actual V8 build and did not receive an OEM
backport, it is in the affected upstream range. That is a strong candidate,
not proof that the Portal's WebView remains vulnerable.

The public root-cause analysis describes inconsistent bytecode after a
function is reparsed following bytecode aging. Its public test uses repeated
large allocations and millions of loop iterations to induce the aging/GC
conditions. Project Zero says the original exploit sample is unavailable; the
analysis describes a V8 memory-corruption primitive and a renderer-RCE chain,
not Android root by itself.

There is also a public exploit repository for CVE-2022-4262. Its README builds
an **x64 `d8`** engine at a specific V8 commit and runs with
`--allow-natives-syntax`. The actual `exploit.js` uses `%DebugPrint` and
`%GlobalPrint` for diagnostics; those calls could be removed for a browser
port. The repository's separate `test.js`, not `exploit.js`, uses
`Sandbox.MemoryView`/`Sandbox.getAddressOf` and the special
`v8_expose_memory_corruption_api` build flag. The exploit itself constructs
JavaScript heap read/write primitives, but relies on 64-bit BigInt pointer
arithmetic, compressed-pointer assumptions, and V8 object-layout details. Its
bytecode-aging routine makes repeated allocations approaching 2 GiB to induce
GC. The artifact contains no Android native-code stage or kernel stage. This
is a more concrete starting point than a root-cause-only reproducer, but it is
not a safe drop-in WebView test; process ABI, exact V8 build/layout, and a
bounded GC trigger must be resolved first.

## Porting constraints and decision

The owner's `CaptivePortalLogin` request confirms Chrome 106, so the Chrome 86
PurrTol page is ineligible. CVE-2022-3723 and CVE-2022-4262 remain upstream
version-family candidates, but neither available artifact is a ready WebView
exploit. CVE-2022-3723's public reproducer relies on V8 intrinsics. The
CVE-2022-4262 exploit is a more plausible porting base, but its pointer/layout
assumptions and expensive GC trigger need work before a bounded browser test;
its current endpoint is a JS heap read/write primitive, not native execution.
The next renderer step would need a WebView-compatible trigger and a bounded
native-execution success marker; the Portal's process ABI and actual V8 build
still need confirmation.

Do not send either Project Zero stress reproducer to the Portal as-is. They
depend on GC/heap conditions and may crash the captive login process; a trigger
alone would demonstrate neither native execution nor root.

The benign `CaptivePortalLogin` request has now been captured. The next work is
to establish whether this Chrome 106 WebView contains OEM backports of the
candidate fixes, and whether either published V8 path can be adapted to the
WebView runtime and its process ABI. A renderer-RCE result would still leave
Android sandbox escape and kernel privilege escalation to solve.

## Follow-up: Portal-side reports and bridge inventory (2026-09-29)

For the explicit boundary between the reported renderer result and device
access, see [`RENDERER_TO_DEVICE_ACCESS_HANDOFF.md`](RENDERER_TO_DEVICE_ACCESS_HANDOFF.md).

The owner supplied output from the bounded CVE-2022-4262 page. It reported the
`0x30` trigger marker, an object recovery/identity candidate, and a successful
round trip on the PoC's test object. The original-size allocation sequence
reported six failed requests and no successful allocation. A separate run
reported a 32-bit ArrayBuffer-layout hint and successful read/write/restore
markers within a self-created ArrayBuffer. Raw pointers and values were not
reported. This is evidence for a renderer-side memory primitive candidate on
the observed WebView; it is not evidence of native execution, sandbox escape,
Android access, or ADB. The terminal output was supplied by the owner and was
not independently reproduced in this review.

The updated benign compatibility page inspected descriptors across the
`window` prototype chain and on `document` and `navigator`, without invoking
getters or bridge methods. It reported an empty `nativeBridgeCandidateSurface`.
Its narrowed enumerable-global inventory returned 26 names, all ordinary
browser window functions. This did not reveal a host bridge, while leaving
non-enumerable or differently named interfaces untested.

The Chrome 106 version remains in the upstream pre-fix family for
CVE-2022-4262: Google's Chrome 108 release lists the V8 fix and says the issue
was exploited in the wild; Chrome for Android 108 shipped the corresponding
security fixes. This supports plausibility if the Portal's reported engine
version reflects the running V8 and no OEM backport was applied. The Portal's
installed WebView package and patch level remain unknown, so the target is not
confirmed vulnerable.

The existing PurrTol Stage 1 helper remains ineligible for this capture: it
uses a Chrome 86 / CVE-2020-16040 trigger and is gated to Chrome 86.0.4240.198.
No native stage, Wasm jump-table mutation, sandbox escape, Android setting
change, or ADB operation was performed in this follow-up. Device access was
not obtained.

## Sources

- [Project Zero CVE-2022-3723 root-cause analysis](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-3723.html)
- [Google TAG Android exploit-chain report](https://blog.google/threat-analysis-group/spyware-vendors-use-0-days-and-n-days-against-popular-platforms/)
- [Project Zero CVE-2022-4262 root-cause analysis](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-4262.html)
- [Google Chrome 108 security release](https://chromereleases.googleblog.com/2022/12/stable-channel-update-for-desktop.html)
- [Chrome 107 security release for CVE-2022-3723](https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_27.html)
- [Chrome for Android 106.0.5249.126 release](https://chromereleases.googleblog.com/2022/10/chrome-for-android-update_13.html)
- [V8 fix commit for Chromium issue 1394403](https://chromium.googlesource.com/v8/v8/+/27fa951ae4a3801126e84bc94d5c82dd2370d18b)
- [Public CVE-2022-4262 exploit repository](https://github.com/mistymntncop/CVE-2022-4262)
- [CVE-2022-4262 exploit source](https://github.com/mistymntncop/CVE-2022-4262/blob/main/exploit.js)
- [PurrTol captive-login setup journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/020_captive_portal_setup.md)
- [PurrTol captured captive-login requests](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/logs/requests_2026-03-03.jsonl)
- [PurrTol source page pinned by the current Portal helper](https://github.com/amemefarmer/the-purrtol/blob/9c9022dbf75f68311ac945bc9a0bd722d2536032/portal-freedom/captive-portal/www/exploit/rce_chrome86.html)
