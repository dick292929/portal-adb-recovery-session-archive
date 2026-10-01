# Renderer-to-device access handoff

**Target:** Meta Portal 10-inch, 1st generation (owner-reported)  
**Last updated:** 2026-09-29

## What was actually reached

The Portal's captive-login WebView was identified from its request headers as
Android 9, build `PKQ1.191202.001`, Chrome `106.0.5249.126`. A controlled,
local captive page was used for compatibility checks and a bounded
CVE-2022-4262 stage-one experiment. The owner supplied output reporting the
trigger marker, a JavaScript object recovery/identity candidate, a successful
read/write check on the PoC test object, and a reversible marker check inside
a self-created 8 KiB `ArrayBuffer`. Another output reported a 32-bit layout
hint. Six original-size allocation requests failed. Raw pointers and values
were not recorded here.

These are owner-supplied renderer results and were not independently
reproduced. They support a **JavaScript renderer primitive candidate only**.
They do not show native code execution on this Portal.

## Milestone map

| Stage | Evidence/status |
| --- | --- |
| Deliver a controlled page to the confirmed captive-login WebView | Done; request route and Chrome 106 user agent were observed. |
| Trigger the reported V8 issue and observe a JavaScript primitive candidate | Owner-reported; bounded stage-one output recorded in the session record. |
| Execute native code in this Portal's renderer | **Not reached.** No Chrome 106-matched native stage or native success marker was tested on this Portal. |
| Prepare a native-execution proof for a separate Chrome 86 target | A bounded PurrTol-derived `getpid` proof and optional environment probe were written. They retain the CVE-2020-16040 trigger, require Chrome 86.0.4240.198, and were not served to this Portal. |
| Escape the renderer/WebView sandbox | **Not reached.** No sandbox escape was implemented or observed. |
| Obtain Android shell/system privileges or change ADB state | **Not reached.** No Android command channel or ADB change was obtained. |

The earlier compatibility scan reported no matching bridge-like surface in
the inspected descriptors. It was a limited scan and does not establish that
all interfaces are absent. The separate EDL/Sahara work did not bridge this
WebView result to Android access; its history and outcomes are in
[`SESSION_RECORD_2026-09-29.md`](SESSION_RECORD_2026-09-29.md).

## What the missing transition means

There is no completed code-execution path for the observed Chrome 106 Portal
to reproduce: its CVE-2022-4262 work stopped at the JavaScript-level
candidate. We did write a separate PurrTol-derived Chrome 86 adapter that
contains a bounded native `getpid` proof payload and an optional environment
probe. That adapter keeps PurrTol's CVE-2020-16040 trigger, is gated to Chrome
86.0.4240.198, and was not served to the Portal after its login WebView was
confirmed as Chrome 106. It is not evidence of execution on this device.

Even native execution in the renderer would still be separate from escaping
Android's process sandbox; sandbox escape would still be separate from gaining
the privileges needed to enable ADB. None of those later transitions has
evidence in this record.

## Code written for this work

| File | What it does | Result/status |
| --- | --- | --- |
| [`scripts/captive_portal_compat_probe.py`](../scripts/captive_portal_compat_probe.py) | Serves the benign compatibility page to the confirmed login WebView, records browser/Wasm/WebGL properties, and inspects selected descriptors without invoking bridge methods. | Used to identify the Portal's Chrome 106 login WebView and collect compatibility output. |
| [`scripts/run_portal_compat_probe.sh`](../scripts/run_portal_compat_probe.sh) | Checks the local bridge/PF state, installs or reuses the dedicated HTTP redirect, and launches the benign probe. | Used during the captive-WebView checks. |
| [`scripts/captive_portal_cve2022_4262_stage1.py`](../scripts/captive_portal_cve2022_4262_stage1.py) | Adapts a pinned public CVE-2022-4262 JavaScript PoC for a bounded, one-shot renderer-side primitive candidate report and optional self-created-buffer diagnostics. | Owner supplied a positive primitive-candidate report; this helper has no native-code stage. |
| [`scripts/run_portal_cve2022_4262_stage1.sh`](../scripts/run_portal_cve2022_4262_stage1.sh) | Applies the same local HTTP redirect checks and launches the bounded CVE-2022-4262 page. | Used to serve the reported stage-one page. |
| [`scripts/captive_portal_purrtol_stage1_getpid.py`](../scripts/captive_portal_purrtol_stage1_getpid.py) | Pins and verifies PurrTol's Chrome 86 page, replaces its embedded payload with a selected bounded ARM32 proof profile, and enforces a one-shot Chrome 86 request gate. The page's existing Wasm `mprotect` stager is retained. | Contains a native `getpid` proof profile, but its Chrome 86/CVE-2020-16040 gate does not match this Portal's observed Chrome 106; the helper was not served to this Portal. |
| [`research/purrtol_stage1_getpid.S`](purrtol_stage1_getpid.S) and [`research/purrtol_stage1_envprobe.S`](purrtol_stage1_envprobe.S) | ARM32 payload sources for the bounded `getpid` proof and optional PID/UID plus limited `/proc/version` environment report. | Assembled into the PurrTol adapter; no successful execution on this Portal was observed. |
| [`scripts/run_portal_purrtol_stage1.sh`](../scripts/run_portal_purrtol_stage1.sh) | Launches the PurrTol adapter through the local redirect runner. | Not used on the Portal after the Chrome 106 mismatch was confirmed. |
| [`scripts/portal_probe_runtime.py`](../scripts/portal_probe_runtime.py) | Shared host-side helper for dropping privileges after binding the local HTTP port. | Server hardening utility; not part of a device exploit. |

The `research/sahara_*_probe.py` files are separate bounded Sahara/EDL
protocol probes. They tested identification, read-only queries, reset
behavior, and metadata rejection paths; none achieved loaderless native code
execution or Android access. Their individual results are in the session
record.

The installed WebView package and its OEM patch state were not identified, so
the observed Chrome 106 version does not by itself prove that the relevant
V8 issue is unpatched. The captured browser platform string is not proof of
the process ABI. The bridge scan is not exhaustive. These unresolved points
must not be presented as successful exploit steps.

## Source records

- [`SESSION_RECORD_2026-09-29.md`](SESSION_RECORD_2026-09-29.md): chronological
  research and owner-supplied outputs, including prior EDL/Sahara work.
- [`CHROME106_V8_CANDIDATES.md`](CHROME106_V8_CANDIDATES.md): version,
  candidate, and patch-status assessment.
- [`CAPTIVE_PORTAL_COMPAT_PROBE.md`](CAPTIVE_PORTAL_COMPAT_PROBE.md): captive
  WebView identification, compatibility checks, and limits of the bridge scan.
- [`captive_portal_cve2022_4262_stage1.py`](../scripts/captive_portal_cve2022_4262_stage1.py):
  bounded renderer-stage diagnostic used in the reported test; it contains no
  native stage.
