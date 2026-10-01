# Research files and tools

This repository preserves the tools and notes used in the first generation Portal 10-inch unlock investigation. The 161 files listed in [RESEARCH_FILES_MANIFEST.json](RESEARCH_FILES_MANIFEST.json) are byte-for-byte copies from the research workspace. The manifest records original relative paths, sizes, and SHA-256 hashes. Documentation and license notices added for this upload are separate from those original files.

Start with the [session record](README.md), then follow the artifacts below. Earlier plans and handoffs reflect what was known at their recorded dates; they can contain hypotheses superseded by later observations.

## Renderer and captive portal

| File | Role in the investigation |
|---|---|
| [captive_portal_cve2022_4262_stage1.py](scripts/captive_portal_cve2022_4262_stage1.py) | Main Chrome 106/V8 renderer investigation: primitive, layout, read/write, indirect-call, ABI, and native-execution experiments. |
| [run_portal_cve2022_4262_stage1.sh](scripts/run_portal_cve2022_4262_stage1.sh) | Original macOS launcher, network checks, and PF anchor handling. |
| [captive_portal_purrtol_stage1_getpid.py](scripts/captive_portal_purrtol_stage1_getpid.py) | Earlier PurrTol-derived Chrome 86 profile assessment; a different renderer version from the target's Chrome 106. |
| [run_portal_purrtol_stage1.sh](scripts/run_portal_purrtol_stage1.sh) | Launcher for that earlier profile. |
| [purrtol_stage1_getpid.S](research/purrtol_stage1_getpid.S), [purrtol_stage1_envprobe.S](research/purrtol_stage1_envprobe.S) | ARM32 assembly for bounded PID/environment probes. |
| [captive_portal_compat_probe.py](scripts/captive_portal_compat_probe.py), [run_portal_compat_probe.sh](scripts/run_portal_compat_probe.sh) | Browser compatibility and feature reconnaissance. |
| [captive_portal_ua_probe.py](scripts/captive_portal_ua_probe.py), [captive_portal_intent_probe.py](scripts/captive_portal_intent_probe.py) | User-agent capture and intent/navigation experiments. |
| [portal_probe_runtime.py](scripts/portal_probe_runtime.py) | Shared privilege-drop support imported by the probe servers. |
| [captive_portal_server.py](scripts/captive_portal_server.py), [breakout_server.py](scripts/breakout_server.py), [test_browser_server.py](scripts/test_browser_server.py) | Earlier captive-portal and browser entry experiments. |
| [portal_proxy.py](scripts/portal_proxy.py), [portal_traffic_sniffer.py](scripts/portal_traffic_sniffer.py), [live_traffic_monitor.py](scripts/live_traffic_monitor.py) | HTTP/CONNECT logging and traffic observation tools. |

The launchers retain the original workstation paths, `/opt/homebrew/bin/python3`, `bridge100`, and `192.168.2.1`. Review and adapt those values for another machine. Python servers mostly use the standard library; traffic tools may rely on local command-line utilities. These are archived experiments, not an automatic unlock installer. Some modes intentionally exercise memory-corruption behavior and can crash the WebView or device. No device probes were run while preparing this upload.

The renderer servers fetch pinned upstream sources and verify Git blob hashes:

- CVE-2022-4262: [mistymntncop's exploit.js](https://github.com/mistymntncop/CVE-2022-4262/blob/f35992269257ef5302d314739608e5cf900b2a19/exploit.js), blob `1f449ccb6be5b8f69b0c26a051b5ce80bde278a6`.
- PurrTol: [amemefarmer's Chrome 86 page](https://github.com/amemefarmer/the-purrtol/blob/9c9022dbf75f68311ac945bc9a0bd722d2536032/portal-freedom/captive-portal/www/exploit/rce_chrome86.html), blob `9dd1150f69bfdd23640b11d22601484a0aee1afc`.

Those pages are upstream dependencies, rather than additional local files used in this snapshot. The preserved servers still fetch them from their original URLs.

## Sahara / EDL and USB

The [research directory](research/) contains all **24 `sahara_*.py` probes** and **six `usb_ep0_*.py` probes**. It includes command/identity queries, memory-debug checks, reset framing/boundary experiments, ELF metadata/layout probes, and USB descriptor/control-request probes. Related variants import neighboring modules, so retain the directory layout.

These probes require Python 3, **PyUSB**, and a usable **libusb** backend. Their recorded outcomes and reasons for stopping each branch are in [APQ8098_SAHARA_RECOVERY_PLAN.md](research/APQ8098_SAHARA_RECOVERY_PLAN.md) and the [handoff](PORTAL_CVE-2021-30327_HANDOFF.md). Some helpers are intentionally disabled guards; their original state is preserved.

[research/katana_src](research/katana_src/) contains the five upstream Katana files downloaded during the investigation. They retain Daniel Grobert's copyright and AGPL-3.0-or-later notices; the [license](research/katana_src/LICENSE) is included. This is a partial, flattened research snapshot: the original runner imports `modules.sahara` and `modules.upload`, whereas those two files were saved directly in this folder. It is not a complete installed Katana checkout. Consult [Daniel224455/katana](https://github.com/Daniel224455/katana) for the original layout and dependencies. Its saved profile table supplies SDM845 data, not a working APQ8098 payload.

## Firmware and certificate analysis

[firmware/extract_ota.py](firmware/extract_ota.py) is the original full A/B payload extractor. It uses Python's standard library and expects `aloha_ota_1041515800015050.zip` in the working directory. It requires explicit partition names. For example, with a matching local OTA:

```sh
cd firmware
python3 extract_ota.py boot abl
```

For all partitions analyzed in the session:

```sh
python3 extract_ota.py system vendor boot modem dsp abl xbl tz keymaster cmnlib cmnlib64 devcfg hyp pmic rpm bluetooth
```

Output is written to `ota_extracted/`. The extractor allocates each partition in memory and is tailored to the observed full payload and operation types; it is not a general delta-OTA implementation or a signature verifier. The two 3 GiB partitions require substantial memory and disk space.

[FIRMWARE_INVENTORY.json](firmware/FIRMWARE_INVENTORY.json) identifies the original 1.28 GB OTA and all 16 extracted partition images by size and SHA-256. Bulk firmware images, APKs, and complete decompiled vendor trees are not included in this Git snapshot. The inventory enables matching a separately obtained OTA and identifying the extraction results.

Small original evidence is included in [evidence/](evidence/): OTA metadata, the vendor USB init rules, board information, and available certificate-pin XML from the device-build setup app and Settings app. The Settings XML is labeled separately; it is not presented as the missing temporary OTA-build setup-app XML. Temporary `/tmp/aloha_setup/` and `/tmp/ota_setup_decoded/` directories mentioned in the record were no longer present during packaging.

## Source snapshots and records

- [v8src/](v8src/): local V8 ARM/Liftoff/Wasm source snapshots and the downloaded tree index used for ABI and JIT analysis; [V8 license](v8src/LICENSE) included.
- [research/src/](research/src/): downloaded Chromium/Blink/GPU headers and source plus reference material used for object-layout analysis; [Chromium license](research/src/LICENSE) included. These are partial reference snapshots, not buildable source checkouts. Three files contain the original `404: Not Found` response; the manifest marks them explicitly.
- [CVE2022_4262_NATIVE_EXEC_PLAN.md](research/CVE2022_4262_NATIVE_EXEC_PLAN.md): renderer-to-native experiments and outcomes.
- [PURRTOL_KERNEL_RACE_ASSESSMENT.md](research/PURRTOL_KERNEL_RACE_ASSESSMENT.md): kernel epoll route assessment.
- [M106_WEBGL_OBJECT_GRAPH.md](research/M106_WEBGL_OBJECT_GRAPH.md): WebGL/object graph investigation.
- Daily records: [September 26](research/SESSION_RECORD_2026-09-26.md), [27](research/SESSION_RECORD_2026-09-27.md), [28](research/SESSION_RECORD_2026-09-28.md), [29](research/SESSION_RECORD_2026-09-29.md), and [30](research/SESSION_RECORD_2026-09-30.md).
- [PORTAL_10_INCH_UNLOCK_ATTEMPTS.md](PORTAL_10_INCH_UNLOCK_ATTEMPTS.md): earlier device-access attempt history.
- [Raw session ZIP and event inventory](ARCHIVE.md): original messages, tool outputs, edits, and observations.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and licensing scope. [SHA256SUMS](SHA256SUMS) covers the published files; the research manifest additionally maps original workspace files to the archived copies.
