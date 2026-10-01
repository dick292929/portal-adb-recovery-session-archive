# Session Record — Portal 10" Full Unlock Campaign (through 2026-09-30)

**Target:** Meta Portal 10" Gen 1 (`aloha`, APQ8098/MSM8998, Android 9 `PKQ1.191202.001`, user build)
**Goal:** Flip the ADB toggle so Immortal Loader can be installed.
**Outcome:** A working renderer primitive was built; every escalation and adjacent route was then closed against device evidence or primary sources. The final lock is Meta's private key, which is nowhere public.

---

## 0. Executive Summary

The campaign proceeded in six phases, each ending at a *proven* boundary rather than a guess:

1. **Renderer (CVE-2022-4262):** a real arbitrary read/write primitive (`addr_of` / `fake_obj` / `v8_read64` / `v8_write64`) and a proven `call_indirect` hijack were built inside the captive-portal WebView.
2. **Native exec:** the primitive could not escalate because of a *precise, instruction-level* cause — V8's ARM32 wasm ABI poisons `r1` (`ClearAllCacheRegisters()`), and `r1` is not a parameter register.
3. **Kernel (CVE-2021-1048):** the epoll-UAF is confirmed *present and unpatched* but unreachable without renderer native exec.
4. **Sahara / EDL (CVE-2021-30327):** silicon identity pinned to APQ8098; the `0x13` reset path stalls at cycle 121→122; no signed Firehose exists.
5. **ADB switch / OTA / cert pin:** the exact switch (`ro.boot.force_enable_usb_adb`) was found; the user's own OTA was proven to be the ADB-enabled build; the OOBE failure was root-caused to native Fizz leaf-cert pinning.
6. **Final closures:** `fastboot flash` refused (`Lock State`); OEM_ID `0x0137` absent from the public loader registry; no AOSP test-key backdoor in the ABL; no loader/activation script in any language.

---

## 1. Device Identification & Reconnaissance

| Field | Value |
|---|---|
| Product | `aloha` (Portal 10" Gen 1) |
| Fingerprint | `Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041481900013050:user/prod-keys` |
| Build type | `user` (`ro.build.type=user`) |
| Security | `ro.secure=1`, `ro.adb.secure=1`, `ro.debuggable=0` |
| Renderer | `com.android.captiveportallogin` WebView, Chrome 106.0.5249.126, V8 10.6.194 |
| Userspace | AArch32 (`armv8l`), 32-bit pointers, no pointer compression / sandbox / external-code-space |
| Address space | full 4 GiB userspace on arm64 kernel; kuser page `0xFFFF0000` reserved |
| Silicon (EDL) | HWID `0x000620e10137b8a1` → MSM_ID `0x0620e1` (APQ8098), OEM_ID `0x0137`, MODEL_ID `0xb8a1` |
| OEM PK hash | `7291ef5c5d99dc05ee00237a1d71b1f572696870b839bb715fba9e89988b4a3f` |
| Storage | eMMC (per `bkerler/edl`: APQ8098 → emmc, secureboot reg `0x00780350`) |

Entry modes available on the unit: **Vol-Down + Power = EDL** (Sahara `05c6:9008`), **Vol-Up + Power = fastboot/ABL**. No keyboard (OTG/AOA HID non-functional), no volume-key recovery entry.

Firmware dump (`firmware/aloha_dump/`): `boot.elf` is the **kernel ELF** (aarch64, not stripped, 49 MB — *not* the ABL), `boot.img`, `boot/kernel` (gzip ARM64 Image), `boot/dtb/` (21 DTBs), `tz.img`, `system/`, `vendor/`, `kallsyms.txt`. The ABL (LinuxLoader) and PBL are **not** in the dump.

---

## 2. Renderer Exploit (CVE-2022-4262) — The Primitive

### 2.1 Primitives built

Inside the captive-portal WebView (V8 10.6, AArch32):

- `addr_of(obj)` → tagged pointer (`raw | 1`).
- `fake_obj(addr)` → forge a V8 object at a chosen address.
- `v8_read64(addr)` → arbitrary read; **works on LOW, HIGH (≥0x80000000) and RX**.
- `v8_write64(addr, val)` → arbitrary write; **reliable only on LOW RW / V8-heap**, SIGSEGVs on HIGH and on RX.

### 2.2 Wasm ABI (the critical constraint)

From V8 ARM32 source, the wasm ABI is:

- Parameter registers: `kGpParamRegisters = {r3, r0, r2, r6}`.
- Return registers: `kGpReturnRegisters = {r0, r1}`.
- The wasm instance lives in `r3`.

The fatal detail: `PrepareCall()` → `cache_state_.ClearAllCacheRegisters()` leaves a **V8-heap pointer in `r1`**, and `r1` is **not** a parameter register. Any native call therefore receives a garbage V8-heap pointer in `r1`.

### 2.3 Proven `call_indirect` hijack

- Overwrite `WasmInstanceObject.targets[0]` at `ibase + 0x2c`, where `ibase = bInstance - 1n`.
- The ref slot (`r3`) sits at struct offset `0x28` (40).

### 2.4 libc offsets resolved

(Thumb entries carry the +1 low bit.)

| Symbol | Offset |
|---|---|
| `getpid` | `0x1f6a4` |
| `abs` | `0x5fb74` |
| `printf` | `0x6d538` → `0x6d539` (Thumb) |
| `syscall` | `0x19e90` (ARM) |
| `mprotect` | `0x61738` (ARM) |
| `memcpy` | `0x19fe0` (ARM) |
| `mmap` | `0x29bc0` (Thumb) |
| `__errno` | `0x1cf7e` |

---

## 3. Native Exec Attempts — Why Every Route Died

Each was device-verified:

| Route | Mechanism | Failure |
|---|---|---|
| `mprotect` direct | call via hijacked slot | `len = r1` (poisoned) → ENOMEM |
| `syscall` direct | call via hijacked slot | `addr = r1` (poisoned) → SIGSEGV |
| JIT literal-pool spray | hope for contiguous RX constants | Liftoff emits `f64.const` as `movw/movt` + `vmov`; **no contiguous RX pool**; TurboFan async + GC-incompatible; no asm.js; Sparkplug off |
| RWX code-space window race | write into RX before it is executed | primitives SIGSEGV after a 500 ms GC yield (`gc_survival` never emitted) — the R/W does **not** survive GC |

Root cause of the direct-call failures (from V8 source): `PrepareCall()` → `cache_state_.ClearAllCacheRegisters()` poisons `r1`. The JIT routes are structurally absent, not just mis-addressed.

---

## 4. Kernel Route (CVE-2021-1048, epoll UAF)

- **Confirmed vulnerable and unpatched** on this kernel via disassembly of `ep_loop_check_proc`: a non-safe `rb_next` after a recursive `ep_call_nested`.
- Status: reachable *only* with renderer native exec, which §3 closed. So the kernel stage is real but orphaned.

Field research cross-reference: `amemefarmer/the-purrtol` (Portal+ 15.6", Chrome 86, CVE-2020-16040 renderer + an incomplete epoll-UAF kernel stage) was abandoned before root — same wall.

---

## 5. Sahara / EDL Route (CVE-2021-30327)

- PBL is ROM; the ABL (LinuxLoader) is a flash partition `abl_a`/`abl_b` and is **not in the dump**.
- Katana PoC (`research/katana_src/`) carries only an SDM845 profile; the MSM8998-generation (same silicon as APQ8098) stack underflow faults into an unmapped gap (Hexacon).
- 24+ probe scripts (`research/sahara_*.py`) were run against the device. Result: the PBL returned HELLO through **cycle 121, then stalled at 122** — consistent with the fault boundary, not a usable exploit.
- No signed Firehose matched among **2,723 indexed loaders**.

---

## 6. The ADB Switch

`vendor/etc/init/hw/init.common.usb.rc` gates ADB on:

```init
on property:ro.boot.force_enable_usb_adb=1 && property:ro.build.type=user ...
    setprop persist.sys.usb.config adb        # ENABLES adbd

on property:ro.boot.force_enable_usb_adb=0 && property:ro.vendor.build.flavor=aloha_prod-user
    stop adbd                                  # production runs this
```

- `ro.boot.force_enable_usb_adb` ← `androidboot.force_enable_usb_adb` in the kernel command line, appended by the **ABL**.
- `boot.img` base cmdline (offset `0x40`, 512 B): `console=ttyMSM0,115200,n8 … buildvariant=user veritykeyid=id:e36e29643be137513034d96a5b5a8209e4464d20` — **no** `force_enable_usb_adb`.
- Extracted `abl.img` contains **no** `force_enable_usb_adb` or `adb` string — the prod ABL never emits the flag.

Standard Android Developer Options controllers (`AdbPreferenceController`, `EnableAdbDialog`, `DeveloperOptionsPreferenceController`) exist in `SettingsFacebook`, but reaching Settings requires completing OOBE.

---

## 7. OTA Analysis & Extraction

### 7.1 The user's OTA is the ADB-enabled build

`firmware/aloha_ota_1041515800015050.zip` (1.28 GB, `SignApk`-signed):

```
ota-type=AB
post-build=Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys
post-security-patch-level=2019-08-01
post-timestamp=1760466470            # 2025-10-14
pre-device=aloha                     # no pre-build → FULL payload, not delta
```

Its `system.img` contains the ADB-enablement machinery (so this **is** the `unmetaportal`-tested "1.44.4 / Oct 2025" build):

```
#aloha_show_prod_adb_enabled_setting        ← Portal "Debug" gate
prod adb enabled: %b   fbns adb enabled: %b
ADB enabled [%b]
DIALOG_ENABLE_ADB / MSG_ENABLE_ADB
com.android.settingslib.development.AbstractEnableAdbController
enable_adb / enable_adb_summary
ro.boot.force_enable_usb_adb
```

### 7.2 Payload format (reverse-engineered and documented)

Wrote `firmware/extract_ota.py` — a from-scratch A/B payload (`CrAU`) dumper.

- Header: `"CrAU"` + `version` (u64 BE) + `manifest_size` (u64 BE) + `metadata_signature_size` (u32 BE).
- **`data_start = 24 + manifest_size + metadata_signature_size`** (the metadata signature sits *between* the manifest and the data blobs — not at the end; confirmed by finding the xz magic `fd 37 7a 58 5a 00` there).
- Manifest protobuf (field numbers observed empirically):
  - `DeltaArchiveManifest.partitions = 13`, `block_size = 3` (default 4096).
  - `PartitionUpdate.partition_name = 1`, `operations = 8` (non-standard field), `old_partition_info = 7`.
  - `InstallOperation.type = 1`, `data_offset = 2`, `data_length = 3`, `dst_extents = 6`.
  - `Extent.start_block = 1`, `num_blocks = 2`; `PartitionInfo.size = 1`.
- Operation types seen: `REPLACE(0)`, `REPLACE_BZ(1)` (bzip2), `ZERO(6)`, `REPLACE_XZ(8)` (xz via `lzma`).

### 7.3 Extracted partitions (`firmware/ota_extracted/`)

| Partition | Size |
|---|---|
| `system.img` | 3,221,225,472 (3.0 GB, ext4) |
| `vendor.img` | 3,221,225,472 (3.0 GB, ext4) |
| `boot.img` | 27,897,856 (valid `ANDROID!`, same size as dump's boot) |
| `modem.img` | 23,236,608 |
| `dsp.img` | 16,777,216 |
| `abl.img` | 217,088 (ELF 32-bit ARM, statically linked) |
| `xbl.img` | 2,686,976 (ELF 64-bit aarch64) |
| `tz.img` | 1,937,408 (ELF 64-bit aarch64) |
| `keymaster.img` | 315,392 |
| `cmnlib.img` / `cmnlib64.img` | 237,568 / 311,296 |
| `devcfg.img` | 61,440 |
| `hyp.img` | 274,432 |
| `pmic.img` | 53,248 |
| `rpm.img` | 237,568 |
| `bluetooth.img` | 454,656 |

Notably **no `vbmeta`** partition in the 16-partition payload.

---

## 8. OOBE Cert Rejection — Root Cause

### 8.1 Not dead servers

From the user's Vector 10: the device sends TLS fatal alert 46 (`certificate_unknown`) to `graph.facebook.com`, while the Mac *and the device's browser* both validate Meta's current cert. So the servers are up; the **native OOBE client** rejects the cert.

### 8.2 Two pinning layers

**Android `network_security_config`** (`res/xml/fb_network_security_config.xml` in `aloha_devicesetup_release.apk`):

- 18 × SHA-256 pins for `facebook.com`/`meta.com`/`fbcdn.net`/etc.
- **Device build `1041481900013050`:** `expiration="2025-11-08"` (past → pins ignored).
- **OTA build `1041515800015050`:** `expiration="2026-07-28"` (also past now; matches the "donor" deadline from Vector 10).
- `base-config` has `<certificates overridePins="true" src="user" />` — a user CA would override these Android pins.

**Native Fizz/Proxygen verifier** (inside the superpack native libs):

- String found: `Failed to verify leaf certificate identity(ies):`
- This pins the **leaf** certificate identity — and Meta has rotated the leaf. This is the actual `certificate_unknown` cause, separate from the (expired) Android pin-set.

### 8.3 SPKI comparison

Fetched Meta's current leaf and hashed its SubjectPublicKeyInfo:

```
current leaf SPKI SHA-256: 3vyHZYu0KX9cBlmM49Wt5pIU0/VUnK8d4SA80J31a9A=
in the 18-pin list?        False
```

Consistent: the 18 network-config pins are root/intermediate-level; the rejecting verifier is the native leaf pin.

---

## 9. Fastboot Flash Test (last write primitive)

The user ran the prepared commands against inactive slot A:

```
Sending 'boot_a' (27244 KB)      OKAY
Writing 'boot_a'                 FAILED (remote: 'Flashing is not allowed in Lock State')
Sending sparse 'system_a' 1/5    FAILED (usb_write failed with status e00002c0)
```

`Flashing is not allowed in Lock State` is definitive: the locked ABL refuses all flashing. `fastboot oem` and `fastboot boot` are "unknown command" (PurrTol capture). EDL is locked (no Firehose).

---

## 10. Chipset-Level Firehose Search

Public Snapdragon 835 / MSM8998 loaders exist but are per-OEM:

- `prog_ufs_firehose_8998_lgev30.elf` — LG V30 (OEM `0x0031`)
- `prog_ufs_firehose_8998_ddr.elf` — Galaxy S8+ (OEM `0x0020`)

Every Firehose carries an **OEM_ID + MSM_ID** and is signed with that OEM's key. The Portal requires:

| Check | Portal requires | Public 8998 loaders have | Match |
|---|---|---|---|
| MSM_ID | `0x0620e1` (APQ8098) | `0x0620e1` | ✅ |
| OEM_ID | `0x0137` (Meta) | LG / Samsung / etc. | ❌ |
| PK hash | `7291ef5c…` | other OEM key | ❌ |

### 10.1 Authoritative registry (`bkerler/edl` `qualcomm_config.py`)

- `vendor` dict has `0x0130` (GlocalMe) and `0x0139` (Lyf) but **no `0x0137`** — Meta's OEM_ID is unlisted.
- `root_cert_hash` lists Qualcomm roots (`cc3153a8…`, `7be49b72…`) — the Portal's `7291ef5c…` is **not** among them; it is Meta's custom OEM cert.
- `msmids` confirms `0x0620E1 = APQ8098`.

Conclusion: no public Firehose can verify against the Portal's PBL.

---

## 11. Test-Key Backdoor Check (LTBox / Lenovo class)

The [LTBox project](https://miner7222.github.io/ltbox/en/how-it-works.html) roots locked Lenovo tablets because their ABL trusts the **AOSP test key** (private key public in `external/avb/test/data/`).

Checked whether the Portal shares this flaw:

- Fetched AOSP `testkey_rsa2048.pem` and `testkey_rsa4096.pem`.
- Computed AVB key hashes:
  - `testkey_rsa2048`: `26f90bd5cc1e27b21b0ebce1a4784551bf219c1ad246c22d3720ae35b221b329`
  - `testkey_rsa4096`: `45cae59d9d4d8168dc1e7f68c731153c3c58f61d53791f2cd5f3775eba2cf610`
- Searched the Portal `abl.img` for both moduli (BE and LE) and both hashes: **not found**.
- Also searched for the Meta PK hash `7291ef5c…` and the dm-verity key `e36e2964…`: not present in `abl.img` (the AVB root of trust is fused in QFPROM, not embedded as a recognizable blob).

Conclusion: the Portal's ABL does **not** carry the AOSP test key. The Lenovo exploit class does not transfer.

---

## 12. Forum Sweeps (English / Russian / Chinese)

Four+ search passes (Chinese terms: `刷机`, `免授权`, `9008`, `救砖`, `激活`, `开发者`, `firehose`, `aloha`):

- **Chinese:** only general articles repeating the official ADB unlock. The most specific ([Hotdry Blog](https://blog.hotdry.top/posts/2026/06/05/meta-portal-adb-debug-abandoned-hardware/)) states plainly: *any system-level modification requires Meta's private-key signature*.
- **Russian/English:** XDA (bot-shielded via bunny.net), unmetaportal, Adafruit, HN. The recurring "dev Portal+ with root" XDA thread is a *development* unit (dev-signed, not transferable to a production unit) and is inaccessible.
- No Meta Firehose, no activation/OOBE-bypass script surfaced from any language.

---

## 13. Artifacts Produced

- `firmware/extract_ota.py` — reusable A/B payload dumper.
- `firmware/ota_extracted/` — all 16 partition images from `1041515800015050`.
- `/tmp/aloha_setup/` — decompiled device-build OOBE app (`apk_decoded/res/xml/fb_network_security_config.xml`).
- `/tmp/ota_setup.apk` + `/tmp/ota_setup_decoded/` — decompiled OTA-build OOBE app.
- `/tmp/*.pem`, `/tmp/*.mod` — AOSP test keys + moduli for the ABL check.
- This record.

Prior-session artifacts still in the workspace: `scripts/captive_portal_cve2022_4262_stage1.py` (~4144 lines), `scripts/run_portal_cve2022_4262_stage1.sh`, `research/PURRTOL_KERNEL_RACE_ASSESSMENT.md`, `research/APQ8098_SAHARA_RECOVERY_PLAN.md` (1596 lines), `PORTAL_CVE-2021-30327_HANDOFF.md`, `research/katana_src/`, `research/sahara_*.py` (24 probes).

Key constants distilled:

- Device `1041481900013050` pin deadline: **2025-11-08**.
- OTA `1041515800015050` pin deadline: **2026-07-28**.
- Boot cmdline (both builds): `buildvariant=user veritykeyid=id:e36e2964…`.
- OEM_ID `0x0137` (Meta), MSM_ID `0x0620e1` (APQ8098), PK hash `7291ef5c5d99dc05…`.

---

## 14. Decision Ledger

| Path | Verification source | Result |
|---|---|---|
| Renderer R/W primitive | Live WebView | ✅ built and working |
| `call_indirect` hijack | Live WebView | ✅ proven |
| Native exec (mprotect/syscall/JIT/RWX race) | Live WebView | ❌ `r1` poisoned + no RX pool + GC kills R/W |
| Kernel epoll-UAF | disassembly | ⚠️ present, unreachable |
| Sahara `0x13` | Live EDL | ❌ stalls at cycle 121→122 |
| Firehose (Meta) | `bkerler/edl` registry | ❌ OEM_ID `0x0137` unlisted |
| Chipset Firehose | public files | ❌ wrong OEM_ID + key |
| Test-key trust | AOSP keys vs `abl.img` | ❌ not present |
| ADB via ABL flag | `init.common.usb.rc` + `abl.img` | ❌ prod ABL never emits it |
| ADB via Settings toggle | OTA `system.img` | ⚠️ exists, needs Settings (OOBE-blocked) |
| `fastboot flash` | live run | ❌ `Lock State` |
| OOBE cert | native libs | ❌ Fizz leaf pin vs rotated cert |
| Forums (EN/RU/ZH) | 4+ passes | ❌ no loader / activation script |

---

## 15. Bottom Line

The 10-inch unit is **soft-locked**: hardware intact, every software/loader/exploit path closed, all against Meta's private key. It is not a hardware brick, but it is sealed.

Two genuinely open paths remain:

1. **Work the 15.6" Portal+** — already ADB-enabled; the Immortal Loader toolchain (`build_immortal_*.sh`, `immortal_*.apk`, `portal_assistant_patched.apk`, `portal_ha_patched.apk`, `reverse_engineering/`) is already built for it.
2. **Find the April–May 2026 Meta-signed OTA** (build > `1041515800015050`) — the only artifact that would add the `Settings > Debug > ADB Enabled` menu; a download hunt, not an exploit.
