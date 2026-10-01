# Session record — 2026-09-29

## Current handoff summary (2026-09-29)

**Target:** owner-reported Portal 10-inch Gen 1. The confirmed captive-login
request is `/generate_204` from `com.android.captiveportallogin`, Android 9,
build `PKQ1.191202.001`, Chrome `106.0.5249.126`; the page host was
`connectivitycheck.gstatic.com`. The browser reports `Linux armv8l` and a
Qualcomm Adreno 540 WebGL renderer. These strings do not independently establish
the process ABI or kernel architecture.

**Renderer evidence:** owner-supplied CVE-2022-4262 run output reported the
PoC's `0x30` marker, object recovery/identity candidate, a 32-bit ArrayBuffer
layout hint, and a matching reversible read/write/restore within a self-created
8 KiB ArrayBuffer. Six original-size allocation attempts failed; none succeeded.
No raw pointers were included. This is a renderer-side primitive candidate,
not native execution or Android access.

**Bridge and compatibility:** the compatibility page confirmed basic Wasm and
WebGL functionality. The latest descriptor scan reported no matching
bridge-like surface. Its enumerable-global list contained 26 ordinary browser
window functions; this heuristic does not rule out every possible interface.
The PurrTol `getpid` helper is pinned to Chrome 86.0.4240.198 and its
CVE-2020-16040 trigger, so it does not match the observed Chrome 106 WebView.

**CVE status:** Chrome 106 is in the upstream pre-fix version family for
CVE-2022-4262, whose Chrome 108 release was announced on 2022-12-02. A WebView
OEM backport has not been checked, so applicability is plausible, not
confirmed. No native stage was tested on this Portal; no sandbox escape, ADB
change, or Android access was achieved. A separate PurrTol-derived Chrome 86
adapter with a bounded native `getpid` proof was written, but its
CVE-2020-16040/Chrome 86 gate does not match this Portal's observed Chrome 106
login WebView and it was not served to this device. Earlier EDL/Sahara and USB
work is recorded chronologically below.

**Latest code changes:** `scripts/captive_portal_compat_probe.py` now performs
descriptor-only bridge-name inspection and a bounded enumerable-global
inventory. The embedded JavaScript regex escape warning was corrected. The
incomplete unused Wasm jump-table report scaffolding was removed from
`scripts/captive_portal_cve2022_4262_stage1.py`; no jump-table mutation was
implemented. The owner ran the compatibility helper; no tests or device
commands were run by Codex in this update.

**Code-execution handoff:** the CVE-2022-4262 work on this Portal stops at an
owner-reported JavaScript primitive candidate. The separate PurrTol adapter
contains a Chrome 86-gated native `getpid` proof payload, but was not served to
this Chrome 106 WebView. No native renderer execution on this Portal, sandbox
escape, Android command channel, or ADB change was achieved. See the code
inventory and milestone map in
[`RENDERER_TO_DEVICE_ACCESS_HANDOFF.md`](RENDERER_TO_DEVICE_ACCESS_HANDOFF.md).

## Public exploit-index and search-tool cross-check

Rechecked whether Katana is the only meaningful public lead. Qualcomm's CVE-2021-30327 record names APQ8098/MSM8998; its QPSS22 deck independently records Sahara `0x13`, an unnamed device crash after 130 resets, and the separate 26/27-reset signature behavior. Those sources establish a credible vulnerability-family lead, but they do not identify the tested PBL or give a Portal profile. CVE/exploit-index records dated June 2026 point back to Katana, not to another independent implementation. The Katana checked-in execution profile remains SDM845-only; Echidna is derived from Katana.

Other solid but non-transferable Qualcomm research includes Kaspersky's separate CVE-2026-25262 (published affected list excludes APQ8098/MSM8998), Aleph Security's signed-programmer EDL attacks, and Xperable's MSM8998 fastboot/XBL/ABL exploit. GitHub and Exa search connections were offered to broaden source/code search further, but remain unconnected. No Portal traffic was sent.

**Answer:** Katana is not the only solid evidence lead, but it is the only public runnable exploit branch for CVE-2021-30327 found so far. No independent Portal/APQ8098 cold-EDL trigger or bounded success oracle surfaced. Do not repeat the already logged reset/hash or inert-image tests.

Sources: [Qualcomm CNA record](https://www.cve.org/CVERecord?id=CVE-2021-30327), [QPSS22 slides](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/qpss22-christopher-wade.pdf), [Katana](https://github.com/Daniel224455/katana), [Echidna](https://github.com/Daniel224455/echidna), [exploit-index entry](https://vulners.com/githubexploit/616C2155-98D5-5316-BB35-BF924B098C71), [Kaspersky CVE-2026-25262](https://ics-cert.kaspersky.com/vulnerabilities/qualcomm-chipsets-series-write-what-where-condition-vulnerability-in-bootrom/), [Aleph Security EDL research](https://alephsecurity.com/2018/01/22/qualcomm-edl-1/), and [Xperable](https://github.com/j4nn/xperable).

## CVE source and upstream checker audit

Expanded the source/tool pass to the CVE Program's public JSON record and the actual `katana/check_vuln.py` and `soc_data.py` files, rather than relying on repository summaries or search snippets. Qualcomm's CNA record explicitly marks APQ8098 as affected by CVE-2021-30327, a physical-access EDL Sahara buffer overflow. That is a direct family-level vulnerability match for the Portal and means Katana is not the only solid lead. The record does not identify the Portal's PBL revision, explain patch/build applicability, or provide an APQ8098 exploit profile.

The upstream Katana checker sends a raw one-byte `0x13`, returns to command mode, and rereads OEM PK hash; its source loops up to 10,000 times. The Portal has already exercised this one-byte reset/hash method through 120 cycles without a hash change, then encountered a handshake timeout at the next boundary. Do not run the upstream loop unchanged or repeat the earlier one-byte test. Katana's separate exploit runner still has only an SDM845 payload/finish profile; Echidna is derived from that path. The 4-byte reset-word plus inert-image run is a different experiment and its `END_IMAGE_TX 0x28` result is not a CVE success oracle.

The expanded evidence/tool set now includes the Qualcomm-assigned CVE JSON, official QPSS22 slides, source-level GitHub and fork/issue review, public code indexes, Chinese Baidu/Bilibili, Yandex, GitLab/Gitee/Exploit-DB searches, security-vendor research, and same-chip device records. These sources establish more than one credible research trail, but this pass found no public APQ8098/Portal-matched runnable exploit or independent APQ8098 execution trace. No Portal traffic was sent and no firmware or service image was opened.

**Disposition:** CVE-2021-30327 is the strongest exact-chip lead; Katana is the only public runnable exploit branch found for that CVE family, not the only evidence. Since its one-byte checker flow is already covered by the Portal log, the next useful advance requires an APQ8098-specific PBL revision/trace or exploit profile with a bounded, observable postcondition. Do not repeat the one-byte reset loop or inert-image transfer.

Sources: [CVE Program record with Qualcomm CNA data](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/30xxx/CVE-2021-30327.json), [Katana checker source](https://github.com/Daniel224455/katana/blob/main/check_vuln.py), [Katana SoC profiles](https://github.com/Daniel224455/katana/blob/main/soc_data.py), and [Qualcomm QPSS22 slides](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/qpss22-christopher-wade.pdf).

## Meta Quest 1 as a same-chipset peer

Expanded the comparison to the first-generation Oculus Quest because it is a Meta product in the Snapdragon 835 generation. Meta's developer article identifies the Quest as Snapdragon 835; a published Quest build-property capture reports `ro.board.platform=msm8998`. QuestEscape's public research documents entry into EDL and an ABL `oem reboot-edl` command. That makes Quest 1 a closer OEM/SoC-generation comparator than unrelated Snapdragon phones.

The public Quest research contains no Sahara-v2 transcript, EDL HWID/PK hash, `0x13` reset test, unsigned image acceptance, or PBL execution result. The described access findings are ABL/fastboot and Android-kernel paths, including an ABL `oem sha1` issue; they do not establish access from the Portal's cold EDL state. Meta's platform label and the Quest's Snapdragon 835 identify a close peer but do not prove its fused HWID/PBL matches the Portal's APQ8098 unit.

**Result:** Quest 1 is a useful target for finding a raw same-OEM MSM8998 EDL trace, but this source pass did not find one. No Quest firmware was opened, no Portal packet was sent, and this finding supplies no new Portal command. The broader evidence remains: Qualcomm lists APQ8098 and MSM8998 for CVE-2021-30327, while the public Katana code has an SDM845 execution profile and no APQ8098 profile. See [the continuing Sahara recovery plan](APQ8098_SAHARA_RECOVERY_PLAN.md).

Sources: [Meta's Quest hardware overview](https://developers.meta.com/horizon/blog/down-the-rabbit-hole-w-oculus-quest-the-hardware-software/), [Quest build-property capture](https://gist.github.com/hxhb/0c72c436044e97f3f11ea44ad7f92912), and [QuestEscape EDL/ABL research](https://github.com/QuestEscape/research).

## Expanded Snapdragon 835 peer scan

Added HTC's first-generation VIVE Focus as another Snapdragon-835 comparison point. HTC's official specification confirms the processor, but does not identify the exact MSM/APQ part number. The public material located for VIVE Focus contains no 9008/Sahara transcript, HWID/PK-hash result, reset-recursion test, or loaderless PBL execution report. Treat it as a same-generation hardware peer, not proof of an identical Portal PBL.

The public `edk2-msm8998` project names OnePlus 5/5T, LG V30, Xiaomi Mi 6/Mi Mix 2, Essential PH-1, and HTC U11+ as supported Snapdragon-835 devices; its documented launch path is `fastboot boot`, so it is downstream of the EDL/PBL question. The `edl-ng` project lists MSM8998 among verified platforms but explicitly requires an appropriate Firehose programmer. These sources confirm broader development and service activity around MSM8998, while still documenting unlocked/downstream or signed-loader workflows rather than a cold-PBL bypass.

Rechecked the public CVE/PoC boundary: Qualcomm's CNA record names both APQ8098 and MSM8998 for CVE-2021-30327. Katana's README describes the `0x13` reset-recursion flaw in MSM8998 terms, but warns that a vulnerable SoC is not necessarily exploitable; its checked-in executable SoC data contains an SDM845 profile and no APQ8098 profile. Therefore the vulnerability-family match is real, but there is still no target-matched Portal exploit profile or public MSM8998 success trace to turn into a bounded Portal test.

**Result:** this sweep adds one same-generation VR device and several MSM8998 development platforms, but no new Portal input. No Portal packet was sent and no firmware image was inspected.

Sources: [HTC VIVE Focus official specifications](https://developer.vive.com/resources/hardware-guides/vive-focus-specs-user-guide/), [EDK2 for MSM8998 devices](https://github.com/edk2-porting/edk2-msm8998), [EDL-NG verified platforms and loader prerequisite](https://github.com/strongtz/edl-ng), [Qualcomm CNA record for CVE-2021-30327](https://www.cve.org/CVERecord?id=CVE-2021-30327), [Katana README](https://github.com/Daniel224455/katana), and [Katana SoC profile](https://github.com/Daniel224455/katana/blob/main/soc_data.py).

## Exact APQ8098 peer-device sweep

Expanded from MSM8998-family phones to products that explicitly identify the exact APQ8098 part. The strongest prospective comparison platform is the Lantronix/Intrinsyc Open-Q 835 development kit: the vendor identifies its SoC as APQ8098, and its board guide documents a forced-USB-boot/EDL selection plus an exposed debug UART. It is marked last-time-buy/discontinued, and the material reviewed does not establish its QFPROM/security-fuse state or show a public CVE-2021-30327 reproduction. It could support an exact-silicon PBL comparison if a board is already accessible, but its OEM identity and fuse setup would still differ from the Portal.

Production peers found with explicit APQ8098 evidence are Lenovo Mirage Solo (VR-1541F), Lenovo Mirage VR S3 (VR-3030S; teardown identifies APQ8098-102-AA), EPOS EXPAND Vision 5, and Freebox Player Devialet. A Mirage Solo owner report says the headset entered EDL but generic Samsung/Xiaomi programmers did not work. This is useful first-hand confirmation of an EDL state on an exact-chip commercial device, but the post has no raw Sahara HELLO, HWID/PK hash, reset-recursion test, or loaderless execution result. The separate Freebox hacking project says its test unit's USB-C connector was detached and lists EDL as a future phase; it has not supplied an EDL trace. The sources found for Mirage VR S3 and EXPAND Vision 5 establish the chip, not EDL exploit behavior.

The MSM8998 phones and Quest 1 remain a secondary comparison tier: public service logs show Sahara v2 followed by OEM/vendor Firehose programmers. Those are useful for protocol/version and recovery-workflow comparison, but they do not establish the Portal's APQ8098 OEM/PBL configuration or a cold-PBL exploit. Across both tiers, this search found no independent APQ8098/MSM8998 `0x13` recursion success trace, no APQ8098-specific Katana payload/profile, and no target-matched postcondition. The result is a better hardware shortlist, not a new Portal input. No Portal packet was sent.

**Next research priority:** look for an owner/lab report from the exact APQ8098 Open-Q 835, Mirage Solo, or Mirage VR S3 that includes raw Sahara identification plus the result of a documented PBL test. Do not treat an EDL entry screenshot, a service-tool success, or a matching Snapdragon 835 marketing name as evidence of trigger success. The prior Portal reset loops and metadata-only qtestsign run remain closed; this pass does not justify repeating them.

Sources: [Lantronix Open-Q 835 product page](https://www.lantronix.com/products/open-q-835-usom-development-kit/), [Open-Q board guide](https://support.intrinsyc.com/attachments/download/1604/Intrinsyc_Open-Q_835_Development_Kit_User_Guide_v1.0.pdf), [Lenovo Mirage Solo APQ8098 specification](https://www.lenovojp.com/business/solution/download/002/pdf/LenovoSelect_18summer.pdf), [Mirage Solo EDL report](https://www.reddit.com/r/daydream/comments/p3jqdz/any1_out_there_with_root_access/), [Lenovo Mirage VR S3 teardown](https://www.techinsights.com/products/ddt-2106-807), [EPOS EXPAND Vision 5 fact sheet](https://www.eposaudio.com/globalassets/__pim/products/expand-vision-5-/expand-vision-5-bundle/0e756e32-b777-404b-a2aa-9ec2d856f562_44254_fact-sheet-expand-vision-5_en_original.pdf), and [Freebox Player Devialet hardware-hacking project](https://github.com/EricBlanquer/freebox-devialet-hack).

One additional candidate is EchoNous KOSMOS Bridge, a handheld ultrasound platform. NIST's FIPS validation record lists its tested Android 8.1 configuration as Snapdragon 835 “APQ8098 / MSM8998,” while EchoNous product material identifies only Snapdragon 835; the slash leaves the exact application-processor part unresolved. Searches found no EDL/Sahara report or PBL test for it, so it is a low-confidence comparison lead rather than an exact-chip peer.

Source: [NIST CMVP certificate 3389](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/3389), [EchoNous KOSMOS product resources](https://echonous.com/product/resources/).

## Cross-check of public exploit and disclosure status

A useful chronology check came from the upstream U-Boot mailing list. An April 2026 SDM845 SPL patch says CVE-2021-30327 might help obtain the required control on some devices, but calls it undocumented and says no PoC was available at that time. Katana was published later in 2026 and supplies a concrete Sahara `0x13` recursion exploit profile for SDM845 only; its checked-in SoC data has no APQ8098 or MSM8998 entry. This explains why the CVE record and the Portal's `END_IMAGE_TX 0x28` response are insufficient to derive an APQ8098 trigger: the missing item remains the exact PBL profile and a target-specific success condition.

I also checked the new Kaspersky CVE-2026-25262 disclosure because it is another public Sahara/BootROM issue. Kaspersky's affected list is MDM9x07/9x45/9x65, MSM8909/8916/8952, and SDX50; it does not name APQ8098 or MSM8998. It is a separate write-what-where vulnerability, not evidence that its trigger transfers to the Portal. Searches in Chinese and Japanese forums and broader English EDL reports produced device-entry and signed-programmer recovery logs, but no raw APQ8098/MSM8998 PBL-exploitation trace.

**Result:** this adds an independent public-source check and a separate vulnerability boundary, but no Portal packet, new command candidate, or reason to repeat the closed reset/image tests. The actionable peer remains an APQ8098 Open-Q 835 board or APQ8098 retail device with a raw Sahara trace; absent that, an APQ8098-specific exploit profile is still the blocking evidence gap.

Sources: [April 2026 U-Boot SDM845 patch](https://lists.denx.de/pipermail/u-boot/2026-April/614033.html), [Katana README](https://github.com/Daniel224455/katana), [Katana SoC data](https://github.com/Daniel224455/katana/blob/main/soc_data.py), and [Kaspersky CVE-2026-25262 advisory](https://ics-cert.kaspersky.com/vulnerabilities/qualcomm-chipsets-series-write-what-where-condition-vulnerability-in-bootrom/).

## Expanded APQ8098/MSM8998 peer scan

The closest exact-silicon bench lead remains the Lantronix/Intrinsyc Open-Q 835 development kit. Its vendor guide identifies APQ8098 and documents a board switch for forced USB boot/EDL. Public Android kernel sources also identify APQ8098 MTP and Mediabox reference-board variants, but provide no Sahara/PBL exploit result or fuse-state comparison. These boards could be useful for a controlled protocol comparison if one is already accessible; their board configuration, OEM keys, and fuse state must not be assumed to match the Portal.

Two consumer cross-checks add hardware matches but no cold-EDL result. A Portal TV teardown identifies APQ8098; the recent “recovery achieved” post only enters Android recovery with `adb reboot recovery` after the OS is already running. Freebox's official Player Devialet and Freebox One guides also identify APQ8098; the public Freebox hardware-hacking project lists EDL as a later research phase and contains no Sahara transcript. These do not add a Portal command or PBL trigger.

For the adjacent MSM8998 variant, Aleph Security's OnePlus advisory confirms that some OnePlus 5 software could enter EDL from a running system (ADB) or a hardware key on OxygenOS 5.0 and earlier. Its recovery path then depends on OnePlus-specific signed programmers and bootloader downgrade; it does not reach code execution from the Portal's cold EDL state and does not establish cross-OEM signer compatibility.

The broadened English, Chinese, Russian, Japanese, and Korean exact-chip/MSM8998 searches found no raw APQ8098/MSM8998 Sahara exploit transcript, no APQ8098 Katana profile, and no independently reported successful `0x13` PBL run. The strongest next evidence checkpoint is the ZeroNights 2026 Qualcomm BootROM talk scheduled for September 30: check the released slides or recording for the tested SoC/PBL and whether its CVE-2026-25262 demonstration includes APQ8098/MSM8998. Until a source ties a reproducible trigger and bounded success oracle to this target, the recent `END_IMAGE_TX 0x28` does not justify another Portal command.

Sources: [Open-Q 835 user guide](https://support.intrinsyc.com/attachments/download/1604/Intrinsyc_Open-Q_835_Development_Kit_User_Guide_v1.0.pdf), [APQ8098 MTP/Mediabox kernel-source record](https://android.googlesource.com/kernel/msm/%2B/29860ce302f202c1ac721cfd51e3a3d7de6e308), [Portal TV teardown](https://electronics360.globalspec.com/article/14945/teardown-facebook-portal-tv), [Portal TV recovery report](https://www.reddit.com/r/FacebookPortal/comments/1w89ob7/portaltv-recovery-achieved/), [Freebox Player Devialet guide](https://assistance.cdn.scw.iliad.fr/Userguide_Freebox_Delta_Player_Devialet_9f5dd54f62.pdf), [OnePlus EDL advisory](https://alephsecurity.com/vulns/aleph-2017007), and [ZeroNights program summary](https://habr.com/ru/companies/dsec/articles/1085342/).

## Additional Snapdragon 835 appliance comparator

The Poly Studio X50 video bar is a newly identified appliance-class comparison point. NIST's validation record identifies the tested X50 platform as Android 8.1 on Qualcomm Snapdragon 835. Qualcomm presents APQ8098 and MSM8998 as the related Snapdragon 835 application-processor family, but the X50 sources reviewed do not identify which exact SKU it uses. Searches for an X50 9008/Sahara trace, EDL HWID/PK hash, or loaderless PBL result found none; its public recovery material describes a product-level factory restore, not a demonstrated EDL path. Treat it as a same-generation lead, not an exact-chip or exploitability match.

**Result:** the broader appliance scan adds one possible peer but no transferable Portal input or new test. No Portal traffic was sent and no firmware or service bundle was opened.

Sources: [NIST CMVP certificate 4469](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4469), [Qualcomm APQ8098/MSM8998 platform page](https://www.qualcomm.com/processors/application-processors/products/apq8098), and [HP Studio X50 support guides](https://support.hp.com/us-en/product/setup-user-guides/studio-x50-series/model/2101738667).

## Fresh public BootROM disclosures checked against the 835 peer set

The newly published Black Hat Asia 2026 slide deck for Christopher Wade's *Practical Attacks Against Smartphone Boot ROMs* does not describe a Qualcomm 835 target. Its first case study is a Google Tensor Pixel 6a, using a USB `SET_SEL` control-transfer flaw in ABL/ROM Recovery; the second is Samsung Exynos EUB on Galaxy A04S/A25. Those are useful examples of BootROM attack surfaces on other platforms, but their USB requests and boot stages do not map to the Portal's Qualcomm PBL/Sahara bulk interface. They supply no APQ8098/MSM8998 trigger.

The companion Black Hat/Kaspersky Sahara disclosure is also outside the Portal's exact chipset family. Kaspersky says its CVE-2026-25262 research primarily used MDM9207 and lists MDM9x07/45/65, MSM8909/8916/8952, and SDX50; APQ8098 and MSM8998 are not listed. Keep it separate from CVE-2021-30327, which is the known family match for the Portal. Rechecking OnePlus 5, Pixel 2, Mi 6/Mi Mix 2, and Galaxy S8 service reports produced only signed-programmer service flows, not a cold-PBL exploit transcript or an APQ8098-matched result.

**Result:** the expanded public-source pass found no new same-chip execution trace or target-specific input. It does not change the stopping point: the Portal's last inert image attempt ended at `END_IMAGE_TX 0x28` before body bytes, and no new Portal command is justified by these cross-platform disclosures. No Portal traffic was sent; no firmware or service file was opened.

Sources: [Black Hat Asia 2026 BootROM presentation slides](https://i.blackhat.com/Asia-26/Presentations/BHAS26-Wade-Practical-Attacks-REV01.pdf), [Kaspersky's CVE-2026-25262 analysis](https://www.kaspersky.com/blog/qualcomm-cve-2026-25262/55811/), [Kaspersky ICS CERT conference note](https://ics-cert.kaspersky.com/publications/events/2026/04/20/kaspersky-ics-cert-experts-present-vulnerability-in-qualcomm-chips-at-black-hat-asia/), and [Qualcomm's CVE-2021-30327 record](https://www.cve.org/CVERecord?id=CVE-2021-30327).

## Open-Q 835 exact-silicon debug-surface recheck (2026-09-29)

Rechecked the Lantronix/Intrinsyc Open-Q 835 documentation as the strongest APQ8098 lab comparator. The vendor guide identifies the SoC as APQ8098 and documents DIP S2301-1 as a choice between forced USB boot and EDL, a debug UART exposed over USB through an FTDI bridge, and a 20-pin JTAG header wired to the main processor. The same JTAG section says the kit has no vendor software support for JTAG. The companion hardware spec labels one SOM connector signal `APQ_GPIO132` as “Secure boot”; the documentation does not establish that this is an external secure-boot override or that it changes QFPROM policy. Treat it only as a routed signal label.

This is a meaningful hardware lead for a controlled same-silicon PBL comparison if an Open-Q 835 board is already accessible: it has an explicit EDL selector and more observability than the Portal board. It is not a successful CVE-2021-30327 reproduction. The sources found still provide no Open-Q Sahara transcript, PBL patch version, fuse/security state, or `0x13` execution result; Lantronix lists the kit as “Last Time Buy” and does not recommend it for new designs. The JTAG header therefore does not imply that debug authentication is disabled, and its availability does not establish a path into the Portal.

**Result:** the board is a better exact-APQ8098 test fixture candidate, but the exploit evidence gap remains. No Portal packet was sent, no firmware/service bundle was inspected, and no new Portal command is justified. If this board becomes available, the first useful comparison artifact is its read-only boot/security identity plus a raw Sahara greeting, before attempting any vulnerability input.

Sources: [Lantronix Open-Q 835 product page](https://www.lantronix.com/products/open-q-835-usom-development-kit/), [Open-Q 835 development-kit guide](https://support.intrinsyc.com/attachments/download/1604/Intrinsyc_Open-Q_835_Development_Kit_User_Guide_v1.0.pdf), [Open-Q 835 SOM hardware spec](https://tech.lantronix.com/attachments/download/10371/Open-Q%20835%20uSOM%20HW%20Device%20Spec%20v1.0.pdf), [Qualcomm CVE-2021-30327 record](https://www.cve.org/CVERecord?id=CVE-2021-30327), and [Katana PoC](https://github.com/Daniel224455/katana).

## Quest 1's newly released unlock compared with the Portal EDL path

The expanded same-generation search found the August 2026 QuestStack release for the first-generation Meta Quest, a Snapdragon 835/MSM8998 peer. It chains Android-side root access with Qualcomm CVE-2021-1931 in ABL fastboot, stages a vulnerable bootloader on an inactive slot, and then unlocks the bootloader. The public project explicitly gates itself to Quest products and expected firmware fingerprints. Qualcomm's CVE record lists Snapdragon 835 among affected platforms and rates the fastboot issue as requiring high privileges; the Quest project demonstrates that a separately obtained root path can satisfy that prerequisite on its own supported headset.

This is useful comparative evidence that a same-generation Meta headset has an OS/ABL route. It does not test Sahara, does not provide a cold-EDL foothold, and does not establish that the Portal's APQ8098 ABL has the same vulnerable build or accepts Quest-specific images. It therefore does not change the present EDL stopping point. No Portal packet was sent and no firmware image was opened during this source check.

**Result:** the new peer lead is downstream of Android access and cannot replace the missing APQ8098 cold-PBL profile. Keep the QuestStack route as a separate comparator; do not repeat the closed `0x13` reset/hash or inert ELF metadata tests on the Portal.

Sources: [QuestStack project and device gates](https://github.com/starseed12345/QuestStack), [QuestStack coverage summary](https://vr.org/articles/quest-1-bootloader-unlock-queststack-webusb-2026), [Qualcomm CVE-2021-1931 record](https://nvd.nist.gov/vuln/detail/CVE-2021-1931), [Portal HWID/APQ8098 mapping recorded earlier](SESSION_RECORD_2026-09-26.md), and [Qualcomm APQ8098/MSM8998 platform page](https://www.qualcomm.com/processors/application-processors/products/apq8098).

## MSM8998 peer HWID and exploit-project recheck

Compared raw peer Sahara identities with the Portal's recorded `MSM_ID`. The Pixel 2 EDL report and Xiaomi Mi 6 service transcript both identify `MSM_ID 0x0005e0e1`; this Portal's live identity is `MSM_ID 0x000620e1`, mapped to APQ8098 in the prior session record. Qualcomm groups APQ8098 and MSM8998 under the Snapdragon 835 family, so the phones remain useful protocol and generation references, but their captures do not establish the Portal's exact PBL identity or configuration.

I also followed the CVE-2021-30327 exploit project's companion repository, Echidna. It describes itself as a wrapper for devices exploitable by Katana and states its supported targets are Snapdragon 845 devices except Samsung. That gives no second MSM8998/APQ8098 execution profile. Katana still describes the MSM8998 reset-recursion flaw but its executable profile remains SDM845-only.

**Result:** the handset reports are lower-confidence peers for this Portal than the exact APQ8098 Open-Q/Mirage devices, and the public unlocker chain still offers no APQ8098 payload or success trace. Keep MSM8998 phones for protocol comparison; prioritize raw EDL captures from APQ8098 hardware. No Portal traffic was sent and no firmware or service file was opened.

Sources: [Pixel 2 Sahara identity report](https://github.com/bkerler/edl/issues/204), [Xiaomi Mi 6 Sahara/Firehose report](https://github.com/bkerler/edl/issues/555), [Qualcomm APQ8098/MSM8998 platform page](https://www.qualcomm.com/processors/application-processors/products/apq8098), [Echidna repository](https://github.com/Daniel224455/echidna), and [Katana repository](https://github.com/Daniel224455/katana).

## Further APQ8098/MSM8998 public-trace search

Ran a further exact-ID and device-name search for `0x620e1`, APQ8098 EDL/Sahara logs, and raw Sahara captures from Open-Q 835, Mirage Solo/VR S3, and EPOS EXPAND Vision 5. It did not find a public same-ID Sahara transcript or raw PBL exploit trace. A later search found a public normal-boot trace from a Lenovo APQ8098 reference board with the same low silicon ID; it reports Secure Boot off and contains no EDL/Sahara test.

The Qualcomm CNA entry for CVE-2021-30327 names APQ8098 and MSM8998, but gives no PBL build, test sequence, affected OEM fuse configuration, or per-device result. Katana's public explanation describes the MSM8998 `0x13` reset-recursion flaw, while its checked-in executable profile is SDM845-only. A separate EDLUnlock README says MSM8998 “should also work,” then explicitly marks that list untested and says its included patched programmer is MSM8953-only; this is not a demonstrated MSM8998 PBL exploit or a Portal-ready trigger. Public OnePlus 5 EDL reports document OEM service/programmer workflows, not successful loaderless execution.

**Result:** the expanded same-chipset scan produced no new command candidate or comparable successful execution. Exact APQ8098 board captures remain the most relevant missing evidence. Do not infer a transferable trigger from a Snapdragon 835 marketing label, the broad CVE affected list, or the untested EDLUnlock claim. No Portal packet was sent and no firmware or service image was opened.

Sources: [Qualcomm CNA entry for CVE-2021-30327](https://www.cve.org/CVERecord?id=CVE-2021-30327), [Katana repository](https://github.com/Daniel224455/katana), [EDLUnlock README](https://github.com/Giovix92/EDLUnlock), [OnePlus EDL advisory](https://alephsecurity.com/vulns/aleph-2017007), and [Open-Q 835 user guide](https://support.intrinsyc.com/attachments/download/1604/Intrinsyc_Open-Q_835_Development_Kit_User_Guide_v1.0.pdf).

Exact-ID follow-up: a Lenovo Vega EVB APQ8098 Linux-mm boot log reports JTAG ID `0x200620e1`, Chip Ver 2.1, PBL Patch Ver 2, and Secure Boot off; the JTAG ID's trailing 24 bits (`0x0620e1`) numerically match this Portal's Sahara `MSM_ID 0x0620e1`. This confirms a public APQ8098 reference-board identity comparison, not a Sahara/PBL exploit match. An indexed log for an unidentified 8998 board also carries JTAG ID `0x200620e1`, but reports Secure Boot off and PBL Patch Ver 1; Xiaomi Mi 6 logs show Secure Boot on and PBL Patch Ver 2 with a different silicon ID (`0x5e0e1`). No comparable cold-EDL exploitation result was found. Sources: [Lenovo Vega EVB APQ8098 boot log](https://www.spinics.net/lists/linux-mm/msg128766.html), [indexed MSM8998 boot log](https://lkml.indiana.edu/hypermail/linux/kernel/1902.0/03670.html), and [Xiaomi Mi 6 boot log](https://wiki.postmarketos.org/wiki/Xiaomi_Mi_6_%28xiaomi-sagit%29).

## Forensic-vendor chipset coverage check (2026-09-29)

Oxygen Forensics' published extraction-method sheet describes Qualcomm EDL coverage for older chipsets and lists Snapdragon 845, 710, 665, 675, 730, and 855, but it does not list MSM8998/Snapdragon 835 or APQ8098. MSAB's separate public flyer lists 665, 670, 710, 712, and 845, likewise omitting the Portal's family. These public lists do not prove that a vendor has no private or case-specific method; they provide no publicly advertised same-chip access path to pursue. No vendor was contacted, no Portal packet was sent, and no firmware or service file was opened.

**Result:** this adds a second vendor-coverage boundary but no new APQ8098/MSM8998 trigger or Portal test. The public CVE-2021-30327 match remains the relevant vulnerability lead; the missing evidence is still an APQ8098-compatible PBL execution profile and a bounded success signal.

Sources: [Oxygen Forensics extraction-method sheet](https://oxygenforensics.com/uploads/press_kit/Device_Extraction_Methods.pdf) and [MSAB Snapdragon exploit flyer](https://www.msab.com/wp-content/uploads/2023/10/New_Snapdragon_Exploit_2023.pdf).

## Additional MSM8998 peer trace and exploit-profile check (2026-09-29)

A Xiaomi Mi Mix 2 repair log reports `MSM_ID 0x0005E0E1` (MSM8998/Snapdragon 835), then a vendor tool's Sahara boot and Firehose connection using a selected service programmer. It records routine signed service only; no `0x13` sequence or loaderless result. Its `PBL Ver: 00000000` field is not the `PBL Patch Ver` reported in Linux boot logs. The primary Hexacon abstract names a locked Pixel but not its exact model, while the public Katana repo's only checked-in executable finish profile is for `sdm845`; neither supplies an APQ8098/MSM8998-ready profile. Sources: [Mi Mix 2 Sahara/Firehose service log](https://forum.gsmhosting.com/vbb/f1065/xiaomi-mi-mix-2-chiron-successfully-flashed-hydra-too-2960332/), [Hexacon talk abstract](https://2023.hexacon.fr/conference/speakers/), and [Katana repository](https://github.com/Daniel224455/katana).

**Result:** this adds a concrete same-SoC Sahara service trace, but no exploit reproduction or new Portal command candidate. No Portal traffic was sent and no firmware or service image was opened during this research pass.

## Commercial Snapdragon exploit coverage screen (2026-09-29)

MSAB's 2023 public flyer lists Snapdragon 665, 670, 710, 712, and 845 for an unnamed paid-access exploit. It omits APQ8098, MSM8998, and SDM660 and gives no CVE, protocol, device transcript, or exploit stage. It cannot validate a Portal match or be treated as a CVE-2021-30327 result. Source: [MSAB Snapdragon exploit flyer](https://www.msab.com/wp-content/uploads/2023/10/New_Snapdragon_Exploit_2023.pdf).

## Additional exact-APQ8098 VR peers and EDL report (2026-09-29)

Expanded the same-chipset scan to iQIYI's Qiyu headsets and Lenovo Mirage Solo. Qualcomm/iQIYI's official release groups Qiyu 2, 2S, and 2Pro on Snapdragon 835; an owner CPU-Z report for Qiyu 2S identifies APQ8098 and Adreno 540, making it an additional exact-APQ8098 retail peer. iQIYI's public Qiyu SDK covers those headsets at the application layer and gives no bootloader or EDL details.

Lenovo's product specification identifies Mirage Solo as APQ8098. A Mirage Solo owner report says the unit could be put into EDL but the author lacked a Firehose programmer; it contains no Sahara HWID/PK hash, PBL revision, raw capture, or PBL exploit result. Searches for those exact identifiers and for Qiyu 2S/2Pro 9008/Sahara traces found no such record. The Mirage report therefore confirms a peer's EDL accessibility only, not a transferable trigger.

**Result:** the expanded device set adds Qiyu 2S as an exact-SoC retail peer and a direct Mirage Solo EDL anecdote, but no APQ8098 PBL execution profile or new Portal test candidate. No Portal packet was sent, and no firmware or service image was downloaded or inspected.

Sources: [Qualcomm/iQIYI Qiyu 2 family announcement](https://www.iqiyi.com/kszt/news20210113.html), [Qiyu 2S APQ8098 owner report](https://post.smzdm.com/p/awx454xp/), [iQIYI Qiyu developer SDK](https://github.com/iQIYIVR/QIYU_VR_v2), [Lenovo Mirage Solo APQ8098 product specification](https://www.lenovojp.com/business/solution/download/002/pdf/LenovoSelect_18Autumn.pdf), and [Mirage Solo EDL report](https://www.reddit.com/r/daydream/comments/p3jqdz).

## Same-chipset Freebox Devialet EDL research project review (2026-09-29)

Found a second public Freebox Player Devialet project, which identifies its target as APQ8098/Snapdragon 835 and is directly comparable at the SoC/product-appliance level. Its roadmap lists the Sahara `0x13` PBL path as promising, but explicitly says it remains to be tested; the repository contains no EDL/Sahara identity capture, raw packet log, or successful loaderless result. A related open issue reports the author's assessment that EDL servicing requires a Firehose signed for that board's HWID and key hash. That is the project's report, not an independently published test result for this Portal.

A separate hardware-hacking repo for the same Freebox model confirms APQ8098 and identifies candidate UART pads, but its posted status still has UART/recon work pending and no EDL transcript. The other repo's Free-specific `snapl` test-mode boot work is a custom later-stage bootloader path, not evidence about Qualcomm PBL/Sahara and not transferable to the Portal.

**Result:** this is the best new same-chipset project to watch for a future APQ8098 EDL capture. At present it adds no tested `0x13` profile, matching HWID/PK hash, or bounded success oracle, so it does not justify another Portal command. No Portal traffic was sent, and no firmware or service image was opened.

Sources: [Freebox-tool APQ8098 project](https://github.com/aminekun90/freebox-tool), [its boot-chain/EDL roadmap](https://github.com/aminekun90/freebox-tool/blob/main/ATTACK-ROADMAP.md), [its EDL findings](https://github.com/aminekun90/freebox-tool/blob/main/FINDINGS.md), [related Freebox EDL/firehose issue](https://github.com/EricBlanquer/freebox-devialet-hack/issues/1), and [second Freebox hardware project](https://github.com/EricBlanquer/freebox-devialet-hack).

## Snapdragon 835 VR headset and reference-board extension (2026-09-29)

Extended the peer set to HTC VIVE Focus and PICO G2 4K, both standalone VR headsets officially described as Snapdragon 835 devices. The public material located for them does not identify their exact APQ/MSM part number and yielded no EDL/Sahara transcript, HWID/PK hash, PBL revision, or loaderless result. A VIVE Focus developer-kit owner reports an ABL/fastboot bootloader unlock, which is a later-stage dev-kit result and does not establish a cold-PBL path.

Rechecked the exact-APQ8098 Open-Q 835 development kit as a controlled same-silicon reference. Its official user guide documents carrier-board switch S2301-1 as selecting forced USB boot versus EDL. That provides a documented hardware way to repeat EDL measurements on an APQ8098 reference platform if such a board is available; the guide does not publish a Sahara exploit trace or show that its trust configuration matches a fused retail Portal. The board is therefore a better candidate for controlled PBL comparison than inferring behavior from MSM8998 phones, but it is not a Portal trigger.

**Result:** the expanded VR cohort yielded no new raw PBL evidence. The APQ8098 reference kit is the only new practical comparator lead, and it still does not support another Portal command. No Portal packet was sent and no firmware or service image was opened.

Sources: [HTC VIVE Focus specifications](https://www.vive.com/us/newsroom/2018-11-08-2/), [PICO G2 4K official specifications](https://www.picoxr.com/jp/products/g2-4k/specs), [VIVE Focus dev-kit owner report](https://www.reddit.com/r/AndroidQuestions/comments/1kezqhy/), [Open-Q 835 APQ8098 user guide and EDL switch](https://support.intrinsyc.com/attachments/download/1604/Intrinsyc_Open-Q_835_Development_Kit_User_Guide_v1.0.pdf), and [Open-Q 835 hardware specification](https://tech.intrinsyc.com/attachments/download/10371/Open-Q%20835%20uSOM%20HW%20Device%20Spec%20v1.0.pdf).

## CVE-2021-30327 peer behavior and sequence cross-check (2026-09-29)

Rechecked the original Qualcomm Product Security Summit 2022 deck against the current public Katana implementation. The deck documents Sahara command `0x13`, a crash after 130 resets on an unnamed test phone, and different signature/hash effects around 26–27 resets; it separately says attempts on SDM665 did not reproduce the result and reports configuration/hash overwrite on SDM665 and SDM730. It does not identify the reset-test phone as APQ8098/MSM8998, so those counts and effects are not a Portal profile.

Katana's README describes the MSM8998 recursion issue, but its executable `soc_data.py` contains only an SDM845 profile. Its exploit code uploads the exploit payload and reaches a successful end-of-image response before performing that profile's reset loop and profile-specific finishing writes. Its separate `check_vuln.py` uses one-byte `0x13` resets and checks OEM PK hash after each cycle. The Portal's recent qtestsign run used four-byte QPSS22 reset words before requesting image transfer, and its inert ELF was rejected at metadata with `END_IMAGE_TX 0x28` before body bytes. That run is therefore not equivalent to Katana's exploit or vulnerability-check flow; it neither confirms nor disproves the CVE on this unit.

The separate one-byte detector path is already represented in the Portal's earlier live records: the OEM PK hash stayed unchanged through 120 reset/hash cycles, the command-mode run timed out waiting for `CMD_READY` at cycle 121, and a raw reset-only run returned HELLO through cycle 121 before timing out at cycle 122. This matches the public checker's reset-and-hash method closely enough that replaying it would add no useful coverage. The public checker itself loops up to 10,000 times, so its default run is not a bounded test for this target. No APQ8098-specific Katana payload, reset/finish profile, or independent MSM8998 exploit-success transcript was found in this expanded peer scan.

A Chinese secondary write-up claims Snapdragon 835's stack overrun may fault in an unmapped region before reaching useful function-pointer data, unlike several later SoCs. This conflicts with Katana's MSM8998 vulnerability description and is not supported by a primary APQ8098/MSM8998 trace, so it remains an unverified hypothesis. The cross-check yielded no APQ8098 profile, target-matched input, or bounded Portal success oracle. No Portal packet was sent and no firmware or service image was opened during this research pass.

Sources: [Qualcomm Product Security Summit 2022 slides](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/qpss22-christopher-wade.pdf), [Katana README](https://github.com/Daniel224455/katana), [Katana exploit sequence](https://raw.githubusercontent.com/Daniel224455/katana/main/katana.py), [Katana vulnerability check](https://raw.githubusercontent.com/Daniel224455/katana/main/check_vuln.py), [Katana SoC profiles](https://raw.githubusercontent.com/Daniel224455/katana/main/soc_data.py), and [secondary Snapdragon 835 analysis](https://www.cnblogs.com/sakrain/p/-/unlock-your-qualcomm).

## MSM8998 peer sweep and Sahara 0x28 status meaning (2026-09-29)

Expanded exact-Snapdragon-835 phone searches across OnePlus 5/5T, Xiaomi Mi 6/Mi Mix 2, LG V30, Essential PH-1, HTC U11+, and Pixel 2-family devices, including Chinese-language searches for MSM8998 `0x13`/Sahara exploitation. Keep their relevance qualified: the Portal's captured `MSM_ID=0x0620e1` maps to APQ8098, while common phone peers identify as MSM8998 (`0x05e0e1`); Qualcomm groups them in the Snapdragon 835 family, but they are distinct MSM IDs and do not establish identical PBL revision, memory layout, or OEM/fuse state. Public sources show ordinary EDL service interactions on OnePlus 5 and Mi Mix 2, but none exposes a raw reset-loop result, a CVE-2021-30327 exploit payload/profile, or an unsigned-loader success trace. This adds no reproducible peer trigger. The qtestsign project's `-v5` label means its Qualcomm image/hash-segment packaging format supports MSM8998 and SDM845; its own README says it is not expected to boot on production devices with fused secure boot, so “v5” is not an MSM8998 exploit profile.

One new interpretation point for the Portal logs: the public Sahara status table maps `END_IMAGE_TX status=0x28` to `SAHARA_NAK_HW_BULK_TRANSFER_ERROR` (“Hardware Bulk transfer error”). That value is distinct from its documented invalid-PHDR/ELF codes (`0x0D`, `0x0E`, `0x13`) and hash/authentication codes (`0x20`–`0x26`). Therefore the observed `0x28` does not, by itself, diagnose a malformed PT_LOAD/hash table or a secure-boot signature rejection. It reports a bulk-transfer error according to that implementation's status table; it does not identify the underlying USB/PBL cause, and the table is community protocol code rather than a Qualcomm specification. The prior qtestsign metadata-only runs consequently remain inconclusive about CVE-2021-30327, but are not a reason to repeat the same transfer sequence. A future investigation would first need the peer's raw USB transaction trace or another independent APQ8098 trace that explains this status.

**Result:** no same-chipset exploit sequence was found. No Portal packet was sent and no firmware or service image was opened.

Sources: [qtestsign supported-chipset notes and security-boot caveat](https://github.com/msm8916-mainline/qtestsign), [OnePlus 5 MSM8998 Sahara service log](https://forum.gsmhosting.com/vbb/f296/successfully-unlocked-repaired-phones-infinity-box-725574/index3547.html), [OnePlus MSM8998 service log](https://forum.gsmhosting.com/vbb/f296/successfully-unlocked-repaired-phones-infinity-box-725574/index3871.html), [Katana current SoC data](https://raw.githubusercontent.com/Daniel224455/katana/main/soc_data.py), and [Sahara status/error table](https://raw.githubusercontent.com/bkerler/edl/master/edlclient/Library/sahara_defs.py).

## Same-APQ8098 project update and official Portal developer path (2026-09-29)

Rechecked the public Freebox Player Devialet project on the exact APQ8098 after its August 2026 update. The maintainer now reports app-level QML/JavaScript execution through the product's documented developer endpoint, still confined by a sandbox, and a later-stage `snapl` test-mode path that is specific to Free's custom bootloader and board wiring. The notes still report no root, no Qualcomm PBL/Sahara exploit result, and no generic Portal-transferable input; the remaining `fbxauthd` check is product-specific. This is useful evidence that Snapdragon peers can expose OEM boot-chain or developer surfaces beyond EDL, but does not establish those surfaces on Aloha.

Meta's own Portal developer documentation, updated in June 2026, now explicitly supports Portal 1st/2nd gen and documents enabling ADB through Settings > Debug for app deployment. Meta's developer blog likewise says developers can deploy apps through ADB. This is confirmed app-level access after the device reaches settings, not root or bootloader unlock, and it does not solve the current unit's onboarding block or its EDL question.

Also screened the newer CVE-2026-25262 Sahara disclosure. Kaspersky's affected list names MDM9x07/45/65, MSM8909/8916/8952, and SDX50; it does not name APQ8098 or MSM8998. A separate July 2026 repository claims an experimental result on SM8450 but reports partial success and supplies no full exploit tool. That is an adjacent-family lead, not evidence for this Portal.

**Result:** the exact-APQ8098 peer has promising OEM-specific research, while the official Meta path offers post-onboarding app deployment. Neither provides a new cold-EDL trigger or explains the Portal's prior `END_IMAGE_TX 0x28`. No Portal traffic was sent and no firmware or service image was opened during this pass.

Sources: [Freebox Player APQ8098 project](https://github.com/aminekun90/freebox-tool), [Meta Portal development setup](https://developers.meta.com/horizon/documentation/android-apps/portal-setup/), [Meta's Portal developer announcement](https://developers.meta.com/horizon/blog/build-apps-for-portal-with-ai/), [Kaspersky's CVE-2026-25262 analysis](https://www.kaspersky.co.uk/blog/qualcomm-cve-2026-25262/30591/), and [experimental SM8450 report](https://github.com/shurikgo/cve-2026-25262-sm8450-research).

## Newly released Quest 1 root and ABL-unlock chain (2026-09-29)

The same-OEM Snapdragon-835 comparison produced a new, concrete Quest 1 result: the public `QuestStack` project now documents a working root/bootloader-unlock workflow on its supported Quest firmware. It first gains Android root through a separate kernel privilege-escalation chain, then writes a vulnerable ABL into the inactive slot and uses CVE-2021-1931 in fastboot to unlock the bootloader. Qualcomm/NVD rates CVE-2021-1931 as requiring high privileges, and QuestStack's separate root stage is how its workflow supplies that prerequisite. Its documented requirements are a normally booted Quest, the exact supported firmware, and an authorized USB-debugging/ADB connection; it performs a factory reset. Meta independently identifies the original Quest as Snapdragon 835.

This is a useful same-OEM boot-chain comparison and a proof that the high-privilege ABL CVE can be chained on that Quest build. It is not an EDL/Sahara result: it neither operates from cold PBL nor supplies a Portal-compatible payload. QuestStack explicitly supports Quest hardware/firmware and rejects other headsets; Portal identifies as APQ8098 (`MSM_ID=0x0620e1`), whereas the Quest peer is a distinct product configuration in the Snapdragon-835 family. The workflow also needs an authorized ADB connection, which this Portal currently lacks during onboarding. It therefore yields no new Portal command or live-test candidate; retain it only as a later-stage comparison if ADB access is independently obtained.

**Result:** one newly released Meta/835 peer chain confirms a compound Android-root-to-ABL path on Quest 1, but the current Portal barrier remains cold EDL. No Portal traffic was sent and no firmware or service image was opened.

Sources: [QuestStack workflow and exact support requirements](https://github.com/starseed12345/QuestStack), [Meta's Quest 1 Snapdragon 835 hardware article](https://developers.meta.com/horizon/blog/down-the-rabbit-hole-w-oculus-quest-the-hardware-software/), and [NVD CVE-2021-1931 record](https://nvd.nist.gov/vuln/detail/cve-2021-1931).

## Fresh CVE-2021-30327 result on adjacent Snapdragon 845 peers (2026-09-29)

A September 14, 2026 Linux mailing-list report provides a concrete newer result for the same vulnerability family: its author says EDL access was used to dump UFS LUNs from three production Sony Xperia Tama devices (XZ2 Compact/Akari, XZ2/Akatsuki, and XZ3/Apollo), based on the SDM845 implementation in Katana. This is stronger than a service-programmer log because it records successful storage access through the exploit path. The Tama devices are SDM845 peers, not the Portal's APQ8098/MSM8998 silicon.

The currently published Katana source still has only an `sdm845` SoC profile. Its exploit sequence also depends on a received payload and SoC-specific finishing data; the Portal's prior inert-image attempt stopped at metadata with `END_IMAGE_TX 0x28`, before sending image-body bytes or reaching that profile's post-transfer phase. Thus the new report confirms the SDM845 branch can produce real EDL/UFS access, but it neither validates the MSM8998 branch nor supplies a Portal-ready input. The Hexacon 2023 abstract still identifies its demonstration only as a bootloader-locked Pixel, so the exact Pixel/SoC remains unconfirmed from the public abstract.

Also checked a seemingly broader MSM8998 EDL-unlock claim. Its README names MSM8998 only under “should also work” and explicitly marks the list untested; the only included working example is the MSM8953 Mi A1. It requires a working, patched Firehose MBN/ELF and changes the `devinfo` partition, so it is a post-loader storage-modification method and does not address the Portal's missing signed loader.

**Result:** newly confirmed exploit-path storage access on adjacent SDM845 retail devices; no new same-chipset MSM8998/APQ8098 reproduction or Portal test candidate. No Portal packet was sent and no firmware or service image was opened.

Sources: [Sony Tama UFS/EDL report on the Linux kernel mailing list](https://lkml.iu.edu/2609.1/15275.html), [Katana SoC profile](https://raw.githubusercontent.com/Daniel224455/katana/main/soc_data.py), [Katana exploit sequence](https://raw.githubusercontent.com/Daniel224455/katana/main/katana.py), [Hexacon 2023 talk abstract](https://2023.hexacon.fr/conference/speakers/), and [EDLUnlock README](https://github.com/Giovix92/EDLUnlock).
## APQ8098/MSM8998 peer CVE sweep: fuse and post-boot paths (2026-09-29)

The broader chipset search found two conditional software-stage leads and one fuse-state hypothesis, but no additional cold-EDL trigger.

Qualcomm CVE-2020-3657 lists APQ8098 and describes a QCMAP web-interface flaw; JFrog's analysis says vulnerable QCMAP deployments varied by OEM and some tested products did not include or run the affected service. Its research centered on mobile-hotspot/router products. This gives a possible local-network route only if the Portal actually runs an affected, reachable QCMAP service after normal boot. There is no public evidence that Aloha includes QCMAP, and this issue does not operate in Sahara/EDL.

Qualcomm CVE-2020-11206 lists both APQ8098 and MSM8998, but is a FastRPC input-validation issue with a local attack vector. Check Point describes FastRPC calls as originating from Android user processes; this is a downstream application/DSP surface, not a PBL foothold, and requires an Android-side execution path that has not been established during onboarding.

A 2019 NoCon slide deck by Bjoern Kerler names an MSM8998 QFPROM register and says secure-boot-disabled fusing can undermine later trust checks, but its list of confirmed affected devices does not include MSM8998. The deck itself cautions that some technical details are simplified or may be wrong. Current public `bkerler/edl` documentation describes QFPROM dumping as requiring an EL3 Firehose loader, so the old slide's loaderless wording does not currently yield a verifiable read-only Portal test. A nonzero Sahara OEM public-key hash alone does not establish that image authentication is enabled.

For the MSM8998 Samsung Galaxy S8/Note 8 peer set, CVE-2018-21070 describes a Samsung N/O software bootloader-integrity flaw. It is OEM- and boot-stage-specific and provides no evidence for Meta's APQ8098 PBL or EDL path.

**Result:** the QCMAP surface is worth a presence/reachability check only if the Portal reaches normal boot; do not send its exploit request based on the SoC match alone. FastRPC and Samsung's bootloader issue remain post-EDL comparators. No Portal traffic was sent and no firmware or service image was opened.

Sources: [NVD CVE-2020-3657](https://nvd.nist.gov/vuln/detail/CVE-2020-3657), [JFrog QCMAP analysis](https://jfrog.com/blog/major-vulnerabilities-discovered-in-qualcomm-qcmap/), [NVD CVE-2020-11206](https://nvd.nist.gov/vuln/detail/CVE-2020-11206), [Check Point FastRPC/DSP research](https://research.checkpoint.com/2021/pwn2own-qualcomm-dsp/), [Bjoern Kerler's 2019 NoCon slide deck](https://www.scribd.com/document/1067270476/Qual-Comm-Crypto), [bkerler/edl QFPROM notes](https://github.com/bkerler/edl), and [INCIBE CVE-2018-21070 summary](https://www.incibe.es/en/incibe-cert/early-warning/vulnerabilities/cve-2018-21070).

## Thundercomm TurboX APQ8098 peer and crash-dump workflow (2026-09-29)

Added the Thundercomm TurboX S835 SBC for VR as another exact-chip development-board peer. Thundercomm's product catalog identifies that board as APQ8098, with UFS storage and 4/6 GB LPDDR4x. Its Easy Flash guide documents ordinary 9008 flashing and partition backup; full partition backup requires a valid flash package and its download-config XML. The guide separately describes “Memory Dump” for a crashed device over a Qualcomm HS USB port. Qualcomm's public Memory Dump Collector guide identifies its crash collection interface as Sahara over Qualcomm HS-USB Diagnostics 90DB and documents entering crash mode from a rooted, running Android system. The Qualcomm guide is not proof that Thundercomm Easy Flash uses the same backend, but it distinguishes that documented crash-dump workflow from cold 9008 access.

The public TurboX material found here provides no raw Sahara HELLO/HWID/PK-hash transcript, CVE-2021-30327 result, unsigned-image acceptance, or loaderless execution report. It adds a good exact-APQ8098 comparison target and clarifies that “memory dump” in this vendor tooling is not evidence of an EDL exploit. It does not supply a new Portal input or justify sending another command. No Portal packet was sent and no firmware or service image was opened.

Sources: [Thundercomm TurboX S835 SBC for VR product catalog](https://pub-mediabox-storage.rxweb-prd.com/exhibitor/document/exh-74927ea3-6c46-44c2-be2b-acbb1646d701/75e85e1f-790e-4d61-99f7-8aa68ccd0645.pdf), [TurboX Easy Flash User Guide](https://www.thundercomm.com/documents/turbox-easy-flash-user-guide/), and [Qualcomm Memory Dump Collector user guide](https://github.com/qualcomm/qcom-memory-dump-collector/blob/main/doc/User_Guide.md).

## Expanded same-chip device and CVE search (2026-09-29)

Added two devices to the APQ8098 peer set: Lenovo Mirage VR S3 (TechInsights identifies APQ8098-102-AA) and EchoNous Kosmos Bridge (NIST's Android 8.1 validation lists Snapdragon 835/APQ8098/MSM8998). Searches of their product names with EDL, 9008, Sahara, fastboot, and bootloader found no public raw Sahara identity, CVE-2021-30327 result, unsigned transfer, or loaderless execution trace.

Rechecked the Qualcomm CVE-2021-30327 record: the affected-chipset list explicitly includes APQ8098 and MSM8998. That is a real family-level match to the Portal chipset, but it still supplies no Portal PBL revision or payload profile. Katana's public executable payload/finish profile remains SDM845-only. Newer search hits CVE-2019-10628 (local kernel TLB corruption via a user library) and CVE-2020-3693 (local qseecom out-of-range pointer) are later-stage OS/TEE issues, not cold-EDL triggers. Display/fastboot CVEs surfaced in 2026 also retain high-privilege requirements and provide no proven Portal path.

**Result:** the same-chip sweep expanded, but no new APQ8098/MSM8998 Sahara reproduction or Portal-safe test candidate emerged. No Portal command was sent, and no firmware or service image was opened. The detailed source review is in [APQ8098_SAHARA_RECOVERY_PLAN.md](APQ8098_SAHARA_RECOVERY_PLAN.md).

Sources: [Mirage VR S3 APQ8098-102 teardown](https://www.techinsights.com/products/ddt-2106-807), [NIST EchoNous Kosmos Bridge validation](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/certificate/3389), [Qualcomm CNA record for CVE-2021-30327](https://www.cve.org/CVERecord?id=CVE-2021-30327), [Katana SoC payload profile](https://github.com/Daniel224455/katana/blob/main/soc_data.py), [CVE-2019-10628](https://nvd.nist.gov/vuln/detail/CVE-2019-10628), [CVE-2020-3693](https://nvd.nist.gov/vuln/detail/CVE-2020-3693), and [Android June 2026 Qualcomm component bulletin](https://source.android.com/docs/security/bulletin/2026/2026-06-01).

## Portal sibling-device EDL trace search (2026-09-29)

Expanded the same-chip comparison to Meta's first-generation Portal+ (`Ohana`), the closest public sibling to this 10-inch `Aloha`. A community device map says Ohana shares Android firmware with Aloha; a Portal+ owner independently reports Android properties `ro.board.platform=msm8998` and `ro.product.board=aloha`. Other current Portal+ owners report reaching Android settings, enabling ADB, and sideloading apps on stock software. This confirms a close Android-board/software peer, but the properties and app access do not identify the silicon SKU or establish PBL equivalence with the Portal's Sahara ID `0x0620e1`.

Targeted public searches for Aloha/Ohana plus EDL, Sahara, `05c6:9008`, and QUSB found no raw Sahara identity, OEM key hash, PBL patch version, `0x13` test, or loaderless execution report. The Portal+ reports therefore help identify a same-OEM peer with working HLOS access, but add no cold-PBL trigger. No device was contacted, no Portal packets were sent, and no firmware image was opened.

Sources: [Portal+ board-property report](https://www.reddit.com/r/FacebookPortal/comments/1wecj05/portal_1st_gen_hardware/), [community Portal codename and firmware-sharing map](https://www.reddit.com/r/FacebookPortal/comments/1iqxs3t/facebook_portal_android_roms_published/), and [Portal+ ADB/sideloading report](https://www.reddit.com/r/FacebookPortal/comments/1wfb94s/finally_turned_my_old_facebook_portal_plus_into_a/).

## Expanded public code-search tools; SDM855 hash-change report

Added Chromium/Bing, anonymous GitHub REST issue/repository/fork search, and grep.app code-index searches to the prior web/CVE/forum sweep. Exact grep.app searches returned no `APQ8098 Sahara` code; `boot_sahara_entry` appeared only in Katana; `SAHARA_RESET_STATE_MACHINE_ID` appeared in Katana and the generic bkerler protocol implementation. Four public Katana forks surfaced; direct reads of all four `soc_data.py` files show the same sole `sdm845` profile and no APQ8098 profile. Google served an automated-traffic page and Sourcegraph/GitLab gated the request, so those sources remain unsearched. These index results bound the search; they cannot rule out private, unindexed, or deleted material.

New lead: [Katana issue #3](https://github.com/Daniel224455/katana/issues/3) reports a changed PK-hash read during a checker run on a Pixel 4 XL, an SM8150/Snapdragon 855 device; Qualcomm lists SM8150 for CVE-2021-30327. The author says they enlarged the response read to `0x400`, received one `RX (0x90)` block, and called part of it a corrupted PK hash. The issue has no baseline, verified before/after comparison, complete reset trace, PBL revision, comments, or execution result. A grep.app search for its distinctive response prefix returned no independent code copy. The current checker sends a one-byte `0x13` and uses a fixed `0x60` read; [issue #2](https://github.com/Daniel224455/katana/issues/2) documents a different Pixel 5 experiment using a full 8-byte reset and advertised data length, with no hash change after thousands of cycles. The exact Pixel 4 XL test sequence therefore remains unresolved. Katana remains the core public exploit project; the issue adds an adjacent-chip signal, not an APQ8098 test candidate. No Portal traffic was sent.

Sources: [Google Pixel 4/4 XL specifications](https://support.google.com/pixelphone/answer/16043605?hl=en-GB), [current Katana checker](https://github.com/Daniel224455/katana/blob/main/check_vuln.py), [Qualcomm CNA record](https://www.cve.org/CVERecord?id=CVE-2021-30327), [Katana fork network](https://github.com/Daniel224455/katana/network/members), [grep.app reset-symbol search](https://grep.app/api/search?q=SAHARA_RESET_STATE_MACHINE_ID), [grep.app response-prefix search](https://grep.app/api/search?q=fcb1320000000000), and [expanded source analysis](APQ8098_SAHARA_RECOVERY_PLAN.md).

## Expanded code and media search: Echidna is a second SDM845 codebase (2026-09-29)

Added GitHub REST tree/content inspection and direct issue-body review to the existing Chromium/Bing, grep.app, fork-network, and public forum searches. The [Echidna repository](https://github.com/Daniel224455/echidna) is a second runnable codebase; its README calls it a Katana-based Snapdragon 845 bootloader unlocker, and its checked-in [`soc_data.py`](https://github.com/Daniel224455/echidna/blob/main/soc_data.py) has only the `sdm845` profile. Its [`main.py`](https://github.com/Daniel224455/echidna/blob/main/main.py) invokes the Katana path. This broadens the public implementation set from one project to two, but supplies no APQ8098/MSM8998 profile or independent trigger validation.

Located the official [Hexacon talk recording](https://www.youtube.com/watch?v=3Zs45Cl3HfQ). YouTube exposes auto-caption metadata, but transcript content would not load and the player could not play in this browser. The official abstract still says only “bootloader-locked Pixel”; no target SoC could be confirmed from the recording in this pass. Targeted searches across GitHub repositories/issues, grep.app, Chinese code/forum indexes, 4PDA, XDA, and exploit/CVE sources found no other APQ8098/MSM8998 EDL trigger. Google search was CAPTCHA-gated; Sourcegraph and GitLab were inaccessible. This is a bounded public-index sweep, not proof that no private or unindexed lead exists.

**Result:** Katana is not the only codebase or evidence trail. Echidna is a Katana-derived SDM845 implementation; the Hexacon presentation, Qualcomm advisory, QPSS22 work, Sony SDM845 results, and Pixel 4 XL report add supporting evidence at varying strength. The strongest executable branch remains SDM845-only. No APQ8098/Portal-matched trigger or bounded success signal emerged. No Portal traffic was sent and no firmware or service image was opened.

Sources: [Echidna](https://github.com/Daniel224455/echidna), [Katana](https://github.com/Daniel224455/katana), [Hexacon recording](https://www.youtube.com/watch?v=3Zs45Cl3HfQ), [Hexacon abstract](https://2023.hexacon.fr/conference/speakers/), [Katana issue #3](https://github.com/Daniel224455/katana/issues/3), and [Qualcomm CVE-2021-30327 record](https://www.cve.org/CVERecord?id=CVE-2021-30327).

## Chinese search-engine and video-platform cross-check (2026-09-29)

Expanded the research tools with direct Baidu and Bilibili UI searches alongside the existing web, GitHub REST/fork, grep.app, and technical-forum searches. Queries used Chinese terminology for APQ8098/MSM8998, Sahara `0x13`, PBL stack overflow, Xiaomi Mi 6, and 9008 authentication bypass. Baidu mainly returned Qualcomm's official CVE-2021-30327 record and generic repair material. One Baidu snippet claimed a Xiaomi Mi 6 PBL bypass/MD5-collision route, but an exact-title web search did not corroborate it and Bilibili's own search did not return the claimed video. Do not count it as evidence without an accessible primary demonstration; the claimed Mi 6 fuse state also needs to be reconciled with the public production boot log reporting Secure Boot on.

The Bilibili page for a 2023 Xiaomi EDL-authentication video says the uploader had tested only a Xiaomi Note 3 and speculates about other pre-2018 devices for which a package exists. It provides no raw Sahara/PBL trace or MSM8998/APQ8098 test. A separate Mi 6 9008 clip shows repair-service context only. These are tooling/community references, not a Portal-compatible trigger.

**Result:** the new Chinese-language indexes did not yield an independent APQ8098/MSM8998 exploit reproduction. Katana is not the only evidence: Qualcomm's CNA advisory is a direct family-level vulnerability match, and SDM845 exploit-path BootROM/UFS reports independently show the vulnerability is operational on that peer. However, Katana/Echidna remain the only public runnable exploit branch found, and their checked-in profiles are SDM845-only. No Portal traffic was sent; no firmware or service image was fetched or opened.

Sources: [Qualcomm CVE-2021-30327](https://www.cve.org/CVERecord?id=CVE-2021-30327), [Bilibili Xiaomi EDL-authentication video](https://www.bilibili.com/video/BV1JD4y1V7d6/), [Xiaomi Mi 6 production boot log](https://wiki.postmarketos.org/wiki/Xiaomi_Mi_6_%28xiaomi-sagit%29), and [Bilibili Mi 6/MSM8998 PBL and Sahara search](https://search.bilibili.com/all?keyword=%E5%B0%8F%E7%B1%B36%209008%20PBL%E6%BC%8F%E6%B4%9E%20%E5%93%88%E5%B8%8C%E7%A2%B0%E6%92%9E%20MSM8998).

## Broader toolset: independent Sahara BootROM research (2026-09-29)

Expanded beyond the prior search and code indexes using the official Black Hat Asia 2026 program/materials, Kaspersky ICS CERT's advisory and technical write-up, direct inspection of a public GitHub follow-up's README/evidence/tools, and targeted Gitee, GitLab, and Exploit-DB searches. The GitLab/Exploit-DB queries returned no APQ8098/MSM8998 CVE-2021-30327 exploit; Gitee surfaced Qualcomm Sahara host/server source in an IPQ8074 tree, not a PBL exploit.

This found an independent research track beyond Katana: Kaspersky's CVE-2026-25262 is a Sahara/PBL write-what-where flaw. Kaspersky says the bulk of its research used MDM9207; its affected list names MDM9x07/45/65, MSM8909/8916/8952, and SDX50, but not APQ8098 or MSM8998. A separate public SM8450/POCO F4 GT follow-up claims an arbitrary SRAM write and a basic Firehose `nop` after applying the same CVE family. The write-up marks full Firehose initialization as incomplete, withholds its modified test tool, and its evidence log references an engineering Firehose image. Treat it as an adjacent-chip research lead, not a reproduced Portal method or an instruction to source that image.

The older Aleph Security Firehose/Firehorse research is another strong, independent Qualcomm boot-chain body of work across several older SoCs. Its EDL attacks operate through already accepted OEM-signed programmers, so it does not remove the Portal's missing-loader problem. Together these results answer the question precisely: Katana is not the only solid Qualcomm BootROM/EDL research lead on the internet. It remains the only public runnable CVE-2021-30327 exploit branch found in this search, and its checked-in profile is SDM845-only. None of the additional tracks establishes a Portal/APQ8098 trigger or bounded success oracle. No Portal traffic was sent; no firmware or service image was fetched or opened by this research pass.

Sources: [Kaspersky CVE-2026-25262 advisory](https://ics-cert.kaspersky.com/vulnerabilities/qualcomm-chipsets-series-write-what-where-condition-vulnerability-in-bootrom/), [Kaspersky technical write-up](https://www.kaspersky.com/blog/qualcomm-cve-2026-25262/55811/), [official Black Hat Asia 2026 presentation](https://i.blackhat.com/Asia-26/Presentations/BHAS26-Kozlov-Anufrienko-Qualcom-REV01.pdf), [Black Hat review-board summary](https://www.blackhat.com/html/blog/2026-02-25.html), [SM8450 follow-up repository and evidence](https://github.com/shurikgo/cve-2026-25262-sm8450-research), [Aleph Qualcomm EDL research](https://alephsecurity.com/2018/01/22/qualcomm-edl-1/), [B. Kerler Qualcomm EDL client](https://github.com/bkerler/edl), and [Gitee Qualcomm IPQ8074 Sahara server source](https://gitee.com/sususususu/Qualcomm-IPQ8074/blob/master/BOOT.BF.3.3.1/boot_images/core/storage/tools/QSaharaServer/src/sahara_protocol.c).

## Yandex index cross-check and a same-silicon non-EDL exploit (2026-09-29)

Added Yandex to the search set and followed its MSM8998/Sahara results to the original Xperable source. Xperable is a concrete, publicly implemented Qualcomm Snapdragon 835/MSM8998 exploit on Sony Xperia XZ Premium/XZ1/XZ1 Compact: CVE-2021-1931 targets Sony's fastboot USB handling in XBL/ABL and the README documents arbitrary code execution in fastboot. This is a solid same-silicon exploit result beyond Katana, but it is not a cold-EDL/PBL/Sahara path. The documented setup depends on Sony-specific bootloader/XFL versions and a temporary root shell to write the older XFL image; the Portal is currently available only in EDL and cannot complete onboarding, so this does not provide a Portal action. Qualcomm/NVD's affected-chipset list includes SD835, but does not make Sony's XBL/ABL binary or exploit parameters transferable to the Portal.

The same pass cross-checked Sahara status `0x28`: B. Kerler's current parser labels it `SAHARA_NAK_HW_BULK_TRANSFER_ERROR`, while OpenPST's Qualcomm-derived header enumerates through `0x26` and declares the next value as the maximum. Treat “hardware bulk transfer error” as one implementation's label, not a fully corroborated standardized diagnosis. The Portal's `0x28` still does not identify a specific malformed PHDR, signature failure, or successful execution, and it does not justify another transfer experiment.

**Result:** no additional APQ8098/MSM8998 loaderless PBL trigger emerged. Katana remains the only public runnable CVE-2021-30327 exploit branch found in this search; Xperable is a separate, strong MSM8998 fastboot/XBL/ABL exploit branch with prerequisites that the Portal does not meet. No Portal traffic was sent; no firmware or service image was opened.

Sources: [Xperable source and platform/setup notes](https://github.com/j4nn/xperable/blob/master/README.rst), [NVD CVE-2021-1931 record](https://nvd.nist.gov/vuln/detail/cve-2021-1931), [B. Kerler Sahara status table](https://github.com/bkerler/edl/blob/master/edlclient/Library/sahara_defs.py), and [OpenPST Sahara status enum](https://github.com/openpst/libopenpst/blob/master/include/qualcomm/sahara.h).

## CVE/exploit index expansion (2026-09-29)

Added multilingual web queries and cross-checked Qualcomm CNA records, Shodan's CVE database, OpenCVE CPE mappings, and Vulners exploit entries against their original sources. CVE-2021-30327 remains the exact-chip EDL/Sahara finding: Qualcomm's record lists APQ8098 and MSM8998. CVE-2026-24085/24091 appear in third-party APQ8098 CPE aggregations, but Qualcomm's CNA JSON masks the affected products, so those are not confirmed APQ8098 matches. Their descriptions concern later display/fastboot parsing and require high privileges; they do not give an EDL-only entry point. The separate 2026 Sahara CVE-2026-25262 does not list APQ8098/MSM8998.

Vulners' result titled as an “Apq8097_Firmware” exploit links back to Daniel224455/Katana and labels the attachment `katana.gzip`; it is a catalog duplicate, not a new PoC. The broader Qualcomm boot-chain evidence includes other solid but non-transferable tracks: Kaspersky's older-chip Sahara research, Aleph's signed-programmer attacks, and Xperable's MSM8998 Sony fastboot/XBL/ABL exploit. Katana remains the only public runnable CVE-2021-30327 branch found, with an SDM845-only checked-in profile. No Portal packets were sent.

Sources: [Qualcomm CVE-2021-30327 record](https://www.cve.org/CVERecord?id=CVE-2021-30327), [APQ8098 CVE index](https://cvedb.shodan.io/dashboard/vulnerabilities?product=apq8098), [OpenCVE CVE-2026-24085 mapping](https://opencve.alliance.unm.edu/cve/CVE-2026-24085), [Vulners catalog record](https://vulners.com/githubexploit/616C2155-98D5-5316-BB35-BF924B098C71), and [original Katana repository](https://github.com/Daniel224455/katana).

## APQ8098 boot-CVE access-stage check (2026-09-29)

Reopened the APQ8098-matched CVE-2020-11132 because its wording says “in boot.” Qualcomm's record describes an over-read while copying a GUID attribute from a request to a response and lists APQ8098. NVD scores it `AV:L/AC:L/PR:L`; Google's November 2020 Pixel bulletin identifies only a closed-source Qualcomm component. No public material maps the request/response to Sahara, PBL, or EDL, and the local low-privilege precondition is not present in the Portal's current EDL state. Keep this as an APQ8098 boot-stack CVE to revisit only if a normal-OS entry becomes available; it is not a Portal cold-EDL trigger. One May 2020 bulletin search snippet juxtaposed an APQ8098 chipset list with the XBL_SEC CVE-2019-14054 description; the CVE-specific Qualcomm CNA/NVD affected-product record omits APQ8098, so it is not counted as an exact-chip match.

Sources: [NVD CVE-2020-11132 record and vector](https://nvd.nist.gov/vuln/detail/CVE-2020-11132), [Android Pixel November 2020 bulletin](https://source.android.com/docs/security/bulletin/pixel/2020-11-01), and [NVD CVE-2019-14054 affected-product record](https://nvd.nist.gov/vuln/detail/CVE-2019-14054).

## Cross-index, exact-symbol, and research-tool pass (2026-09-29)

Expanded searches to exact code symbols (`boot_sahara_entry`, `SAHARA_RESET_STATE_MACHINE_ID`), academic venue indexes, public source indexes, vendor CVE aggregators, and the upcoming conference agenda. Queries for the exact CVE/symbol combinations yielded no independently maintained CVE-2021-30327 exploit implementation and no APQ8098/MSM8998 PBL execution trace. Tenable/NotCVE index the Katana/Echidna branch; the Echidna repository says it is a Katana-based unlocker and lists Snapdragon 845 support. Katana's checked-in SoC profile is SDM845-only. These are one exploit family, not multiple independent leads.

This pass supports a sharper answer: Katana is not the only solid Qualcomm boot-chain lead overall. Qualcomm's CNA finding and QPSS22 research independently establish a real EDL/Sahara vulnerability family that includes APQ8098/MSM8998, and Kaspersky and Aleph document separate BootROM/EDL research. But Katana is the only public runnable software exploit found for the exact CVE-2021-30327 path; the other tracks either concern different SoCs or require a signed programmer / later boot stage. None is a Portal-matched cold-EDL trigger.

The research-tool directory showed Consensus as an available scholarly paper-search option; it was suggested but is not connected yet. Existing GitHub/Exa suggestions also remain unconnected. This pass used the built-in web index and source-page inspection; it is not an exhaustive search of all Internet content. The ZeroNights program lists the Qualcomm BootROM/Sahara talk on September 30, 2026, at 10:00 MSK and describes it as CVE-2026-25262 research. Review its released recording/materials for exact chipset scope and any APQ8098/MSM8998 evidence; the agenda itself adds no target-specific exploit evidence.

No Portal traffic was sent. No firmware or service image was inspected. Do not repeat reset/hash or inert-image experiments.

Sources: [Qualcomm CNA JSON](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/30xxx/CVE-2021-30327.json), [Katana SoC profile](https://github.com/Daniel224455/katana/blob/main/soc_data.py), [Echidna README](https://github.com/Daniel224455/echidna), [QPSS22 slides](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/qpss22-christopher-wade.pdf), [Tenable CVE entry](https://www.tenable.com/cve/CVE-2021-30327), [Qualcomm APQ8098/MSM8998 page](https://www.qualcomm.com/processors/application-processors/products/apq8098), and [ZeroNights agenda announcement](https://habr.com/ru/companies/dsec/articles/1085342/).

## APQ8098 CVE false-positive boundary check (2026-09-29)

The exact-chip search returned CVE-2020-3698 and CVE-2020-11206. Qualcomm/AOSP/NVD descriptions place them in WLAN association-response processing and the DSP FastRPC path, respectively—not PBL/Sahara. They are APQ8098 vulnerabilities, but neither creates an entry from the Portal's current 9008 state. The same search surfaced generic Qualcomm host clients `qdl` and `qdlrs`; those are transport/service utilities, not publicly documented signature bypasses. No Portal packet was sent.

Sources: [Android July 2020 bulletin](https://source.android.com/docs/security/bulletin/2020-07-01), [NVD CVE-2020-3698](https://nvd.nist.gov/vuln/detail/CVE-2020-3698), [NVD CVE-2020-11206](https://nvd.nist.gov/vuln/detail/CVE-2020-11206), [qdl](https://github.com/linux-msm/qdl), and [qdlrs](https://github.com/qualcomm/qdlrs).

## Recent boot/CVE candidate filter (2026-09-29)

CVE-2026-21385 is tagged to APQ8098 in third-party/NVD product mappings and Google says it may be under limited targeted exploitation, but the Android bulletin identifies Graphics and the NVD vector is local/low-privilege. It supplies no cold-EDL/PBL entry. CVE-2024-21482 describes a Linux `bootm` secure-boot bypass, but Qualcomm's July 2024 affected list does not name APQ8098/MSM8998 and instead covers router/connectivity families; it is also downstream of PBL. These do not add another target-matched trigger. No Portal traffic was sent.

Sources: [Android March 2026 bulletin](https://source.android.com/docs/security/bulletin/2026/2026-03-01), [Qualcomm July 2024 bulletin](https://docs.qualcomm.com/product/publicresources/securitybulletin/july-2024-bulletin.html), and [CVE-2024-21482 record](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2024-21482).

## Tool expansion and same-silicon lead check (2026-09-29)

Used the callable Consensus scholarly-search connector plus built-in web search and direct GitHub source/issue/profile inspection. Its focused queries returned no paper or reproduction for CVE-2021-30327; the returned results were generic buffer-overflow, modem, and TEE research, and two initial calls were rate-limited. This supersedes the earlier note that Consensus was not connected. No dedicated GitHub connector is available in the active tool list.

Two solid MSM8998 branches beyond Katana remain outside cold EDL: Xperable is a real Sony XBL/ABL fastboot exploit (CVE-2021-1931), and Check Point documents Pixel 2/MSM8998 modem-service research involving CVE-2020-11292 and QMI access from Android. Their execution stages and prerequisites do not fit the Portal's current 9008 state. `qtestsign` supports MSM8998 image-format version 5 only for firmware-secure-boot-disabled setups; it creates no signature bypass.

**Result:** Katana is not the only solid Qualcomm/MSM8998 lead overall; it is the only public runnable code branch found for the exact cold-EDL CVE-2021-30327 path, and its checked-in exploit profile is SDM845-only. No Portal-matched APQ8098 trigger or reproducible success trace emerged. No Portal traffic was sent and no firmware/service image was inspected.

Sources: [Qualcomm CVE-2021-30327 record](https://www.cve.org/CVERecord?id=CVE-2021-30327), [Katana SoC profile](https://github.com/Daniel224455/katana/blob/main/soc_data.py), [Xperable README](https://github.com/j4nn/xperable/blob/master/README.rst), [Check Point research](https://research.checkpoint.com/2021/security-probe-of-qualcomm-msm/), and [qtestsign README](https://github.com/msm8916-mainline/qtestsign).

## Independent disclosure and reference-PBL metadata check (2026-09-29)

The official Hexacon 2023 abstract is another strong public evidence artifact for CVE-2021-30327's vulnerability family: it describes an unbounded-recursion bug in a new Sahara command, memory corruption to PC control and EL3 shellcode, and a root shell on a bootloader-locked Pixel. Katana credits the speakers as the first exploiters of this CVE. This is a separately reported demonstration, not a second public runnable implementation; the abstract does not name the handset generation, SoC/PBL build, or a target profile. Direct inspection of `soc_data.py` confirms Katana's only checked-in execution profile is SDM845.

A public APQ8098-MTP boot log reports chip version 2.1, PBL patch version 2, and secure boot off. This gives a reference example of APQ8098 PBL metadata and varianting, but it is not representative evidence for the fused production Portal. No authoritative relation between that PBL patch number and CVE-2021-30327 applicability was found.

**Result:** Katana is not the only solid lead overall: Qualcomm's CNA affected-product record and the Hexacon researchers' exploit demonstration independently support the CVE-2021-30327 cold-EDL vulnerability family, and Xperable remains a separate MSM8998 XBL/ABL lead. Katana is still the only public runnable implementation found for the exact CVE-2021-30327 Sahara path. Apparent extra exploit-index hits checked here lead back to Katana, not a second PoC. No APQ8098-specific profile or Portal-matched PBL success trace surfaced. No Portal packets were sent.

Sources: [Hexacon 2023 talk abstract](https://2023.hexacon.fr/conference/speakers/), [Katana README](https://github.com/Daniel224455/katana), [Katana SoC data](https://github.com/Daniel224455/katana/blob/main/soc_data.py), [APQ8098-MTP boot log](https://www.spinics.net/lists/linux-mm/msg128766.html), and [Qualcomm CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/30xxx/CVE-2021-30327.json).

## Live GitHub repo and issue search

Expanded with live GitHub repository/issue search and attempted direct code search. The public repo query returns only Katana and Echidna for CVE-2021-30327; Echidna is Katana-derived and currently lists Snapdragon 845 devices. Anonymous GitHub code search requires sign-in; Sourcegraph presented a Cloudflare challenge. A GitHub connector is available in the plugin directory but is not active in this task.

A Logitech G Cloud / SM7125 issue reports failed Sahara overflow attempts, but the repository labels its material AI-generated and supplies no raw trace in the issue; it is not a solid independent result for the Portal. A public Qualcomm BootROM-dump index lists MSM8992, QCS6490, QSD8650, and SDM845, but no MSM8998/APQ8098 dump.

**Answer:** Katana is not the only solid lead overall: Qualcomm's affected-product record and the Hexacon exploit demonstration support the CVE-2021-30327 family, while Xperable is a separate MSM8998 XBL/ABL branch. Katana/Echidna remain the only public runnable cold-EDL branch found for this CVE, and Katana's code profile is SDM845-only. This is a stronger multi-source search, not an exhaustive Internet claim. No Portal traffic was sent.

Sources: [GitHub CVE repository search](https://github.com/search?q=CVE-2021-30327&type=repositories), [GitHub CVE issue search](https://github.com/search?q=CVE-2021-30327&type=issues), [Katana SoC profile](https://github.com/Daniel224455/katana/blob/main/soc_data.py), [Logitech G Cloud issue](https://github.com/HYCQAQ/Logitech-G-Cloud-GhostLock-CVE-2026-43499/issues/1), [Qualcomm BootROM dump listing](https://github.com/Zenofex/SoC-BootROMs/tree/main/qualcomm), [Qualcomm CNA record](https://www.cve.org/CVERecord?id=CVE-2021-30327), [Hexacon talk abstract](https://2023.hexacon.fr/conference/speakers/), and [Xperable](https://github.com/j4nn/xperable).

## GitHub connector and same-OEM Quest lead (2026-09-29)

After the user asked to expand the toolset and approved GitHub, live repository, issue, and code search became available. The CVE-2021-30327 repository results are Katana, four Katana forks, Echidna, and an Echidna fork: one lineage, not independent implementations. Code search found `sakuraedltool-sys/sakuraedl`, which lists MSM8998, but its broad Sahara-v2/v3 version detector and lack of a README, device-specific profile, test log, or successful target trace make it an unverified claim rather than a solid exploit lead.

Same-vendor peer research adds Meta Quest 1 (MSM8998): public Quest unlock tools use CVE-2021-1931 in fastboot/ABL, and the newer QuestStack workflow describes acquiring local root through GhostLock (CVE-2026-43499), staging a vulnerable A/B boot chain, and then using fastboot. GhostLock is a Linux futex/rtmutex local privilege escalation; the chain still requires Android code execution, ADB/root, and build-specific bootloader components. It does not enter from cold EDL and does not prove Portal kernel/ABL applicability. Xperable is another credible MSM8998 path, but it targets Sony XBL/ABL fastboot with Sony-specific setup. OnePlus CVE-2017-5947 only helps enter EDL and does not bypass programmer authentication.

**Result:** Katana is not the only solid lead across all Qualcomm/MSM8998 boot-chain research. It remains the only public runnable software exploit lineage found that starts at cold EDL/Sahara for the exact CVE-2021-30327 family; its checked-in execution profile is SDM845-only. No Portal-matched cold-EDL trigger or PBL/ABL success trace emerged. No Portal packets were sent and no firmware/service image was inspected.

Sources: [GitHub CVE-2021-30327 repository search](https://github.com/search?q=CVE-2021-30327&type=repositories), [SakuraEDL source claiming MSM8998](https://github.com/sakuraedltool-sys/sakuraedl/blob/main/Qualcomm/Exploit/sahara_exploit.cs), [QuestStack](https://github.com/starseed12345/QuestStack), [Quest bootloader unlocker](https://github.com/darknight1050/quest-bootloader-unlocker), [Android July 2021 security bulletin](https://source.android.com/docs/security/bulletin/2021-07-01), [NVD CVE-2021-1931](https://nvd.nist.gov/vuln/detail/cve-2021-1931), [NebuSec GhostLock write-up](https://nebusec.ai/research/ionstack-part-2), [CVE-2026-43499 record](https://security-tracker.debian.org/tracker/CVE-2026-43499), [Xperable](https://github.com/j4nn/xperable), and [Aleph's OnePlus EDL advisory](https://alephsecurity.com/vulns/aleph-2017007).

## Sahara MCP utility audit (2026-09-29)

Live GitHub search found `libertyrights/sahara-mcp`, a Python MCP server created in August 2026. It provides generic Sahara USB operations (enumeration, handshake, chip-info reads, image upload, command-mode client commands, and reset), not an exploit or signature bypass. Upload still requires a supplied programmer.

Reviewed the command and reset helpers. The command path does not verify that the response's client-command ID matches the requested command before sending `EXECUTE_DATA`; the reset path may send up to five reset packets; the upload helper automatically serves requested ranges and acknowledges completed transfers. That behavior is outside the Portal project's strict one-command/no-retry bounds. The server was not installed or run, and no Portal packets were sent.

Sources: [sahara-mcp README](https://github.com/libertyrights/sahara-mcp/blob/main/README.md), [command execution path](https://github.com/libertyrights/sahara-mcp/blob/main/sahara_mcp_server.py#L323-L336), and [upload/reset paths](https://github.com/libertyrights/sahara-mcp/blob/main/sahara_mcp_server.py#L399-L487).

## Expanded source-tool pass: GitHub and Consensus (2026-09-29)

Used the active GitHub connector for repository, code, file, and issue search, plus web search and Consensus scholarly search. Consensus did not return a direct Sahara/CVE-2021-30327 study. Rechecked the already-recorded Katana issue #3 and the checker source; no new run or reproducible baseline has appeared, so that issue remains an unverified adjacent-chip signal, not a second implementation or Portal result.

The Sunmi T2s SDM660 field-study repo records measured EDL behavior: reset `0x13` at 0, 30, 60, and 100 repetitions reportedly had no effect, while its PBL did not request loader code bytes for tested images. This is a useful negative comparator from a different chip and PBL. Its result does not transfer to the Portal's APQ8098.

Conclusion unchanged: several independent research sources support the CVE-2021-30327 vulnerability family, and Xperable is a separate MSM8998 fastboot/XBL/ABL branch. Katana/Echidna remain the only public runnable cold-EDL implementation lineage found for the Sahara CVE; no APQ8098 trigger or Portal-matched success trace surfaced. No Portal packets were sent; no firmware or service image was opened.

Sources: [Katana issue #3](https://github.com/Daniel224455/katana/issues/3), [Katana checker](https://github.com/Daniel224455/katana/blob/main/check_vuln.py), [Sunmi T2s field study](https://github.com/Yuzz1e/sunmi-t2s-research), [Qualcomm CVE-2021-30327 record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2021/30xxx/CVE-2021-30327.json), [Hexacon 2023](https://2023.hexacon.fr/conference/speakers/), and [Qualcomm QPSS22](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/qpss22-christopher-wade.pdf).


## Exact-family Portal Freedom repository review (2026-09-29)

GitHub code search for the Portal's APQ8098 MSM_ID surfaced [`amemefarmer/the-purrtol`](https://github.com/amemefarmer/the-purrtol). The nested [`portal-freedom` project](https://github.com/amemefarmer/the-purrtol/tree/main/portal-freedom) says Portal 10-inch Gen 1 is its target; its first journal records successful EDL/Sahara identity reads. This is a materially closer public comparison than generic MSM8998 phone traces. The repository's top-level narrative, however, describes a separate Portal+ 15.6-inch project, so do not mix its logs or model assumptions without checking the nested source.

The repo also reports a fastboot entry path and CVE-2021-1931 DMA-buffer experiments. Its final project context says the overflow could not reach the lock-state data and could not unlock the device. Journal 013 acknowledges that many apparent hangs were USB Zero Length Packet issues and retracts earlier execution claims; later results remain inconsistent across the notes. The captive-portal browser chain is another stated OS-level avenue, but its kernel privilege-escalation stage is incomplete. These are useful self-published measurements and claims, not a verified takeover, and none is a loaderless EDL trigger.

For the EDL objective, the source adds no second CVE-2021-30327 implementation: its journal calls that PBL vulnerability unexploited and proposes future fuzzing only. Katana/Echidna remain the only public runnable cold-Sahara code lineage found, without an APQ8098 profile. No device traffic was sent.

Sources: [Portal Freedom README](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/README.md), [EDL/Sahara journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/001_edl_sahara_query.md), [USB-ZLP correction and overflow notes](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/013_zlp_discovery_and_real_overflow_search.md), [later DMA/lock-state conclusion](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/018_addr_spray_breakthrough.md), [project context](https://github.com/amemefarmer/the-purrtol/blob/main/docs/context-bundle/purrtol-context.md), and [PBL CVE research note](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/019_cve_research_alternative_paths.md).

## Katana payload-stage audit and APQ8098 Freebox peer (2026-09-29)

Used the active GitHub connector to fetch the Katana PBLDump commit and full source files, then searched CVE/repository/commit/issue records and exact-SoC Freebox sources. Katana's September `PBLDump` addition is post-execution memory collection: it looks for a marker and range in a supplied payload and reads bulk bytes after the existing profile-specific exploitation path. Its payload companion fixes the dump range to 0x300000–0x33c000. The active Katana and Echidna SoC tables each still contain only `sdm845`; no APQ8098/MSM8998 run profile appeared. Thus the new feature does not help produce the missing trigger.

A useful same-chip comparison lead appeared in `aminekun90/freebox-tool`: its current public docs report code execution on a Freebox Player Devialet using the Free-specific SNAPL bootloader's GPIO test mode. That demonstrates a separate path on an APQ8098 board, not Sahara/PBL execution. The project's own EDL roadmap still says a matching Free-signed programmer is required and leaves the `0x13` PBL behavior unverified. A separate Freebox hardware project reports UART test-point candidates but no published EDL result. Do not transfer the SNAPL/GPIO behavior to the Portal.

**Answer to the coverage question:** Katana is not the only solid public research lead overall. Qualcomm's affected-device record, the independent Hexacon presentation, QPSS22, Xperable, and now this same-silicon Freebox work are separate evidence tracks. Katana/Echidna remain the only public runnable cold-EDL CVE-2021-30327 implementation lineage found, and its executable profile is SDM845-only. No Portal-matched trigger surfaced; no Portal traffic was sent, no external researcher was contacted, and no firmware/service image was inspected.

Sources: [Katana PBLDump commit](https://github.com/Daniel224455/katana/commit/c4e77f173fde07933b5696ab11a7ed6cc6100444), [Katana SoC profiles](https://github.com/Daniel224455/katana/blob/main/soc_data.py), [SDM845 payload source](https://github.com/Daniel224455/sdm845-payloads/blob/main/pbldump/pbldump.c), [Freebox APQ8098 test-mode/EDL roadmap](https://github.com/aminekun90/freebox-tool/blob/main/ATTACK-ROADMAP.md), and [Freebox APQ8098 hardware peer report](https://github.com/EricBlanquer/freebox-devialet-hack/issues/1).

## Portal Freedom exact-identity and captive-WebView lead (2026-09-29)

Follow-up review found that the Portal Freedom repository's Sahara record reports the same full HWID and OEM public-key hash as this Portal's 2026-09-26 identity capture: HWID `0x000620e10137b8a1` and PK hash `7291ef5c5d99dc05ee00237a1d71b1f572696870b839bb715fba9e89988b4a3f`. This is a strong same-secure-boot-identity match. Product labeling is inconsistent: the early journal calls the tested device Portal 10-inch Gen 1, while the current root README and the observed captive-portal User-Agent identify it as Portal+ 15.6-inch Gen 1. Treat the shared HWID/hash as evidence about the boot identity, not proof that the 10-inch Portal has the same Android image or browser build.

The repository reports that a controlled captive Wi-Fi setup opened the device's CaptivePortalLogin WebView and observed Chrome `86.0.4240.198` / Android 9. Its later journal claims renderer code execution on that target, and a subsequent milestone reports the WebAssembly stage and test syscalls working. The project did not reach root or enable ADB: its Binder test reports that the kernel UAF was patched, its epoll-UAF journal is marked deployed but awaiting a device test, and its root README says the project was abandoned before completion. These are self-published measurements, not independently reproduced results. Chrome's own release record places the CVE-2020-16040 fix in Chrome 87.0.4280.88, so the reported Chrome 86 version is within the affected range.

This is a promising software-side route around the signed-loader barrier, but it is not an EDL/Sahara trigger and does not yet provide root. The next bounded check is a benign fingerprint of the already demonstrated captive-login WebView on the user's 10-inch Portal: serve a static page that displays the browser User-Agent, distinguishing it from the separate Terms-of-Service browser. Do not serve exploit content or repeat the old intent/toolbar escape attempts. No Portal traffic was sent for this review.

Sources: [Portal Freedom Sahara identity journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/001_edl_sahara_query.md), [captive-portal setup and observed User-Agent](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/020_captive_portal_setup.md), [renderer RCE journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/021_chrome_rce_v8_exploit_iterations.md), [stage-one milestone](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/027_mprotect_jump_confirmed.md), [kernel race test status](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/029_epoll_uaf_v1_race_test.md), [current project status](https://github.com/amemefarmer/the-purrtol/blob/main/README.md), and [Chrome's CVE-2020-16040 fix record](https://chromereleases.googleblog.com/2020/12/stable-channel-update-for-desktop.html).

Prepared a separate [`captive_portal_ua_probe.py`](../scripts/captive_portal_ua_probe.py) and [run note](CAPTIVE_PORTAL_UA_PROBE.md). It serves one static page on a caller-selected hotspot IPv4 address, displays `navigator.userAgent`, and prints request path/User-Agent to the terminal without saving them or changing DNS/PF/Wi-Fi. I did not run the older `captive_portal_server.py`; that script alters PF rules, blocks DNS-over-TLS, and serves additional navigation/diagnostic content. A read-only host check found no active `bridge100`/`bridge101` interface and no listener on TCP port 80, so the probe is not running and cannot yet receive the Portal's connectivity check. No Portal traffic was sent.

The owner's earlier [10-inch unlock record](../PORTAL_10_INCH_UNLOCK_ATTEMPTS.md) already documents a successful captive-login window after intercepting its HTTP probe and blocking DoT. It also documents that intent, toolbar, fullscreen, and settings escape attempts were blocked. That record's Chrome 106 observation is specifically from a Terms-of-Service browser, not the captive-login WebView. The only new live observation needed for this lead is the captive-login WebView's own User-Agent; do not repeat the already-failed escape attempts.

## Controlled captive-WebView fingerprint setup (2026-09-29)

With the owner's confirmation, enabled macOS Internet Sharing from the USB LAN adapter to Wi-Fi. The active hotspot bridge is `bridge100` at `192.168.2.1`; the owner reports that the Portal joined successfully. The owner started the static `captive_portal_ua_probe.py` page on that address and port 80, then stopped it before configuring the redirect; no request had been captured at that point. The first launch attempt found a non-ASCII ellipsis inside the Python bytes literal; changed that placeholder to ASCII and the owner relaunched successfully.

The helper does not redirect traffic. The owner loaded the minimal temporary PF rule from [the run note](CAPTIVE_PORTAL_UA_PROBE.md): redirect TCP port 80 only from `192.168.2.0/24` on `bridge100` to the static page. The `pfctl` output showed no syntax error; the rule does not block DNS-over-TLS or alter other interfaces. After restarting the helper, four `/generate_204` requests were logged: three with an X11/Linux Chrome 60 UA and one with an Android 9 Portal UA containing `wv` and Chrome `106.0.5249.126` (`Build/PKQ1.191202.001`). This proves an HTTP request with that UA reached the page, but the log did not include `Host` or `X-Requested-With`; it does not identify the CaptivePortalLogin Activity or its WebView version. No exploit content was served and no access was gained. Stop the helper with Ctrl-C and flush only the `com.apple/portal_ua_probe` anchor when the check is complete; the hotspot may then be turned off if no longer needed.

## Captive WebView browser-version compatibility check (2026-09-29)

The previous capture recorded Chrome `106.0.5249.126` only on `/generate_204`. This is the network connectivity-check request; without the HTTP `Host` and `X-Requested-With` headers, it does not establish the CaptivePortalLogin WebView version.

The current PurrTol setup journal and its request log contain a more specific observation: `GET /mobile/status.php`, `Host: portal.fb.com`, `X-Requested-With: com.android.captiveportallogin`, and Chrome `86.0.4240.198` / V8 8.6. Its UA uses `Portal+ Build/PKQ1.191202.001`, which matches the owner's observed build tag apart from the product label. This is a strong same-build-family lead, but it is PurrTol's self-reported Portal+ capture; the owner's retail model is Portal 10-inch Gen 1, so the actual login WebView still needs a direct capture.

This means the prior Chrome-version mismatch conclusion was premature. If the owner's CaptivePortalLogin request reports Chrome 86, PurrTol's renderer route becomes a close version/build match: CVE-2020-16040 was fixed in Chrome 87 and CVE-2021-30632 in Chrome 93. If that request instead reports Chrome 106, CVE-2022-3723 remains a possible compatibility lead, but Project Zero lists the exploit sample as unavailable and its public reproduction uses internal V8 test flags, not a browser-ready page. Neither UA establishes renderer compromise or a sandbox escape.

Next step: capture the actual login request path, `Host`, `X-Requested-With`, and User-Agent; `/mobile/status.php` plus `X-Requested-With: com.android.captiveportallogin` distinguishes the login WebView from `/generate_204`. The updated compatibility helper logs those request fields and accepts both `Portal` and `Portal+` spellings of the known build token. No exploit code or vulnerability trigger has been served; no access, renderer control, or sandbox escape has been demonstrated.

Sources: [PurrTol CaptivePortalLogin setup journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/020_captive_portal_setup.md), [PurrTol captured captive-portal requests](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/logs/requests_2026-03-03.jsonl), [Chrome 87 CVE-2020-16040 fix](https://chromereleases.googleblog.com/2020/12/stable-channel-update-for-desktop.html), [Chrome 93 CVE-2021-30632 fix](https://chromereleases.googleblog.com/2021/09/stable-channel-update-for-desktop.html), and [Project Zero CVE-2022-3723 analysis](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-3723.html).

## PurrTol captive-WebView compatibility follow-up (2026-09-29)

Read the PurrTol source journals and request log directly. Its author reports renderer RCE and a successful `getpid` syscall on Chrome 86.0.4240.198 / V8 8.6 / 32-bit ARM WebView, then reports a WebAssembly `mprotect`-and-jump stage. The PurrTol request log shows that its Chrome 86 UA came from `/mobile/status.php` with `X-Requested-With: com.android.captiveportallogin`; the owner's Chrome 106 observation came from `/generate_204`, so the actual login-WebView version has not been compared yet. The same project says its Binder UAF attempt returned `writev=31` and did not corrupt, while its CVE-2021-1048 epoll race test is marked deployed and awaiting a device test; that entry explicitly says its race-test version does not implement kernel escalation. These are self-reported results, not independently reproduced. The PurrTol first stage may match closely if the owner's actual CaptivePortalLogin UA is Chrome 86; the kernel/root stage remains unproven.

Created [`captive_portal_compat_probe.py`](../scripts/captive_portal_compat_probe.py) and [run instructions](CAPTIVE_PORTAL_COMPAT_PROBE.md). The page is served only to a User-Agent containing the observed Portal build token, runs a tiny ordinary Wasm function and bounded Wasm memory-grow check, and reads WebGL renderer strings when exposed. It posts a small allowlisted JSON report to the local server, which prints it to stdout without saving it. The helper performs no exploit, navigation, remote fetch, or network configuration changes. It has been prepared but not run; no result is claimed yet.

The next live observation is the actual CaptivePortalLogin request plus the returned WebAssembly/WebGL report. Even a full pass confirms browser features and the exposed graphics renderer only; it does not prove CVE-2020-16040 compatibility, renderer compromise, KGSL vulnerability, sandbox escape, or root. Sources: [PurrTol captured captive-portal requests](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/logs/requests_2026-03-03.jsonl), [PurrTol renderer-RCE journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/021_chrome_rce_v8_exploit_iterations.md), [PurrTol Wasm-stage journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/027_mprotect_jump_confirmed.md), and [PurrTol epoll-race test status](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/029_epoll_uaf_v1_race_test.md).

## Current PurrTol tree and same-chipset kernel-stage review (2026-09-29)

Rechecked the current public tree rather than relying on journal titles. The `portal-freedom/README.md` currently presents the project as an ABL/CVE-2021-1931 effort whose stated remaining blocker is the missing ABL binary. The captive-WebView subtree contains one named renderer page, `rce_chrome86.html`; the associated journal says its exploit depends on Chrome 86 / V8 8.6 heap layout and can break when code structure changes. This is evidence that PurrTol has a target-specific experiment, not a portable Chrome 106 exploit. The repository's ABL README and the browser journals describe different branches of work, so they should not be collapsed into one completed chain.

There is a relevant, separate post-renderer lead on the Portal's exact SoC: NVD's CVE-2019-10567 affected-product list includes APQ8098. Project Zero's follow-up explains that the original patch was incomplete and documents CVE-2020-11179 as the root-cause fix; its Adrenaline demonstration achieved kernel PC control on a Pixel 3a / SDM670 with kernel 4.9.200. That establishes a Qualcomm Adreno attack-surface lead, not Portal applicability. The Portal's KGSL driver revision, GPU firmware revision, and whether the follow-up fix was integrated are unknown, and a normal WebGL renderer string cannot answer those questions. This path also still needs a browser-to-driver trigger that works from the Portal's captive WebView.

Current assessment: the PurrTol renderer primitive may be a close match, because PurrTol's actual login-WebView capture is Chrome 86 on the same build tag; the user's Chrome 106 observation was from `/generate_204`, not a verified CaptivePortalLogin request. The public CVE-2022-3723 reproduction remains only an alternate path if the actual login WebView is 106. The immediate live step is to capture the login request path and `X-Requested-With` with the updated harmless page. No exploit payload was served and no code-execution or privilege-escalation attempt was made.

Sources: [PurrTol current Portal Freedom README](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/README.md), [NVD CVE-2019-10567 product list](https://nvd.nist.gov/vuln/detail/CVE-2019-10567), [Project Zero Adreno research and CVE-2020-11179 fix history](https://projectzero.google/2020/09/attacking-qualcomm-adreno-gpu.html), and [Project Zero CVE-2022-3723 analysis](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-3723.html).

After confirming `bridge100` is still `192.168.2.1` and port 80 has no listener, attempted to start the compatibility server from the Codex shell. The sandbox denied `sudo`, and the direct non-root bind failed with `PermissionError`; the command exited and no listener started. No Portal request was served. The owner must launch the helper from their Terminal with `sudo` as described in the run note. The returned `navigator.platform` string is not enough to prove process bitness; PurrTol's journal reports a 32-bit ARM WebView, while the Portal's CaptivePortalLogin ABI remains unknown.

## Chrome 106 public-PoC search (2026-09-29)

Checked a public GitHub result for CVE-2022-3723 after Project Zero's report indicated that the issue's affected range includes Chrome 106. The third-party `numencyber/Vulnerability_PoC` folder says it is based on Google's public reproduction, but its HTML uses V8 shell-only optimization intrinsics and has unresolved placeholders; the same folder's Go/Wasm demo contains a separate native payload path. It is not a verified browser-ready WebView exploit and is not a Portal PoC. Project Zero itself marks the exploit sample unavailable and shows a reproduction that requires internal V8 flags. No candidate exploit page was served. The latest host check still shows `bridge100` at `192.168.2.1` with no listener on port 80; the compatibility probe remains unrun because the Codex shell cannot bind that privileged port.

Sources: [Project Zero CVE-2022-3723 analysis and reproduction](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-3723.html), [third-party CVE-2022-3723 folder](https://github.com/numencyber/Vulnerability_PoC/tree/main/CVE-2022-3723).

## PurrTol first-stage artifact audit (2026-09-29)

The later PurrTol evidence strengthens the Chrome 86 path and corrects its earlier exploit-selection table. The setup journal initially selected CVE-2021-30632 for Chrome 86, but the PurrTol device report records that this type-confusion attempt failed on V8 8.6. Its later v11b report records the CVE-2020-16040 path reaching a `getpid` result from the renderer. Treat this as the project's self-reported bounded renderer-RCE result; its report places the process in Android's isolated-app UID, not root.

The current `rce_chrome86.html` is not the minimal v11b artifact: it includes an `mprotect` stager followed by the CVE-2021-1048 epoll-UAF v1 race payload, which does not implement kernel escalation. The earlier minimal one-syscall source is described in journal 021 but is not preserved as a separate public artifact. Do not serve the unmodified page as a renderer-only proof. The following entry records a transformed, one-shot adapter that replaces its in-memory payload before serving.

Sources: [PurrTol CVE-2021-30632 failure and later renderer reports](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/logs/device_reports.jsonl), [PurrTol v11b RCE journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/021_chrome_rce_v8_exploit_iterations.md), [current renderer/race page](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/www/exploit/rce_chrome86.html), and [PurrTol kernel race status](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/029_epoll_uaf_v1_race_test.md).

## Bounded PurrTol renderer proof prepared (2026-09-29)

Checked the retained page's public history, branches, tags, and releases. The
public repo exposes one `main` branch, no tags/releases, and one file-history
commit for `rce_chrome86.html`; the separate minimal v11b artifact is not
recoverable from those refs. Prepared
[`captive_portal_purrtol_stage1_getpid.py`](../scripts/captive_portal_purrtol_stage1_getpid.py)
to fetch that page from its pinned commit, verify its Git blob hash, replace all
254 embedded ARM32 payload words with a `getpid` routine and NOP fill, and serve
it once only to the expected `portal.fb.com/mobile/status.php` request carrying
`X-Requested-With: com.android.captiveportallogin` and the matching Android 9,
Chrome 86.0.4240.198, and Portal build tokens. A retry/reload request is denied;
other traffic receives only a static captive hint or harmless mismatch page.

The payload and the original page's bounded result decoder use a fixed marker
and return the PID as `PID_FROM_RENDER`. The retained page also uses its
existing `mprotect` stager to execute bytes from its own WebAssembly mapping.
The transformed target payload makes no storage, process-launch, persistence,
or kernel-race call. Offline checks against the pinned GitHub source passed for
the blob hash, all 254 rewritten words, result slot, UA gate, and result decode.
This remains only a renderer proof, not root or ADB. The helper has not been
started on the host or served to the device, and the Portal's actual
CaptivePortalLogin headers remain unconfirmed. A different V8 build, ABI, or
heap layout could still crash the login WebView.

Assembled [`purrtol_stage1_getpid.S`](purrtol_stage1_getpid.S) for ARMv7-A and integrated its machine words into [`captive_portal_purrtol_stage1_getpid.py`](../scripts/captive_portal_purrtol_stage1_getpid.py). An offline adapter check passed. The helper has not been started on the host or served to the Portal; the target CaptivePortalLogin UA/ABI and successful renderer result remain unverified.

## PurrTol kernel-stage completion audit (2026-09-29)

The public PurrTol materials do not provide a completed root payload to attach
after the renderer proof. Journal 029 explicitly calls its CVE-2021-1048
payload a race test that does not implement kernel escalation and says it is
awaiting device testing. Its next steps describe future fake-epitem shaping,
kernel read/write, and credential modification. The `stage2_kernel.c` file is
instead an older CVE-2019-2215 Binder attempt, while later PurrTol notes say
that Binder CVE was patched. The context bundle labels CVE-2021-1048
"research complete, code incomplete" and describes CVE-2021-0920 only as a
backup unpatched candidate. These are self-reported research notes, not a
verified path to root on this Portal. The renderer proof is still useful
progress, but the requested device access remains unachieved.

The host currently has `bridge100` at `192.168.2.1`; the Codex terminal shows
the prior `com.apple/portal_ua_probe` PF anchor was flushed, and a read-only
listener check found no process on TCP port 80. Attempted to restore the
previously authorized redirect and start the helper with non-interactive sudo;
the command stopped at `sudo: a password is required`, before PF or listener
state changed. The owner must enter their local sudo password in Terminal to
reapply the redirect and start the gated helper. No Portal request or exploit
page was served.

Sources: [PurrTol kernel race journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/029_epoll_uaf_v1_race_test.md), [PurrTol kernel payload](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/payloads/stage2_kernel.c), [PurrTol context bundle](https://github.com/amemefarmer/the-purrtol/blob/main/docs/context-bundle/purrtol-context.md), and [CVE-2021-1048 design status](https://github.com/amemefarmer/the-purrtol/blob/main/docs/llms-full.txt).

Follow-up: corrected the helper's response CSP so Chrome 86's `WebAssembly.Module`
is permitted via `script-src 'unsafe-eval'`; the W3C CSP specification gates
WebAssembly compilation on `unsafe-eval` or `wasm-unsafe-eval`. The AOSP
November 2021 bulletin classifies both CVE-2021-0920 and CVE-2021-1048 as
kernel local privilege-escalation issues, but that does not prove the user's
Portal lacks vendor backports. Attempted a current-host launch using
non-interactive sudo; it stopped before PF changes because a local macOS
password is required. CUA also refused to control Terminal for safety reasons.
The latest read-only checks still show `bridge100=192.168.2.1` active and no
TCP/80 listener. No Portal traffic was sent.

Sources: [W3C Content Security Policy](https://www.w3.org/TR/CSP/), [Android Security Bulletin—November 2021](https://source.android.com/docs/security/bulletin/2021-11-01).

## Captive WebView version gate follow-up (2026-09-29)

Rechecked the live setup before resuming. `bridge100` is active at
`192.168.2.1`, and no process is listening on TCP port 80. The prior app
terminal shows the static UA helper stopped and the Portal redirect anchor
flushed. An interactive local `sudo -v` prompt is now open for owner
authentication; no redirect rule or server has been started in this step.

Corrected the immediate probe order: the observed Portal Chrome 106 User-Agent
was from `/generate_204`, which identifies the Android connectivity check, not
the captive-login WebView. Run the existing benign
[`captive_portal_compat_probe.py`](../scripts/captive_portal_compat_probe.py)
first, then use its `portal_page_request` evidence to check for
`/mobile/status.php` and `X-Requested-With=com.android.captiveportallogin` and
its report to identify that WebView's actual version/capabilities. The
PurrTol-derived one-shot renderer helper only serves its page to the specific
Chrome 86.0.4240.198 UA/build match; until the login-WebView request is
observed, serving that helper would be premature. No renderer exploit page or
new request was sent to the Portal. This supersedes the immediately preceding
suggestion to start the PurrTol helper directly.

## Same-generation kernel-stage comparison: Quest 1 and GhostLock (2026-09-29)

Expanded the PurrTol follow-up to the original Meta Quest, another Snapdragon
835 device. Meta's developer documentation identifies Snapdragon 835 in the
original Quest, and Qualcomm documents APQ8098/MSM8998 as the associated
Snapdragon 800-series platform. This makes the Quest root work a same-generation
kernel/SoC comparison, not evidence that its device-specific exploit is
portable to Portal.

The current Quest 1 unlocker documents a real chain using IonStack for
Android-side temporary root, then a build-specific vulnerable ABL and
CVE-2021-1931 fastboot handling. Its published workflow gates on the Quest
model/build and requires an authorized ADB shell; it modifies the inactive
boot-chain slot, uses fastboot, and can factory-reset the device. It does not
provide a no-ADB Portal entry path. The root binary could be a reference for a
separate kernel stage only after matching Portal kernel version, architecture,
configuration, and mitigation state.

A newer candidate is GhostLock, CVE-2026-43499, the futex PI/rtmutex waiter
use-after-free published by NebuSec. Its analysis gives an upstream affected
range of Linux 2.6.39-rc1 through 7.1-rc1 absent the fix and requires
`CONFIG_FUTEX_PI=y`; actual Android vendor backports and Portal applicability
remain unknown. The public exploit chain is kernel/build/layout-specific and
includes a staged kernel-write/privilege transition. It is a potential
replacement/reference for PurrTol's incomplete CVE-2021-1048 race stage, not a
ready Portal payload. Do not infer vulnerability from the Android version or
SoC alone. No crash-oriented detector was run; the published third-party
Android detector warns that its D-state test can leave a process stuck.

Useful path if the captive renderer check succeeds: identify the Portal
kernel/build and whether PI-futex syscalls are permitted to the isolated
WebView process, then select a read-only or bounded non-crashing compatibility
check before adapting any kernel stage. Current live state remains unchanged:
`bridge100=192.168.2.1`, TCP/80 has no listener, and the local sudo prompt is
still waiting. No Portal code-execution or kernel attempt was made.

Sources: [Meta Quest chipset documentation](https://developers.meta.com/horizon/documentation/unity/po-advanced-gpu-pipelines/), [Qualcomm APQ8098/MSM8998 product page](https://www.qualcomm.com/processors/application-processors/products/apq8098), [Quest 1 WebUSB unlocker workflow](https://github.com/darknight1050/quest1-bootloader-unlocker-web), [QuestStack root/ABL workflow](https://github.com/starseed12345/QuestStack), [NebuSec GhostLock technical report](https://nebusec.ai/research/ionstack-part-2/), and [Android GhostLock detector warning and kernel-version references](https://github.com/CakesTwix/Android-CVE-2026-43499).

## GhostLock Android compatibility detail (2026-09-29)

NebuSec's Android 17 report gives a useful, testable distinction for the
Portal's reported Android 9 captive environment: it says Android apps before
SDK 29 could open `/dev/ashmem` directly, while SDK 29+ targets lost that path
and the report later used a per-boot ashmem node. This makes ashmem reachability
worth measuring in a renderer-stage diagnostic if the Portal's actual login
WebView and process permit the operation. The Portal's Android version in the
User-Agent does not reveal the CaptivePortalLogin app's target SDK, SELinux
label, seccomp filter, or device-node access, so this is only a hypothesis.

The Android 17 implementation is not portable by chipset alone: the report's
ARM path relies on kernel-specific stack-frame reuse, KASLR disclosure, kernel
structure layout, and a matching-function ashmem/configfs read-write stage.
The Quest 1 IonStack binary and the PurrTol Chrome86 native stager therefore
remain distinct pieces with different target assumptions. A later bounded
read-only renderer probe could collect `uname` and an `open()` result for
`/dev/ashmem`; do this only after confirming the captive-login request and
starting the controlled helper. No such syscall probe or kernel exploit has
been sent to the Portal.

Source: [NebuSec IonStack part III—Android ashmem and ARM adaptation](https://nebusec.ai/research/ionstack-part-3/).

## Hotspot reachability recheck (2026-09-29)

Current `arp -a` lists a client at `192.168.2.3` on `bridge100` (MAC
`a4:0e:2b:12:7e:d6`), but the address has not been independently identified as
the Portal. A single local ICMP echo attempt produced no reply; this is
inconclusive because the device may not answer ping. The first attempt was
blocked by the shell sandbox; the one permitted host-level attempt transmitted
one packet and received none. No port scan or HTTP request was made. TCP/80
still has no listener, and the `sudo -v` prompt remains live without
authentication.

## One-command compatibility-probe runner prepared (2026-09-29)

Added [`run_portal_compat_probe.sh`](../scripts/run_portal_compat_probe.sh) and
updated [`CAPTIVE_PORTAL_COMPAT_PROBE.md`](CAPTIVE_PORTAL_COMPAT_PROBE.md). The
runner is invoked with `sudo`; it verifies the bridge IP, free TCP/80, enabled
PF, and an empty dedicated anchor before loading the narrow redirect. It serves
the existing benign compatibility page and flushes only that dedicated anchor
on exit. It was reviewed from source but not executed; the live macOS sudo
prompt remains unauthenticated. No Portal request or page was sent.

## Local authentication prompt closed; compatibility runner awaits owner (2026-09-29)

The Codex app terminal bridge failed again, so the unused interactive `sudo -v`
process was interrupted. It exited with `sudo: a password is required`; this
prompt performed no PF or server operation. The single-command compatibility
runner is ready for the owner to invoke from regular macOS Terminal. It has not
been executed, no redirect is active from this turn, and no Portal page was
served.

## Probe HTTP privilege drop added (2026-09-29)

Added a shared `portal_probe_runtime.py` helper. Both the benign compatibility
probe and the PurrTol getpid probe now bind their configured address/port first,
then drop UID/GID and supplementary groups to the non-root account identified
by `SUDO_UID`, `SUDO_GID`, and `SUDO_USER` before handling requests. If invoked
as root without a valid sudo user identity, they refuse to serve. Updated the
run notes and wrapper output accordingly. This is a source-level review only;
no syntax check, test, PF operation, server start, or Portal request was run.
The `sudo -v` prompt is closed and TCP/80 was last observed without a listener.

## Portal kernel source lead — GhostLock cross-check (2026-09-29)

Meta's public [`facebookincubator/Portal-Kernel`](https://github.com/facebookincubator/Portal-Kernel)
repository describes itself as “Kernel Code for Portal.” Its root Makefile
identifies the source baseline as Linux 4.4.78. This is a closer Portal source
lead for GhostLock than the earlier same-SoC comparisons, but the published
root page does not establish that the 10-inch retail unit shipped this exact
tree. The repository page currently reports only five commits, and this
research pass did not obtain the Portal `remove_waiter()` implementation or a
matching defconfig. The runtime kernel release and `CONFIG_FUTEX_PI` therefore
remain unknown.

The upstream GhostLock fix is commit
[`3bfdc63936dd`](https://github.com/torvalds/linux/commit/3bfdc63936dd),
“Use waiter::task instead of current in remove_waiter().” That gives us a
precise source-level comparison to make in the Portal tree: determine whether
proxy-lock cleanup operates on `waiter->task` or `current`, then determine
whether futex PI is enabled in the shipped build. The Portal repository's
4.4.78 version alone does not prove either point or establish an exploitable
privilege transition.

PurrTol's root README describes a test on a Portal+ 15.6-inch first-generation
unit and claims Chrome 86; this target is the Portal 10-inch first generation.
The device's previously captured Chrome 106 string was for `/generate_204`,
not the captive login page, so it neither confirms nor rules out PurrTol
compatibility. The benign captive-WebView probe remains the next device check:
capture the `/mobile/status.php` request's path, request header, full User-Agent,
and basic WASM result. Only then can we choose a renderer payload for this
model/build. The compatibility runner was not started and no new Portal request
was made during this research pass.

Sources: [Meta Portal-Kernel repository](https://github.com/facebookincubator/Portal-Kernel),
[Portal-Kernel Makefile](https://github.com/facebookincubator/Portal-Kernel/blob/master/Makefile),
[upstream GhostLock fix](https://github.com/torvalds/linux/commit/3bfdc63936dd),
and [PurrTol project README](https://github.com/amemefarmer/the-purrtol).

## PurrTol stage runner prepared (2026-09-29)

Added `scripts/run_portal_purrtol_stage1.sh` and documented it in
`research/PURRTOL_STAGE1_GETPID.md`. It applies the same bridge, port, PF,
and empty-anchor preflight as the benign compatibility runner, adds a local
HTTP redirect only in the dedicated anchor, then launches the one-shot PurrTol
getpid helper. The helper itself requires the exact Chrome 86
`CaptivePortalLogin` request and sends no kernel-escalation payload; Ctrl-C
cleans only the dedicated anchor. This runner must only be used after the
compatibility output confirms the expected login request and browser build.
The script was reviewed from source only; it was not syntax-tested or run, and
no redirect or Portal request was made.

## PurrTol kernel-stage applicability check (2026-09-29)

The upstream CVE record sharpens the PurrTol kernel question. Google Project
Zero identifies CVE-2021-1048 as the `ep_loop_check_proc()` refcount/UAF bug,
introduced by commit `a9ed4a6560b8` and fixed by `77f4689de17c`. Project Zero
lists upstream Linux 4.4.234–4.4.235 as affected and 4.4.236 as fixed; it also
explains that Android vendors could retain the buggy commit after the December
2020 bulletin while missing the November 2021 repair.

The public Meta `Portal-Kernel` tree's top-level Makefile identifies a 4.4.78
baseline. If that baseline accurately represents the retail 10-inch unit and
the buggy change was not vendor-backported, CVE-2021-1048 would not be the
right kernel lead. The public baseline alone cannot establish the shipping
kernel branch or downstream backports, so treat applicability as unknown
until a non-firmware source or an authorized live system interface establishes
the exact kernel release and relevant implementation.

A direct GitHub-connector read of the public tree's `fs/eventpoll.c` narrows
this further: its `ep_loop_check_proc()` adds non-epoll files to
`tfile_check_list` without the `get_file()` calls introduced by
`a9ed4a6560b8`. The CVE's bad refcount operation therefore is absent from the
published Portal source. PurrTol's race stress test may be probing a different
epoll lifetime issue on this older code; its journal marks that test “awaiting
device test” and expects its v1 result to leave UID unchanged. Do not label
that race as CVE-2021-1048 or as a root primitive on the Portal without a
matching vulnerable implementation and a measured result.

PurrTol's public README makes stronger claims about two kernel CVEs and
validated primitives, while its published epoll-race journal and source
describe the CVE-2021-1048 payload as a race diagnostic and say that it does
not implement kernel escalation. Its own root README says the project stopped
before root/ADB. Those statements are self-reported and internally uneven;
they do not establish a complete Portal 10-inch privilege-escalation chain.

The PurrTol assembly header identifies its race-test target as Portal 10-inch
Gen 1 / APQ8098, Android 9, kernel 4.4.153, patch level 2019-08-01. That is a
closer model match than the README's Portal+ label, but remains the author's
report about their unit. The backup CVE-2021-0920 is a better fit for the old
public kernel source: Project Zero describes the `MSG_PEEK`/Unix-socket-GC UAF
and the Android fix commit `cbcf01128d0a` adds a `unix_gc_lock` barrier when
duplicating file descriptors from a peeked message. The public Portal
`net/unix/af_unix.c` still duplicates those descriptors directly with
`scm_fp_dup()` in the `MSG_PEEK` paths and has no such barrier. This makes
CVE-2021-0920 a plausible source-level candidate for the old branch; the
shipping 10-inch image, downstream patches, and a working escalation remain
unverified. PurrTol's context claims this backup was unpatched in its binary,
but the published repository contains no completed exploit for it.

The project's final journal gives a clearer status, and exposes inconsistent
summaries: it marks CVE-2021-1048 blocked by a backport, CVE-2021-0920 not
patched, and kernel privilege escalation not done. Project Zero's published
CVE-2021-0920 reproducer is compiled for AArch64, while PurrTol's renderer
payload is ARM32. That reproducer is root-cause evidence, not a drop-in
renderer payload or completed root PoC. CVE-2021-0920 remains the strongest
source-supported kernel candidate, with a missing 32-bit userspace port and
an unverified runtime match on this Portal.

The next bounded device observation remains the captive-login request, not the
separate `/generate_204` connectivity request: record the `/mobile/status.php`
User-Agent and `X-Requested-With` value using the benign compatibility probe.
The previous Chrome 106 observation belongs only to `/generate_204` and does
not identify CaptivePortalLogin's WebView. The runner is prepared but has not
been activated from this host because local sudo authorization was unavailable;
no new redirect, HTTP server, or Portal request was created in this check.

Sources: [Google Project Zero CVE-2021-1048 analysis](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-1048.html), [Google Project Zero CVE-2021-0920 analysis and AArch64 reproducer](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-0920.html), [Android's CVE-2021-0920 fix](https://android.googlesource.com/kernel/common/+/cbcf01128d0a92e131bd09f1688fe032480b65ca), [Meta Portal-Kernel Makefile](https://github.com/facebookincubator/Portal-Kernel/blob/master/Makefile), [Portal `af_unix.c`](https://github.com/facebookincubator/Portal-Kernel/blob/master/net/unix/af_unix.c), [PurrTol race-test header](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/payloads/epoll_uaf.s), [PurrTol final journal](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/journal/030_claude_refusal_and_cost_analysis.md), and [PurrTol project summary](https://github.com/amemefarmer/the-purrtol/blob/main/docs/llms.txt).

Updated the benign compatibility runner so it can reuse the exact single HTTP
redirect previously installed in its dedicated anchor. It leaves a pre-existing
matching rule untouched on exit, loads and removes the rule only when the anchor
was empty, and refuses filter rules or different/additional NAT rules. Updated
the run note to match. A fresh unprivileged host check found `bridge100` active
at `192.168.2.1` and no listener on TCP/80; macOS denied read-only PF inspection
without local authorization. No PF changes or Portal requests were made. The
runner was not executed or tested because the local sudo prompt could not be
authorized through this session.

Adjusted the same runner's existing-rule comparison to normalize the `http`
service-name spellings that macOS `pfctl` may use for port 80. This lets it
reuse only the exact redirect previously installed for the Portal probe while
preserving the anchor's other rules checks. Source-reviewed only; the runner
remains unexecuted pending local sudo authorization.

Aligned `run_portal_purrtol_stage1.sh` with the compatibility runner's exact-rule
reuse behavior and updated its run note. This removes the existing-anchor
collision between the benign fingerprint phase and the gated renderer-only
proof. The stage remains gated on a matching Chrome 86 CaptivePortalLogin
request; neither runner was executed, and no page was served.

## CVE-2021-0920 reproducer portability audit (2026-09-29)

Read the Project Zero appendix directly before treating it as a Portal kernel
stage. It is an AArch64 reproducer for the Unix-domain-socket GC race, while
PurrTol's reported captive WebView and payload ABI are 32-bit ARM. Project Zero
labels the exploit sample unavailable; the appendix demonstrates a race
trigger but does not include the described kernel read/write primitive or a
credential transition. Its sample also runs 20 trigger cycles and requests
negative nice values (`-19`/`-18`) plus fixed CPU affinities. Raising priority
requires `CAP_SYS_NICE` or a suitable `RLIMIT_NICE`, and CPU affinity is limited
by the thread's permitted cpuset. Neither condition is established for the
Portal's isolated renderer. Copying or merely recompiling this sample would
therefore be both architecture-incompatible with the reported WebView and an
unbounded crash-risk test, not a root PoC.

A local read-only toolchain check found `/usr/bin/clang`, but no Android NDK in
the usual per-user SDK or Homebrew locations and no `arm-linux-androideabi-gcc`
or `qemu-arm` on `PATH`. No compilation or test was run. This confirms that an
ARM32 kernel-stage port cannot be built with an already-installed Android
toolchain in this workspace.

The evidence changes the next technical step: first capture the real captive
login request and run the existing PurrTol renderer-only `getpid` proof if its
Chrome 86 gate matches. Then add a separate bounded renderer environment report
for ABI, UID, and `uname` before deciding whether a kernel trigger can run in
that sandbox. Do not launch the Project Zero 20-cycle trigger as-is, and do not
claim that its appendix supplies root escalation.

Sources: [Project Zero CVE-2021-0920 analysis and reproducer](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-0920.html), [Linux `setpriority(2)` manual](https://man7.org/linux/man-pages/man2/setpriority.2.html), and [Linux `sched_setaffinity(2)` manual](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html).

## PurrTol repository artifact and target audit (2026-09-29)

The GitHub connector's current commit listing still ends at `9c9022d` (March
14, 2026); there is no later technical implementation commit. The repository's
own latest context files identify the tested unit as a Portal+ 15.6-inch Gen 1,
while the `epoll_uaf.s` header alone says Portal 10-inch Gen 1. The owner has a
Portal 10-inch Gen 1, so the public code's target provenance is mixed and its
self-reported offsets or syscall results cannot be treated as this unit's
measurements.

Inspection of `epoll_uaf.s` resolves another discrepancy: it calls itself v1.1
“race test,” says escalation is not implemented, and explicitly sets
`msg_control = NULL`; the 128-byte spray is ordinary iovec data. Its comments
defer valid `SCM_RIGHTS` spraying to a future v2. The context bundle's later
`addr_limit`/pipe/credential plan is therefore design text, not behavior present
in the checked-in payload. The repository does contain `recon_procfs.s`, but
that is a separate reconnaissance payload reading several procfs paths and
probing `/dev/binder`; no page integration or result on the owner's Portal is
present here.

The GitHub code search returned the Project Zero analysis and documentation
mirrors, but no independent public CVE-2021-0920 kernel-escalation
implementation. This closes the “find a ready backup exploit” branch for now.
The immediate path remains the owner-device CaptivePortalLogin fingerprint,
followed by the already-prepared renderer proof; only after a positive renderer
result should a narrowed UID/kernel-version reconnaissance payload be adapted.

Sources: [PurrTol repository history](https://github.com/amemefarmer/the-purrtol/commits/main/), [PurrTol current context bundle](https://github.com/amemefarmer/the-purrtol/blob/main/docs/context-bundle/purrtol-context.md), [PurrTol epoll payload](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/payloads/epoll_uaf.s), and [PurrTol recon payload](https://github.com/amemefarmer/the-purrtol/blob/main/portal-freedom/captive-portal/payloads/recon_procfs.s).

## Bounded PurrTol environment profile prepared (2026-09-29)

Added [`purrtol_stage1_envprobe.S`](purrtol_stage1_envprobe.S) and an optional
`env` profile to the one-shot PurrTol helper. It records only the renderer's
PID and UID and reads up to 255 bytes from `/proc/version`; it does not read
`/proc/self/maps`, device nodes, or kernel pointer controls. The default
`getpid` profile is unchanged. The `env` profile requires the explicit
`--confirm-prior-getpid` gate and reports values to stdout without saving them.

The ARM32 source assembled to 216 bytes (54 words) with the host's Clang; those
words are embedded into the existing 254-word page layout. This was a build
step only: no tests, helper launch, PF modification, or Portal request were
made. The runner's previous `sudo` process was canceled at the password prompt
because the Codex app terminal snapshot did not expose that prompt; it exited
before privilege or network state changed. Use the existing benign compatibility
runner from the owner's regular Mac Terminal to capture the actual captive
login request. The PurrTol renderer stage remains gated on that result.

Fresh host check after that attempt: `bridge100` still owns `192.168.2.1`,
TCP/80 has no listener, and ARP for the previously observed Portal address
`192.168.2.3` is incomplete. Process-table inspection was denied by the shell
sandbox. No compatibility server or Portal request is confirmed active.

## Captive WebView path distinction and Chrome 106 alternatives (2026-09-29)

Corrected the version interpretation against the run record: the owner's
`Chrome/106.0.5249.126` observation came from `/generate_204`, the connectivity
check, with no `Host` or `X-Requested-With` evidence identifying
`CaptivePortalLogin`. It does not show the version of the login WebView and
does not invalidate the prepared Chrome 86 PurrTol gate.

PurrTol's own setup journal and request log report
`GET /mobile/status.php`, `Host: portal.fb.com`,
`X-Requested-With: com.android.captiveportallogin`, Chrome 86.0.4240.198, and
the same Android 9 build token. That capture is from a Portal+ 15.6-inch unit,
while the owner has a 10-inch Gen 1. It is a strong lead, but a direct capture
from the owner's actual login WebView remains the next live check.

If that WebView reports Chrome 106, CVE-2022-3723 (upstream affected through
107.0.5304.62) and CVE-2022-4262 (upstream affected through 108.0.5359.71) are
version-family candidates, subject to any OEM backport. Their public root-cause
reproducers need V8-only intrinsics or heavy GC/allocation behavior and are not
ready WebView exploit pages. Google TAG's reported Android chain for
CVE-2022-3723 targeted Chrome versions before 106 and also depended on GPU and
Mali-driver issues, so it does not establish a transferable chain for this
Portal. The target process ABI and effective V8 build remain unconfirmed. See
[`CHROME106_V8_CANDIDATES.md`](CHROME106_V8_CANDIDATES.md) for sources and
porting gaps.

No helper was launched, no PF or network state changed, and no request was
sent to the Portal during this assessment. The next live operation is the
benign compatibility probe on the owner's `CaptivePortalLogin`, capturing the
path, Host, `X-Requested-With`, and browser version. Do not select the renderer
branch from the `/generate_204` UA alone.

Hardened the prepared PurrTol report path: it now accepts reports only from
the source IP and exact User-Agent that received the one-shot page. The env
profile reports success only after a nonempty `/proc/version` read with zero
syscall status, preventing an empty read from being counted as a pass. Source
review only; no tests or device requests were run.

## Captive compatibility probe route gate (2026-09-29)

Corrected the local compatibility helper to distinguish Android's
connectivity check from its login WebView. A `/generate_204` request without
the Portal build token and
`X-Requested-With: com.android.captiveportallogin` receives only a static HTTP
200 captive hint. A matching confirmed login-WebView request receives the
benign feature page at most once; the log reports whether its path appears in
PurrTol's route set. This supports the Android 9 AOSP behavior where
CaptivePortalLogin initially loads `/generate_204` and only a 204 dismisses
the captive UI. A report is accepted once only from the same source IP and
exact User-Agent that received the page. Documentation now explains the
distinction and links the primary AOSP source. No test, helper launch, PF
change, or Portal request was made during this edit.

### PurrTol path routing correction

Checked the current public PurrTol server implementation and its recorded
requests. The server accepts `/mobile/status.php`, `/generate_204`, and
`/gen_204` by path; Host is logged in its examples but is not a routing gate.
Its request records include a Chrome 86 Android 9 CaptivePortalLogin request
on `/generate_204`, in addition to `/mobile/status.php`. Updated the local
compatibility and Stage 1 helpers to use that three-path route set while
retaining the exact `X-Requested-With`, Android 9, Chrome 86.0.4240.198, build
token, and WebView-marker checks for the Stage 1 page. Host is logged only.
Updated both research notes to match. This is source/doc review only: no tests
were run, no helper is listening, and no new request or payload was sent to
the Portal.

Latest host snapshot: `bridge100` still has `192.168.2.1`, but reports
`status: inactive`; no TCP/80 listener or Portal ARP neighbor was present.
Therefore a live captive-WebView capture has not yet been made for this
session. Next step is to reconnect the Portal to the controlled hotspot, run
the benign compatibility probe, and inspect the confirmed login-WebView path,
`X-Requested-With`, and User-Agent before deciding whether the exact-gated
Chrome 86 Stage 1 runner applies.

## Confirmed CaptivePortalLogin WebView and feature report (2026-09-29)

The owner ran `run_portal_compat_probe.sh`. The request log positively
identified `com.android.captiveportallogin` on `/generate_204` at
`connectivitycheck.gstatic.com`; the User-Agent reported Android 9,
`Build/PKQ1.191202.001`, and Chrome 106.0.5249.126. The compatibility page
was served once and reported WebAssembly available, `wasmAdd42=true`,
`wasmMemoryGrow=true`, WebGL 2, Qualcomm, and unmasked renderer Adreno 540.
`navigator.platform` reported `Linux armv8l`, which is not proof of process ABI
or kernel architecture. This is a real login-WebView fingerprint, not merely
the system connectivity-check UA.

The capture does not match the prepared PurrTol Stage 1 gate (Chrome
86.0.4240.198). Only the benign compatibility page was delivered; there is no
renderer RCE or device-access result. The next technical branch is to assess
the Chrome 106 V8 candidates against this WebView and determine whether OEM
backports or a compatible bounded trigger can be established. The posted
terminal output ended while the helper was still listening; stop it with
Ctrl-C. It reused the existing exact HTTP redirect, so that redirect remains
in the dedicated PF anchor after the helper exits.

### Chrome 106 lead review

Google's Chrome release notes place CVE-2022-3723's fix in Chrome 107.0.5304.87
and CVE-2022-4262's fix in Chrome 108.0.5359.94; both notes say exploitation
was observed in the wild. The Portal's reported 106.0.5249.126 therefore
matches the upstream pre-fix version family, but an OEM WebView backport has
not been ruled out. The reported Chrome 106 build does not match TAG's
documented Chrome-before-106 Android/Mali chain, and the observed GPU renderer
is Qualcomm Adreno 540. The public CVE-2022-4262 `exploit.js` is a more
concrete porting base than its root-cause reproducer: it builds against x64
`d8`, uses d8's `%DebugPrint`/`%GlobalPrint` diagnostics, and derives JS heap
read/write primitives with 64-bit compressed-pointer/layout assumptions. The
separate `test.js` uses d8 Sandbox APIs and requires
`v8_expose_memory_corruption_api`; that flag is not a dependency of
`exploit.js`. Its bytecode-aging trigger makes allocations approaching 2 GiB,
and the exploit stops at JS heap read/write rather than Android native code or
kernel access. It needs an architecture/layout port and bounded browser-GC
trigger before any Portal test. No CVE-2022-4262 trigger was sent. See
[`CHROME106_V8_CANDIDATES.md`](CHROME106_V8_CANDIDATES.md) and the
[CVE-2022-4262 exploit repository](https://github.com/mistymntncop/CVE-2022-4262).

## Compatibility-page WebAssembly CSP correction (2026-09-29)

Static review found that the compatibility page's CSP allowed inline JS but
did not allow WebAssembly compilation, so Chrome could reject the feature
check before measuring WebAssembly support. Added the older-browser
`'unsafe-eval'` CSP opt-in to the local diagnostic response, matching the
PurrTol renderer helper's Chrome 86 CSP allowance. This opt-in applies only to
the self-contained local page; it loads no remote scripts or resources. The
Chromium source history documents that WebAssembly compilation was guarded by
`unsafe-eval` before the narrower WebAssembly-specific directive existed.
Static review only; no test or Portal request was run.

## Captive WebView primitive and bridge-surface follow-up (2026-09-29)

The owner supplied terminal output from the bounded CVE-2022-4262 page runs.
The page reported `trigger_observed=true`, `primitive_candidate`, a nonzero
object address, successful object recovery, and identity with the original
test object. The original-size allocation sequence reported six failed
`0x7fe00000` allocations and zero successful allocations. A later run reported
the PoC test-object round-trip as matching. Another run reported a 32-bit
ArrayBuffer-layout hint and a successful read/write/restore marker round trip
inside a self-created 8 KiB ArrayBuffer. The output redacted raw pointers and
values. These are owner-provided WebView results, not independently repeated
here. They establish a renderer-side primitive candidate and a reversible
write/read on the page's own test allocation; they do not establish native
execution, Android access, sandbox escape, ADB, or root.

The compatibility helper was extended to inspect property descriptors on the
`window` object and a short prototype chain, plus `document` and `navigator`,
without invoking accessors or bridge methods. Its first all-global inventory
was noisy (578 entries). The narrowed run reported 26 enumerable window
function candidates (`atob`, `blur`, `btoa`, `getComputedStyle`, and other
ordinary browser functions); `nativeBridgeCandidateSurface` remained empty.
No bridge methods were enumerated or invoked. This is a limited surface scan,
not proof that no differently named or non-enumerable interface exists. The
owner's latest run produced no Python `SyntaxWarning`; the embedded JavaScript
whitespace-regex escape was corrected in the Python bytes literal.

The stage-one helper's incomplete, unused Wasm jump-table telemetry fields
and parameter were removed. No jump-table write or native-code stage was
implemented or sent. The captured target remains the Portal 10-inch Gen 1's
Android 9 `CaptivePortalLogin` WebView, reporting Chrome 106.0.5249.126 on
`/generate_204` with
`X-Requested-With: com.android.captiveportallogin`. PurrTol's existing
renderer `getpid` helper remains pinned to Chrome 86.0.4240.198 and
CVE-2020-16040; it is not a match for this observed WebView and must not be
run unchanged.

The official Chrome release record places CVE-2022-4262 in the Chrome 108
security update and reports exploitation in the wild. Chrome for Android 108
received the corresponding security fixes. Chrome 106.0.5249.126 is therefore
in the upstream pre-fix version family if the reported version reflects the
running engine and no OEM backport was applied. No package-level patch
verification was obtained for this Portal, so vulnerability applicability
remains plausible, not confirmed.

No EDL, USB command, image body, storage operation, Android setting change,
native payload, or ADB operation was performed during this follow-up. No
device access was gained. The remaining technical gap is beyond the evidence
collected by these probes; do not treat the renderer-side result as a device
takeover.

Sources: [Chrome 108 CVE-2022-4262 release](https://chromereleases.googleblog.com/2022/12/stable-channel-update-for-desktop.html), [Chrome for Android 108 update](https://chromereleases.googleblog.com/2022/12/chrome-for-android-update_13.html), [PurrTol renderer helper requirements](PURRTOL_STAGE1_GETPID.md), and [Chrome 106 V8 candidate assessment](CHROME106_V8_CANDIDATES.md).
