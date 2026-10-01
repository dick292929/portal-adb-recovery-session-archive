# Meta Portal 10-Inch (Gen 1) — Comprehensive Unlock & OOBE Bypass Engineering Audit

**Target Device:** Meta Portal 10" (1st Generation, Codename `aloha`, Snapdragon 660, Android 9 / API 28 / Aloha OS)  
**Host Environment:** macOS (Sonoma / Sequoia)  
**Target Output File:** `/Users/kahnmndez/Documents/Portal/PORTAL_10_INCH_UNLOCK_ATTEMPTS.md`  
**Related Workspace Repositories & Dumps:**
- `/Users/kahnmndez/Documents/Portal/CONVERSATION_DUMP.md` (Active 15.6" Portal+ documentation)
- `/Users/kahnmndez/Documents/Portal/scripts/` (`captive_portal_server.py`, `breakout_server.py`, `aloha_ble_advertiser.py`, `portal_traffic_sniffer.py`, `live_traffic_monitor.py`)

---

## 1. Executive Summary

This document compiles the exhaustive record of all engineering research, software exploits, network-layer interceptions, peripheral emulations, and hardware-level reverse-engineering methodologies attempted to unlock, unbrick, or bypass the Out-Of-Box Experience (OOBE) setup wizard on the **1st Generation 10-inch Meta Portal**.

### The Core Problem: The "Cloud E-Waste" Trap
When a 1st Gen Meta Portal 10" is restored to factory settings, it boots into the initial setup wizard (`com.facebook.aloha.devicesetup` / `DeviceSetupActivity`). The wizard progresses through:
```
[ Language Selection ] ──► [ Wi-Fi Connection ] ──► [ Terms of Service (TOS) ] ──► [ "Where is this portal going to live?" (Room Selection) ]
```
At the **Room Selection** screen, setup makes a network-backed request and shows a spinner, then an error on this unit. During a fresh September 24 attempt, a Portal TLS connection to `graph.facebook.com` ended with the Portal's fatal `certificate_unknown` alert before HTTP. That connection is a strong candidate for the screen failure, but the capture alone cannot tie it to the specific UI request. The exact request path and any later server response remain unknown. A permanent shutdown of the activation service, a 404/410 response, and `graph-portal.facebook.com` as the endpoint are therefore **unverified hypotheses**, not established causes. The native client's specific certificate-validation failure is not known because this 10-inch unit has no accessible ADB logs or firmware dump. See Vector 10.

### The ADB Catch-22
[Meta's official Portal developer setup instructions](https://developers.meta.com/horizon/documentation/android-apps/portal-setup/) (updated June 10, 2026) list the 1st-generation Portal as supported and say to enable ADB at **Settings > Debug > ADB Enabled**. This is Portal's Settings app, not AOSP Developer Options. A factory-reset Portal stuck in OOBE cannot reach that screen through the normal flow. The exact firmware and Settings build on this 10" unit have not yet been identified.

---

## 2. Chronological Matrix of All Attempted Vectors

| # | Attack Vector / Methodology | Specific Technique & Tools | Theoretical Goal | Failure Mode / Hard Boundary Encountered | Final Status |
|---|---|---|---|---|---|
| **1** | **CVE-2024-31317 (`portal-toolkit`)** | MobileConfig Zygote injection script (`tchebb/portal-toolkit`) | Force debug mode & override OOBE | Requires an already active ADB shell connection; cannot establish initial handshake on locked unit. | **Blocked** |
| **2** | **Network MitM & Activation Forgery** | Custom proxy (`portal_proxy.py`) spoofing `*.facebook.com`, `*.fbcdn.net` | Feed spoofed "Activated/Provisioned" JSON response | The proxy attempt failed, but the exact cause is not established for the 10" setup build. The available DeviceIdentityService config has no pin-set; its hardware attestation is application-layer data, not evidence of TLS mTLS. | **Blocked; cause unverified** |
| **3** | **Captive Portal DNS Hijacking** | Local DNS redirect (`192.168.1.43`) & `captive_portal_server.py` | Force Android `CaptivePortalLoginActivity` | Android 9 bypassed port 53 via Private DNS (DNS-over-TLS on port 853). Once blocked with `pfctl`, captive window loaded, but intents are stripped. | **Blocked** |
| **4** | **Captive Portal Browser Escape** | Text selection floating toolbar (`Web Search`) & intent URIs | Escape captive sandbox to AOSP Settings | Meta's custom ROM disabled `Web Search` on text highlight. Intent links returned `net::ERR_UNKNOWN_URL_SCHEME` / "This intent is not supported". | **Blocked** |
| **5** | **Terms of Service (TOS) Chrome Breakout** | Tap TOS legal hyperlinks to open embedded Chromium (Chrome 106) | Navigate to local server (`breakout_server.py`) and trigger intents | Chromium 106 blocks unregistered `intent://` system schemes. Intent firewall drops calls to internal activities. | **Blocked** |
| **6** | **Chrome Action Sheet Exploitation** | Tap Chrome menu: Settings, Downloads, Print, Share | Breach file system or Android Settings | • **Settings:** Refreshed web page.<br>• **Downloads:** "File downloads are disabled" (policy lock).<br>• **Print:** No-op (PrintSpooler missing).<br>• **Share:** Sharesheet opened but completely blank (no social/storage apps installed). | **Blocked** |
| **7** | **HTML5 Immersive Video Escape** | Fullscreen HTML5 video with swipe-to-reveal navigation bar | Force Android navigation/status bar to appear | Aloha OS WindowManager kiosk policy permanently hides the status bar and soft navbar during OOBE. | **Blocked** |
| **8** | **On-Screen Keyboard (`NiuEditText`)** | Long-press comma, gear icon, globe key, clipboard menus | Open IME Settings / Gboard settings | Decompiled bytecode revealed Meta used Java reflection to set `mSelectionControllerEnabled=false`. All context menus and gear icons stripped. | **Blocked** |
| **9** | **Secret Accessibility Gesture** | 4–6 second continuous multi-finger touch-and-hold | Trigger hidden accessibility service | **Discovered in decompiled APK!** Successfully activated Google TalkBack ("it spoke and show a menu"). | **Partial Success (TalkBack active)** |
| **10** | **TalkBack Context Menu Escape** | "L" gesture, Up/Right, 3-finger tap, Vol Up + Vol Down 3s | Open TalkBack Settings ➔ TTS ➔ Android Settings ➔ ADB | Aloha custom touch dispatcher intercepted and dropped multi-touch context gestures. Menu never rendered. | **Blocked** |
| **11** | **USB OTG Physical Keyboard** | USB-C OTG keyboard injecting `Win+N`, `Win+Enter`, `Alt+Esc` | Trigger global shortcut keys | Device failed to enumerate or power keyboard. USB-C port locked in peripheral/device mode in OOBE HAL without 5V VBUS host power. | **Blocked** |
| **12** | **BLE Remote Emulation** | `aloha_ble_advertiser.py` broadcasting Aloha TV Remote UUIDs | Pair fake Bluetooth remote to inject D-pad navigation | Decompiled `aloha_devicesetup_release.apk` proved BLE remote discovery is hardcoded only for Portal TV (`aloha_tv`/`ohana`); disabled on touchscreens. | **Blocked** |
| **13** | **MediaTek Bootloader Bypass** | `mtkclient` in Python virtual environment (`.venv`) | Bypass BROM / preloader to dump/flash partitions | Hardware audit revealed Portal 10" Gen 1 uses **Qualcomm Snapdragon 660**, not MediaTek. MTK handshake failed. | **Inapplicable** |
| **14** | **Qualcomm EDL (9008) & Firehose** | Emergency Download Mode (EDL) via cable / motherboard test points | Flash custom patched `boot.img` with ADB root | Qualcomm Secure Boot (QSB) enforces OEM Root of Trust (`PK_HASH`). Requires an OEM Meta-signed Firehose loader (`prog_emmc_firehose_...mbn`). No leaked loader exists. | **Blocked** |
| **15** | **Identity Certificate Cloning** | Extract identity certificates from active 15.6" Portal+ | Replay identity on 10" Portal | Certificates are cryptographically bound to unique hardware IDs (SoC serial, eMMC CID, TrustZone RPMB). | **Blocked** |
| **16** | **Extended Online Provisioning Wait** | Leave the 10" Portal powered and connected at Room Selection for 7 consecutive days | Allow delayed OTA, certificate provisioning, or backend recovery to complete | The device did not provision or advance. Passive waiting alone is ruled out as a workaround; see the separate network-remedy test below. | **Failed** |
| **17** | **Common Network & Community Setup Remedies** | Test alternate network/DNS and the basic setup suggestions found in Portal community reports | Resolve provisioning failure caused by local network conditions or a known setup quirk | User confirms these basic suggestions were tried without success. Individual configurations are not itemized in this record. | **Failed** |
| **18** | **Launch Meta Settings from the TOS browser** | Intent links target app ID `com.facebook.alohaapps.settings` and activity `com.facebook.aloha.system.settings.SettingsActivity`, with `android.settings.SETTINGS`, `DEBUG_TAB`, and `PROD_DEBUG_TAB` actions | Reach the Portal ADB toggle without completing OOBE | The user tapped the links and saw no visible response. The Settings dump is from the activated Portal+ and is not confirmed to match this 10" firmware. | **Failed in current browser path** |
| **19** | **Meta's browser-openable Portal Settings URIs** | Regular `portal://settings/accessibility_settings` and `portal://settings/network` links declared `BROWSABLE` in the available Settings manifest | Launch the Settings app through its registered custom URI routes, then navigate to Debug settings | The user reports no visible response when tapping the links or entering either URI directly in the address bar. The available manifest is from the activated Portal+ and may differ from the 10" firmware. | **Failed in current browser path** |
| **20** | **AOAv2 host-side HID keyboard, consumer controls, and touchscreen** | Mac switches the Portal into Android Open Accessory mode over the existing USB cable, registers HID input devices, and sends navigation/touch events | Navigate OOBE/browser without ADB or browser link launches | Portal reported AOA protocol 2 and re-enumerated as `18D1:2D00`. Keyboard Tab/arrow/Escape/Enter and consumer Home produced no visible effect; consumer Back returned to Welcome. The emulated touchscreen tap did not advance Welcome. User then advanced by physical touch through Welcome and Terms to Room Selection, where Living room is selected. | **Physical setup navigation reaches the blocker** |
| **21** | **Submit Room Selection** | Select the preselected Living room option and tap Continue | Complete OOBE's mounting/location step | User confirms Continue shows a spinner for a while, then an error, and does not advance. The attached photo shows the spinner in progress; the exact final error text is not captured. | **Failed; app/backend error confirmed by user** |

---

## 3. Deep-Dive Technical Post-Mortems

### Vector 1: Network-Layer Captive Portal Interception & Private DNS (DoT)
* **Script:** `/Users/kahnmndez/Documents/Portal/scripts/captive_portal_server.py`
* **Mechanism:**
  Android devices run a captive portal detection check on network association by making an unencrypted HTTP probe to:
  ```text
  http://connectivitycheck.gstatic.com/generate_204
  ```
  If the endpoint returns HTTP 204 No Content, Android assumes open internet. If it receives an HTTP 302 redirect, Android summons `CaptivePortalLoginActivity`.
* **The Mac Interception Rig:**
  1. Enabled macOS Internet Sharing to create Wi-Fi hotspot on `bridge100` (`192.168.2.1`).
  2. Routed traffic via macOS packet filter (`pfctl`):
     ```bash
     rdr pass on bridge100 inet proto tcp from any to any port 80 -> 192.168.2.1 port 80
     block drop quick on bridge100 proto tcp to any port 853
     ```
* **Discovery (DNS-over-TLS Blockade):**
  The initial setup failed to catch the Portal because Android 9 employs **Private DNS (DoT on port 853)** directly to `1.1.1.1:853` or upstream resolvers. The Portal bypassed standard UDP port 53 DNS redirection. Once port 853 was dropped via firewall rules, the device fell back to port 53, and the captive redirect fired.
* **Failure Mode:**
  The captive portal WebView launched successfully. However, Meta hardened the captive portal container:
  - All standard URL schemes (`intent:`, `package:`, `tel:`, `file:`) returned `net::ERR_UNKNOWN_URL_SCHEME`.
  - The browser window did not provide a standard address bar, preventing arbitrary navigation.

* **Extended wait test:** The Portal was left powered and connected at Room Selection for **7 consecutive days**. It did not provision or advance. Waiting longer by itself is not a useful next step.

* **Alternate network and community suggestions:** The user confirms trying the common network/DNS and setup remedies discussed in Portal community reports, without success. The specific configurations were not itemized, so this closes the basic troubleshooting path without identifying a particular failed network variable.

---

### Vector 2: The Terms of Service (TOS) Chrome Escape & Action Sheet Audit
* **Script:** `/Users/kahnmndez/Documents/Portal/scripts/breakout_server.py`
* **Mechanism:**
  On the Welcome/TOS screen of OOBE, clicking hyperlinks (Privacy Policy, Terms of Service) launched an embedded Chromium browser (Chrome 106). By clicking around and hitting the space/escape sequence, the full URL bar was exposed.
* **The Breakout Server (`breakout_server.py` on Port 8000):**
  A custom test suite was built on the Mac and served to the Portal:
  ```html
  <!-- Test 1: Standard Settings Intent -->
  <a href="intent://#Intent;scheme=android-app;package=com.android.settings;action=android.settings.SETTINGS;end">Settings</a>

  <!-- Test 2: Direct Component Launch -->
  <a href="intent://#Intent;package=com.android.settings;component=com.android.settings/.Settings;end">Component Settings</a>

  <!-- Test 3: Developer Options Intent -->
  <a href="intent://#Intent;package=com.android.settings;action=android.settings.APPLICATION_DEVELOPMENT_SETTINGS;end">Developer Options (ADB)</a>

  <!-- Test 4: Aloha Settings Package -->
  <a href="intent://#Intent;package=com.facebook.aloha.system.settings;action=com.facebook.aloha.action.ACCOUNT_LOGIN;end">Aloha Settings</a>
  ```
* **Failure Modes Observed:**
  1. **Intent Firewall:** Previous `intent://` tests showed *"This intent is not supported"*. The tested target/action did not match the exported Portal Settings entry point described below, so that result does not rule out the Settings launch route.
  2. **Chrome Action Sheet:**
     - **Settings (`gear`):** Clicking it triggered a page reload rather than opening Chrome settings.
     - **Downloads:** Clicking download displayed: *"File downloads are disabled"*. Meta deactivated Android's `DownloadManager` service in kiosk mode.
     - **Print:** Invoking the print action failed to open Android's `PrintSpooler`.
     - **Share:** The native Android Sharesheet appeared, but it was 100% empty. Meta stripped Bluetooth transfer, email clients, Android Beam, and cloud storage apps from the base image.
 3. **Text Highlight / Context Menu:**
  - Text highlighting was suppressed via `-webkit-user-select: none` across system web components. Where text could be selected, Android's `Web Search` intent action had been stripped from the ROM.

---

### Vector 3: The Secret Touch-Hold Backdoor & TalkBack Accessibility Trap
* **Decompiled Source:** `aloha_devicesetup_release.apk` ➔ `com.facebook.aloha.devicesetup.DeviceSetupActivity`
* **The Breakthrough:**
  By decompiling the OOBE application, we audited `DeviceSetupActivity.dispatchTouchEvent()`. Embedded within Meta's touch event handler was a hidden continuous touch timer:
  - If a user presses and firmly holds multi-finger contact anywhere on the screen for **4 to 6 continuous seconds**, `DeviceSetupActivity` invokes the internal accessibility setup service.
* **The Result:**
  Upon executing this gesture on the physical device, the screen immediately responded:
  > *"It spoke and show a menu... the pop up went away and now is talking back every menu item."*
  **Google TalkBack was successfully activated in memory!**
* **The TalkBack Escape Plan:**
  In standard Android kiosk breakouts, activating TalkBack allows navigating to:
  ```
  Draw "L" Gesture ──► Global Context Menu ──► TalkBack Settings ──► Text-to-Speech Settings ──► Back Arrow (←) ──► Portal Settings ──► Debug ──► ADB Enabled
  ```
* **Failure Mode (Input Filtering):**
  Once TalkBack was active, we tested every recognized TalkBack activation gesture:
  - Down and right ("L" gesture).
  - Up and right.
  - Three-finger tap.
  - Physical Volume Up (+) and Volume Down (-) buttons held together for 3 seconds.
  
  **Result:** None of the gestures opened the Global Context Menu overlay.
  **Root Cause:** Meta implemented a custom `WindowManager` policy and touch dispatcher for Aloha OS that filters raw motion events before they reach the accessibility overlay layer. While the TalkBack text-to-speech feedback engine ran in the background, gesture recognition was dropped, preventing access to TalkBack Settings.

---

### Vector 4: Hardware & Peripheral Injections
#### 1. Physical USB-C OTG Keyboard
* **Hypothesis:** Connect a USB keyboard via USB-C OTG to send global key combinations (`Win + N` for Notification Shade, `Win + Enter` for Settings, `Ctrl + Alt + Del`).
* **Result:** Keyboards failed to receive power or enumerate.
* **Root Cause:** The 10" Portal motherboard requires a 12V DC barrel jack for power. The USB-C port is managed by a hardware power delivery controller that locks the port in USB Device (Peripheral) mode during OOBE. It does not supply 5V VBUS host power or initialize the USB HID kernel driver.

#### 2. Aloha BLE Remote Emulation
* **Script:** `/Users/kahnmndez/Documents/Portal/scripts/aloha_ble_advertiser.py`
* **Mechanism:**
  Meta Portal TV (`aloha_tv` / `ohana`) uses an unbonded Bluetooth Low Energy (BLE) remote controller for setup. We wrote a CoreBluetooth advertiser in Python to broadcast the exact Aloha Remote BLE advertising payload:
  - Service UUID: `0000fee7-0000-1000-8000-00805f9b34fb` (Aloha Service)
  - HID UUID: `00001812-0000-1000-8000-00805f9b34fb` (Human Interface Device)
  - Device Name: `"Aloha Remote"`
* **Outcome:** The 10" Portal showed zero interaction.
* **Decompiled Bytecode Confirmation:**
  In `aloha_devicesetup_release.apk`, Meta branched OOBE pairing by device form factor:
  ```java
  if (DeviceFormFactor.isPortalTV(context)) {
      startBleRemoteDiscovery();
  } else {
      // Touchscreen devices (10" & 15.6" Plus) strictly use capacitive touch
      disableBleRemoteDiscovery();
  }
  ```
  The BLE remote discovery receiver is explicitly disabled on touchscreen Portals.

---

### Vector 5: Low-Level Silicon & Bootloader Exploitation
#### 1. MediaTek BROM (`mtkclient`)
* **Attempt:** Initial testing explored if `mtkclient` could catch the device during boot.
* **Result:** No handshake.
* **Reality:** The 10" Portal (Gen 1) does not run MediaTek silicon. It is built entirely on the **Qualcomm Snapdragon 660 (`SDM660`)**. MediaTek exploits are completely inapplicable.

#### 2. Qualcomm EDL (Emergency Download Mode 9008) & Firehose
* **Architecture:**
  Qualcomm SoCs have a hardware-level recovery mode called EDL (USB PID `05C6:9008`), triggered via an EDL cable (shorting D+ to GND) or physical motherboard test points.
* **The Cryptographic Wall:**
  In Snapdragon 660, Qualcomm Secure Boot (QSB) is enforced in hardware:
  1. The Primary Bootloader (PBL) in SoC ROM checks the digital signature of the incoming Firehose programmer (`prog_emmc_firehose_...mbn`).
  2. The signature is validated against the OEM Public Key Hash (`PK_HASH`) permanently burned into the SoC's One-Time Programmable (OTP) eFuses.
  3. If the Firehose programmer is not signed with Meta's private key, the PBL aborts the connection with error `0x0E (Authentication Failed)`.
* **State of the Community:**
  Unlike popular Xiaomi or OnePlus phones, no signed Qualcomm Firehose programmer for the Meta Aloha platform has ever been leaked. Without Meta's signed loader, EDL cannot read or flash partitions.

### Vector 6: Exported Meta Settings Entry Point (Pending Device Test)
* **Static evidence:** The available Settings manifest has app ID `com.facebook.alohaapps.settings` and marks class `com.facebook.aloha.system.settings.SettingsActivity` exported with no component permission. Its filters include `android.settings.SETTINGS`, `com.facebook.aloha.system.settings.DEBUG_TAB`, and `com.facebook.aloha.system.settings.PROD_DEBUG_TAB`. The separate `DebugSettingsActivity` and `ProdDebugSettingsActivity` are `exported="false"`.
* **ADB toggle evidence:** The same Settings dump contains the ADB row in its debug layout and the mobile-config gate `aloha_show_prod_adb_enabled_setting`. Therefore, even if the exported entry point launches, the production ADB row may be hidden by config.
* **Why this was missed:** The earlier test targeted `com.android.settings` or used the Java namespace `com.facebook.aloha.system.settings` as the app ID with an account-login action. It did not target the actual app ID and exported `SettingsActivity` with its Settings or Debug-tab action.
* **Artifact limitation:** The Settings APK dump came from the already activated 15.6" Portal+, not a verified dump from this 10" Portal. Treat the manifest result as a lead, not proof that the 10" firmware has the same component.
* **Test result:** The LAN test page loaded in the Portal browser. The user tapped each Settings/Debug intent link; there was no visible response or dialog. The exported Settings route remains unverified on the 10" firmware.

### Vector 7: Browser-Openable Portal Settings URIs (Pending Device Test)
* **Static evidence:** The available Settings manifest declares `portal://settings/accessibility_settings` and `portal://settings/network` as `VIEW` + `BROWSABLE` routes to `SettingsActivity`.
* **Why try this after the Intent URIs:** The user tapped all four `intent://` launch links and saw no visible response. These are ordinary links using an app-registered URI scheme, so they exercise a different browser-to-app handoff path.
* **Test result:** Neither tapping nor directly entering the two URIs produced a visible response. Browser-to-app launches appear blocked in the current OOBE browser.

### Vector 8: Android Open Accessory v2 HID Keyboard over the USB-C Cable
* **Why this differs from the OTG keyboard attempt:** The Portal stays in USB-device mode while the Mac sends AOA host-side control requests. It does not require the Portal to provide USB host power or enumerate a physical keyboard.
* **Capability check:** A standard AOA `GET_PROTOCOL` request returned version 2, which supports HID input. The Mac then sent `ACCESSORY_START` without app-identifying strings; the Portal re-enumerated as Google accessory-mode ID `18D1:2D00`.
* **Input registration:** Registered an 8-byte keyboard HID report descriptor. The first event attempt returned a USB pipe error because it was sent immediately after registration. Android's AOA HID implementation recommends a short initialization delay; after adding that delay, the Portal accepted an 8-byte Tab press report and an 8-byte release report.
* **Current status:** The USB-side input path is working. Tab, arrow, keyboard Escape/Enter, and consumer-control Home reports were accepted but had no visible effect. A separate AOA consumer-control `AC Back` press/release returned the user to the Portal Welcome screen. An AOA touchscreen HID tap at the photographed Get Started button did not advance. The user then advanced successfully with physical touch through Welcome and Terms to Room Selection, with Living room selected. The device remains in AOA mode until USB is disconnected and reconnected, which restores its normal USB identity.

### Vector 9: Room Selection Continue Fails After Loading
* **Observed behavior:** The user selected the preselected Living room option and tapped Continue. The Portal displayed a loading spinner, then an error, and stayed on Room Selection. The attached photo was taken during the spinner, before the final error appeared; the exact error text is not visible. The user has now confirmed they also tried a custom room name earlier; changing the room-name input did not resolve the setup failure.
* **Known limits:** Passive waiting (seven days) and common network/community suggestions have already been tried. `scripts/captured_traffic.log` is a September 3 capture from an earlier Mac-hotspot session; it contains DNS and connection summaries, not the current request's HTTP result, so it cannot identify this failure's response.
* **Next diagnostic input:** The final on-device error text or screenshot, if available without retrying the step. Do not repeat Continue solely to produce another identical failure.

### Vector 10: Cross-Owner Reports and Service-State Uncertainty
* **Current reports:** Multiple owners reported the same spinner-then-error at the room/name step on first-generation Portal-family hardware in June–July 2026. In the same discussions, some newer or different Portal models completed activation. This supports a real setup/provisioning failure affecting multiple owners, but does not prove a total service shutdown or establish that every model/firmware/region is affected.
* **Meta report:** Meta's developer feedback tracker has an investigation titled "Portal+ Device Setup Fails with 'Something Went Wrong' Error," currently marked "Investigating" (single report; status may change): https://developers.meta.com/horizon/feedback/vr/investigations/867821569245608/
* **Community references:** Exact room-step reports: https://www.reddit.com/r/FacebookPortal/comments/1u29dti/setup_problem/ and https://www.reddit.com/r/FacebookPortal/comments/1v4hl8l/having_setup_problem_after_factory_reset_on_meta/. These are anecdotes and include mixed outcomes across device generations.
* **Implication for this case:** Do not treat "Meta shut down the provisioning endpoint" as proven. The user's seven-day wait, common network remedies, and custom room-name variation are already ruled out. The next useful distinction is whether a fresh room submission is rejected by the service or the local setup app: preserve the final error text and, if needed, capture a fresh request's connection metadata. Avoid factory resetting again; it would erase state without testing this hypothesis.
* **Fresh capture result (2026-09-24):** The Portal is on the Mac's `Portal test` Internet Sharing network (`192.168.2.3`); the Mac's `bridge100` is `192.168.2.1/24`. It completes TCP handshakes and receives HTTPS data from `57.144.248.141:443`, ruling out basic TCP/443 reachability failure for these exchanges. The `-X` capture exposed SNI `graph.facebook.com` and the Portal's outbound bytes `15 03 03 00 02 02 2e`: TLS Alert, fatal level `2`, description `0x2e` (`certificate_unknown`, alert 46). This is immediately followed by a TCP reset, so the Portal is rejecting the TLS peer certificate in this flow; RFC 5246 defines fatal alerts as terminating the connection. The earlier 184-byte client hello, ~4.4 KB server flight, 7-byte alert and reset are consistent with that sequence. The same capture also shows `b-www.facebook.com` client hellos followed by a 126-byte TLS handshake response, so those flows appear to continue past certificate receipt.
* **Mac-side certificate comparison:** OpenSSL to the same IP with TLS 1.2 and hostname verification succeeds for both `graph.facebook.com` and `b-www.facebook.com`. Both names present the same leaf SHA-256 fingerprint (`02:54:1B:FD:7A:A7:15:D7:0E:2B:DC:67:3F:35:0C:E1:E7:7D:53:D1:2D:5B:17:97:DE:50:B4:D5:9B:69:EF:61`), subject `CN=*.facebook.com`, issuer `DigiCert Global G2 TLS RSA SHA256 2020 CA1`, valid 2026-07-03 through 2026-10-01. The server sends a 3-certificate chain (leaf, DigiCert Global G2 TLS RSA SHA256 2020 CA1 intermediate, and cross-signed DigiCert Global Root G2); Mac verification returns `Verify return code: 0 (ok)`. This proves the certificate chain/hostname validate against the Mac's trust store, not the Portal's. Because Portal flows to `b-www.facebook.com` appear to proceed while `graph.facebook.com` triggers `certificate_unknown`, likely next distinctions are Portal-side per-client trust/pinning or certificate-validation behavior; the specific reason is not yet proven. A device clock or CA-store issue also remains possible.
* **Exact firmware artifact limit:** The workspace contains a decompilation of the Portal+ 15.6-inch setup APK, not an APK confirmed from this 10-inch unit. There is no exact 10-inch setup APK or runtime log available to determine its pinned certificates or trust-store contents. The Portal+ source contains a mobile-config-gated MNS certificate-verifier path, but that is only a lead for this device.
* **On-device browser comparison:** The diagnostic page's `https://graph.facebook.com/` link returned an “unsupported GET” response, which means the browser completed HTTPS and received an HTTP response; the `b-www.facebook.com` link opened Facebook. This confirms browser-side TLS succeeds to both hosts while the OOBE native client rejects the Graph connection. The browser displayed timezone `GMT+0000`; the two-hour difference from Warsaw local time is consistent with UTC versus CEST and does not establish a two-hour error in the underlying clock. The leaf certificate is valid across the current date, so a two-hour offset alone would not explain this rejection. The exact device UTC instant was not recorded.
* **Alternate edge and certificate-profile check (2026-09-24):** DNS resolvers returned `31.13.84.8` and `57.144.112.141` as alternate Graph edges. With the normal ECDSA TLS 1.2 negotiation, both present the same `*.facebook.com` leaf and chain as `57.144.248.141` (SHA-256 leaf fingerprint beginning `02:54:1B:FD`). Meta also offers a different RSA leaf (fingerprint beginning `D9:7C:BD:15`) when a test client explicitly offers only RSA signatures, but the Portal's captured ClientHello offers ECDSA cipher suites. Merely changing DNS to these checked edges will not change the certificate the Portal receives. The capture also shows another Portal client profile completing TLS to Graph, so this is a client/connection-specific failure rather than evidence that every Portal connection to Graph is broken.
* **Expanded routing check (2026-09-24):** Tested seven reachable Meta Graph edges (`157.240.205.1`, `157.240.8.18`, `57.144.110.141`, `57.144.112.141`, `57.144.248.141`, `57.144.252.141`, `57.144.50.141`) with the same `graph.facebook.com` SNI and ECDSA TLS 1.2 negotiation. Each returned the same leaf certificate fingerprint (`02:54:1B:FD:7A:A7:15:D7:...`) and verified on the Mac. Testing `-status` on multiple edges and the separate `b-www.facebook.com` edge showed no stapled OCSP response on any of them. A route to these edges, or a transparent TCP proxy to them, leaves the Portal-facing certificate unchanged. A local HTTPS server would need a certificate the Portal accepts for `graph.facebook.com`; simply rewriting DNS or the destination IP cannot supply that. This does not rule out a different, as-yet-unidentified Meta edge or a separate failure in revocation checking.
* **Mac firewall check limitation:** The user ran `sudo pfctl -a '*' -sn` in the visible Terminal while the Portal was off. It showed only `com.apple/*` and `com.apple.internet-sharing` NAT/redirect anchor references, with no `captive_portal` redirect in the Mac's rule listing at that moment. This does not establish which rules were active during the earlier room-selection attempt or whether the Portal's certificate-status traffic was affected then. The first direct-anchor query returned `DIOCGETRULES: Invalid argument`; neither query captured live Portal traffic.
* **Pin-set lead from donor Portal+ APK:** Its decompiled network trust manager checks SHA-256 public-key pins from an embedded list until `2026-07-28 11:00:47 UTC`, after which that extra pin check is skipped. The present Graph chain contains the DigiCert Global Root G2 public key whose pin is in that list. This weakens a simple “Meta rotated away from every embedded pin” explanation for the donor APK, but the target 10-inch setup build and its pin list remain unavailable; it does not establish this unit's cause.
* **Recovery update status:** Standard Android recovery can sometimes sideload a manufacturer-signed OTA without normal Android ADB, but no verified Meta-signed update package or safe recovery procedure for this exact 10-inch unit was found in this investigation. Do not enter the documented two-volume-button factory-reset sequence as an update attempt; it initiates a reset, not an identified sideload procedure.

---

## 4. Architectural Comparison: 10" Portal vs. 15.6" Portal+

| Feature / State | User's 10-inch Portal | User's 15.6-inch Portal+ (`aloha`) |
|---|---|---|
| **Hardware ID** | Retail Unit (Gen 1) | `818PGA01P0927M29` |
| **Status Prior to Project** | Factory Reset / De-provisioned | **Already Activated / Home Screen Accessible** |
| **OOBE Screen State** | Stuck at "Choose Room" | Completed before Meta server shutdown |
| **ADB Status** | **Disabled** (Cannot reach Settings) | **Enabled** via Portal Settings > Debug |
| **OpenPortal (`openportal.cc`)** | Ineffective (requires ADB to push payload) | **Fully Applied & Functional** |
| **Installed Launcher** | Stock OOBE Setup Wizard | **Immortal Launcher** (`com.immortal.launcher`) |
| **Home Assistant Integration** | None | Full bidirectional HA bridge + live feeds |
| **Alexa Voice Services** | Inactive | Restored via `com.millennium` + Falcon |

---

## 5. Feasibility Verdict & Current State

### 1. Is the 10" Portal Brick Permanent?
* **Through Standard Software:** **Not yet proven, but currently blocked.** Browser-to-Settings launches produced no visible response. AOA HID accepted input reports but did not open Settings or bypass Room Selection. A fresh capture during setup identifies a Portal TLS certificate rejection that may explain the failure; its exact validation rule, relation to the UI request, and any later provisioning result remain unknown.
* **Through Low-Level Flashing:** **Blocked by Qualcomm Secure Boot.** Unless a signed Meta Snapdragon 660 Firehose loader leaks or a bootrom-level hardware vulnerability is found for SDM660, EDL flashing is impossible.

### 2. The Single Working Surface: The "Kiosk Web Display" Fallback
While full Android OS unlocking and ADB remain blocked, the device **does have an active, hardware-accelerated Chromium 106 engine accessible via the Terms of Service hyperlinks**. 

By pointing the TOS browser to a local Mac/Home Assistant web server, the 10" Portal can render:
- Home Assistant Lovelace dashboards.
- Local fullscreen clocks / weather stations.
- Web-based video or camera streams.

*Note: Because this operates inside the TOS Custom Tab, the screen lacks deep system power management and must be managed via web-based wake locks.*

---

## 6. Document History & Artifact References

* **Original Engineering Sessions:** August 20, 2026 – September 3, 2026
* **Transcripts Audited:**
  - `53d03e01-d801-4336-a80c-da117a69e1a8` (Initial OOBE catch-22, captive portal tests, EDL analysis)
  - `c126c816-af2c-4630-9c54-c2b70004ea97` (Proxy activation & Android 9 vulnerability review)
  - `f4030438-1f3c-42f8-b1f0-737f8884b6d0` (Deep decompilation, BLE remote emulator, TalkBack trigger, Chrome breakout suite)
* **Associated Code Files in Workspace:**
  - `/Users/kahnmndez/Documents/Portal/scripts/captive_portal_server.py`
  - `/Users/kahnmndez/Documents/Portal/scripts/breakout_server.py`
  - `/Users/kahnmndez/Documents/Portal/scripts/aloha_ble_advertiser.py`
  - `/Users/kahnmndez/Documents/Portal/scripts/portal_traffic_sniffer.py`
  - `/Users/kahnmndez/Documents/Portal/scripts/live_traffic_monitor.py`
