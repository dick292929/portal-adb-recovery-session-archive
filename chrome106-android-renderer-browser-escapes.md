# Renderer→Browser Sandbox Escapes for Chrome 106.0.5249.126 (Android WebView)

**Target:** Chrome/Chromium **106.0.5249.126**, Android, renderer process (WebView renderer).
**Relevance cutoff:** anything first-fixed in a version *newer than* 106.0.5249.126 is still exploitable in the target. Practically, that means everything fixed in **107.0.5304.x** and **108.0.5359.x** (late 2022) is in scope.

> Version-order sanity check: `106.0.5249.126` is *newer* than `106.0.5249.119`. So any CVE fixed in 106.0.5249.119 or earlier (e.g. CVE-2022-3445/3446) is **already patched** in this target.

---

## Corrections to the task's assumptions (verified against OSV/chromereleases)

- **CVE-2022-3445** is *"Use after free in Skia"*, not "Network service". Fixed in **106.0.5249.119** → **already patched** in the target. Renderer-only, not a boundary escape.
- **CVE-2022-3446** is *"Heap buffer overflow in WebSQL"*, not "Network service". Fixed in **106.0.5249.119** → **already patched**. Renderer-only.
- The actual *"Network service"* renderer→browser escape from that era is **CVE-2022-3038** ("Use after free in Network Service", `crbug.com/1340253`), but it was fixed in **105.0.5195.52** → **not applicable** to 106. It reappeared as an *n-day* stage in the Dec-2022 Samsung Internet chain (below).
- **CVE-2022-4182** is *not* a Mojo/Blink UAF — it is *"Inappropriate implementation in Fenced Frames"* (a web-platform policy bypass, Medium, no memory corruption). Not a sandbox escape.

---

## Candidate-by-candidate analysis

### 1. CVE-2022-3656 — Insufficient data validation in File System ⭐
- **CVE/bug:** CVE-2022-3656 / `crbug.com/1345275`
- **Component:** File System (browser-process side; reached by the renderer via the storage/FileSystem Mojo interfaces). "Bypass file system restrictions" = a renderer→browser data-validation hole that lets web content cause the browser process to operate on files outside the renderer's permitted scope.
- **First fixed:** **107.0.5304.62** (2022-10-24/25).
- **Renderer→browser boundary:** **Yes.** This is a browser-process file-system restriction bypass, not a kernel/GPU-driver bug.
- **Public exploit/PoC:** **No public PoC or root-cause writeup.** No Project Zero RCA exists (it is absent from the [0days-in-the-wild RCA index](https://googleprojectzero.github.io/0days-in-the-wild/rca.html)). Reported by **Clement Lecigne (Google TAG)** and flagged by Chrome as exploited **in the wild**. Maturity = *private spyware exploit only*; a port would require reverse-engineering the [patch](https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_25.html) + `crbug` discussion.
- **Triggerable from plain web content:** **Yes** — "crafted HTML page", no `chrome://`, no extension, no `--allow-natives-syntax`.
- **Sources:** [chromereleases 107.0.5304.62](https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_25.html) · [OSV](https://api.osv.dev/v1/vulns/CVE-2022-3656) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-3656)

### 2. CVE-2022-4135 — Heap buffer overflow in GPU "validating command decoder" ⭐
- **CVE/bug:** CVE-2022-4135 / `crbug.com/1392715`
- **Component:** Chrome's own GPU command-buffer **GLES2 "validating command decoder"** (`gpu/command_buffer` / `TextureManager`). *This is a Chromium component, not a GPU driver or kernel bug.*
- **First fixed:** **107.0.5304.121** (2022-11-24). TAG describes it as **"Chrome GPU sandbox bypass, only affecting Android"**.
- **Renderer→browser boundary:** **Yes (renderer→GPU-process in full Chrome).** TAG/Project Zero treat it as the *sandbox-escape stage* of a real Android chain: the renderer drives the command buffer via WebGL/shared-memory + IPC and overflows a `level_infos` vector in the decoder. In full Chrome-on-Android this is the **GPU process**; in **Android WebView** the command buffer runs **in-process** (see architecture note below), so for a WebView target it plausibly lands in the host/browser process directly.
- **Public exploit/PoC:** **Yes — full Project Zero root-cause analysis** (Sergei Glazunov) with a working trigger (`repro.diff` + `repro.html`, a 3-line WebGL2 `blendColor` repro). Exploit *sample* itself was not published ("N/A", analyst had access), so maturity = *root-cause + confirmed repro, port/weaponization left to researcher*. Reporter: Clement Lecigne (TAG).
- **Triggerable from plain web content:** **Yes** — WebGL2 from an HTML page.
- **Chain:** documented as `CVE-2022-3723 (V8) → CVE-2022-4135 (GPU escape) → CVE-2022-38181 (Mali kernel EoP)`.
- **Sources:** [Project Zero RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-4135.html) · [chromereleases 107.0.5304.121](https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop_24.html) · [bug](https://bugs.chromium.org/p/chromium/issues/detail?id=1392715) · [patch](https://chromium.googlesource.com/chromium/src/+/2bd6ab1a16090fd20d422c11d794edf5c0ff6b89)

### 3. CVE-2022-4178 — Use after free in Mojo ⭐
- **CVE/bug:** CVE-2022-4178 / `crbug.com/1376099`
- **Component:** **Mojo** (the renderer↔browser IPC/interface layer).
- **First fixed:** **108.0.5359.71** (2022-11-29).
- **Renderer→browser boundary:** **Yes.** NVD wording is notable: *"remote attacker **who had compromised the renderer process**"* — i.e. this is a **post-renderer-RCE escalation into the browser process**, distinct from CVE-2022-4180 which requires an *extension*.
- **Public exploit/PoC:** **No public root-cause/PoC** found. Maturity = *patch-diff / code-audit port only*.
- **Triggerable from plain web content:** **Yes, after renderer compromise** (needs renderer RCE first, e.g. CVE-2022-3723); no extension or `chrome://` privilege required.
- **Sources:** [OSV](https://api.osv.dev/v1/vulns/CVE-2022-4178) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-4178) · [chromereleases 108](https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop_29.html)

### 4. CVE-2022-4180 — Use after free in Mojo (extension-gated)
- **CVE/bug:** CVE-2022-4180 / `crbug.com/1378564`
- **Component:** Mojo.
- **First fixed:** **108.0.5359.71**.
- **Renderer→browser boundary:** Yes, **but** requires *"an attacker who convinced a user to install a malicious extension"*. Extensions are **not available in Android WebView**, so this is effectively **not applicable** to the stated target (and not plain web content).
- **Public PoC:** none.
- **Sources:** [OSV](https://api.osv.dev/v1/vulns/CVE-2022-4180) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-4180)

### 5. CVE-2022-4190 — Insufficient data validation in Directory
- **CVE/bug:** CVE-2022-4190 / `crbug.com/1378997`
- **Component:** Directory handling (browser-process file access), same bug class as CVE-2022-3656.
- **First fixed:** **108.0.5359.71**. Medium severity.
- **Renderer→browser boundary:** **Yes** (file-system restriction bypass via crafted HTML).
- **Public PoC:** none; not flagged as in-the-wild. Lower priority than 3656 (no exploit evidence, no writeup).
- **Sources:** [OSV](https://api.osv.dev/v1/vulns/CVE-2022-4190) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2022-4190)

### 6. CVE-2022-4181 — Use after free in Forms (renderer-only, NOT an escape)
- **CVE/bug:** CVE-2022-4181 / `crbug.com/1382581`
- **Component:** Blink "Forms".
- **First fixed:** **108.0.5359.71**.
- **Renderer→browser boundary:** **No** — this is a Blink (renderer) UAF → renderer RCE primitive, not a boundary crossing.
- **Public PoC:** none.
- **Sources:** [OSV](https://api.osv.dev/v1/vulns/CVE-2022-4181)

### 7. CVE-2022-4182 — Fenced Frames policy bypass (not a UAF)
- **Component:** Fenced Frames. Fixed 108.0.5359.71. Medium. Not memory corruption, not a sandbox escape. Omit.
- **Sources:** [OSV](https://api.osv.dev/v1/vulns/CVE-2022-4182)

### 8. CVE-2022-3723 — V8 Turbofan logic bug (renderer-RCE *first stage*, already known to you)
- **CVE/bug:** CVE-2022-3723 / `crbug.com/1378239` (embargoed)
- **Component:** V8 Turbofan JIT (`kStoreInLiteral` fails to generalize a "None" FieldType → type confusion).
- **First fixed:** **107.0.5304.87** (2022-10-27). Exploited in the wild (found by **Avast**: Jan Vojtěšek, Milánek, Przemek Gmerek).
- **Renderer→browser boundary:** **No** — renderer RCE only; it is the *first stage* that then needs an escape (4135/4178/3656).
- **Public PoC:** **Yes — full PZ RCA** (Samuel Groß) with repro (needs `--allow-natives-syntax`/`--expose-gc` in the *published repro*, though the in-the-wild exploit was plain web content).
- **Sources:** [PZ RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-3723.html) · [chromereleases 107.0.5304.87](https://chromereleases.googleblog.com/2022/10/stable-channel-update-for-desktop_27.html)

### 9. CVE-2022-4262 — V8 type confusion (renderer-RCE first stage)
- **Component:** V8 (incorrect bytecode generation by the JS parser). **First fixed: 108.0.5359.94** (2022-12-02). 0-day in the Samsung Internet (Variston) chain, reported by Clement Lecigne (TAG). Renderer RCE only (not an escape). [PZ RCA exists](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-4262.html).
- **Sources:** [OSV](https://api.osv.dev/v1/vulns/CVE-2022-4262) · [chromereleases](https://chromereleases.googleblog.com/2022/12/stable-channel-update-for-desktop.html)

---

## The two documented late-2022 Android chains (TAG)

1. **Nov 2022 — Chrome on Android (ARM GPU), Italy/Malaysia/Kazakhstan** (commercial spyware, delivered via SMS bit.ly links):
   `CVE-2022-3723` (V8 renderer RCE) → **`CVE-2022-4135` (Chrome GPU sandbox escape, Android-only)** → `CVE-2022-38181` (ARM Mali GPU *kernel driver* EoP).
   Sources: [TAG blog](https://blog.google/threat-analysis-group/spyware-vendors-use-0-days-and-n-days-against-popular-platforms/) · [SecurityAffairs summary](https://securityaffairs.com/144174/hacking/exploit-chains-zero-day-spyware.html) · [PZ RCA 4135](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-4135.html).

2. **Dec 2022 — Samsung Internet, UAE (Variston/Heliconia):**
   `CVE-2022-4262` (V8, 0-day) → `CVE-2022-3038` (Network Service sandbox escape, n-day) → `CVE-2022-22706` (Mali kernel, n-day) → `CVE-2023-0266` (Linux kernel sound, 0-day).
   (Both kernel/Mali stages are out of scope for a *renderer→browser* report, included only for chain completeness.)

**CVE-2022-3656 (File System)** was a *separate* TAG-reported in-the-wild bug (fixed 2022-10-24, `107.0.5304.62`) from the same commercial-spyware activity window; it has **no public Project Zero RCA**, so its exact chain/platform pairing is less thoroughly documented than the 3723+4135 chain.

---

## Android WebView process-topology note (matters for CVE-2022-4135)

- In **full Chrome on Android**: separate browser / renderer / **GPU** / utility processes. CVE-2022-4135 is therefore *renderer → GPU process*.
- In **Android WebView**: the embedding app's process hosts the Chromium browser-side (`AwBrowserProcess`), and there is strong source-level evidence that WebView uses the **in-process command buffer** — the Chromium file `gpu/ipc/in_process_command_buffer.cc` carries the comment *"// scheduler for non-WebView cases"* (i.e. WebView decodes GL commands in-process rather than via a dedicated GPU process scheduler). See [gpu/ipc/in_process_command_buffer.cc](https://chromium.googlesource.com/chromium/src.git/+/ccab4bc38337ec3306b5f3847f7f88b358111309/gpu/ipc/in_process_command_buffer.cc) and the surrounding [`command_buffer_service.gypi`](https://chromium.googlesource.com/chromium/src/+/92dd777782cec8b8add8dcf2d4a3618c3ebbc21a%5E%21/gpu/command_buffer_service.gypi) build split.
  → For a **WebView** target, CVE-2022-4135 most likely executes **in the host/browser process**, making it a de-facto **renderer→browser** escape. (Verify the specific target build's `--in-process-gpu`/WebView configuration before relying on this.)

---

## Ranked shortlist (most promising for this target)

1. **CVE-2022-4135 (GPU validating-command-decoder heap overflow)** — highest public maturity (full PZ root-cause + working WebGL repro), Android-specific, part of a proven in-the-wild Android chain, and in WebView it lands in the host process → effectively renderer→browser.
2. **CVE-2022-3656 (File System data validation)** — the most direct *renderer→browser* file-restriction bypass, plain-HTML-triggerable, exploited in the wild (TAG), target vulnerable (fixed only in 107); port requires patch reverse-engineering (no public writeup).
3. **CVE-2022-4178 (Mojo use-after-free)** — a clean renderer→browser Mojo UAF fixed in 108 (target vulnerable), reachable once you have renderer RCE and needing no extension; port from patch/code-audit only (no public PoC).
