# PurrTol kernel-race assessment + epoll-UAF patch status (2026-09-30)

## Purpose

Assess whether the PurrTol kernel route — **CVE-2021-1048 (epoll UAF)** — is worth
pursuing against this Portal's kernel, and record exactly what PurrTol completed and
what is missing. Pulled from `amemefarmer/the-purrtol` (`portal-freedom/journal/`) and
confirmed against the local firmware dump.

## TL;DR

- **CVE-2021-1048 is unpatched on this device.** Confirmed by disassembling
  `ep_loop_check_proc` in the local firmware dump's kernel — it still uses the
  vulnerable non-safe `rb_next` traversal.
- The epoll-UAF route is a viable **kernel** target, and PurrTol wrote ~80% of it
  (race-test shellcode + confirmed primitives).
- It is **downstream of the renderer native-exec blocker**: the shellcode needs
  renderer RCE to run, and the escalation (v2) was never written.
- The renderer blocker is the **V8 10.6 `r1`-poisoning** in call_indirect — not seccomp
  and not W^X. PurrTol confirmed `mprotect + PROT_EXEC` is allowed by the renderer
  seccomp policy.

---

## 1. Kernel: CVE-2021-1048 confirmed vulnerable

### Method

- Decompressed `firmware/aloha_dump/boot/kernel` (gzip → ARM64 Image).
- Used `firmware/aloha_dump/kallsyms.txt` to locate `ep_loop_check_proc`
  (`0xffffff8008249eb8`; `_text = 0xffffff8008080000`; file offset = VA − _text).
- Disassembled the function with a minimal AArch64 decoder.

### Finding

`ep_loop_check_proc` traverses the `rbr` red-black tree with the loop update
`rbp = rb_next(rbp)` placed **at the loop top**, which is reached by branching back
*after* the recursive `ep_call_nested(... ep_loop_check_proc ...)` call:

```
loop:
    rbp = rb_next(rbp)        ; reads rbp->rb_right / rbp->rb_parent  <-- UAF site
    if (!rbp) break
    ... epi = rb_entry(rbp) ...
    ep_call_nested(...)       ; recursion may free the epitem (ep_remove/rb_erase)
    if (error == 0) goto loop
```

The CVE-2021-1048 fix saves `next = rb_next(rbp)` **before** the recursive call and
updates the loop with a register move (`rbp = next`), avoiding the post-recursion read.
That form is **absent** here → vulnerable.

### Build-date cross-check

- Local dump kernel: `Linux 4.4.153+ ... #1 SMP PREEMPT Tue Dec 3 17:41:53 PST 2024`.
- On-device `env_probe_version`: `Linux 4.4.153+ ... Sep 15 16:57:16 PDT 2023`.

The dump is *newer* than the device and still lacks the fix, so the older on-device
kernel is also vulnerable (same `4.4.153+` branch).

---

## 2. PurrTol gap analysis (from `portal-freedom/journal/`)

| Stage | Status |
|---|---|
| Renderer RCE — CVE-2020-16040 (Chrome 86 / V8 8.6) | ✅ 100% reliable, but **Chrome 86 ≠ this device's Chrome 106** |
| mprotect+jump → execute shellcode from wasm memory | ✅ 4/4 (journal 027) |
| Kernel primitives — clone/sendmsg/socketpair/epoll_ctl/`sched_setaffinity` | ✅ 4/4 (journal 028) |
| epoll-UAF v1 **race test** shellcode (`epoll_uaf.s`, 260 words) | written; **never device-tested** |
| epoll-UAF v2 **escalation** (addr_limit clobber → pipe kread/kwrite → cred patch) | **never written** |
| Root → enable ADB | ❌ not reached; project abandoned (day 18) |

### PurrTol's confirmed on-device facts (transferable)

- **Seccomp allows `mprotect + PROT_EXEC`** (journal 027: "mprotect_probe 2/2 R0=0").
- `AF_INET`/`socket` blocked (EPERM) — shellcode must be self-contained (no network).
- `userfaultfd`, `msgsnd`/`msgrcv` are `ni_syscall` (unavailable for race stabilization/spray).
- `add_key` at `0xffffff800832fa5c` available as an alternative spray.
- **No HW PAN on SD835 (ARMv8.0)** — fake kernel structs can live in userspace.
- KASLR: `CONFIG_RANDOMIZE_BASE=y`, but 4.4 AArch64 had no upstream KASLR (added 4.6) —
  likely a low-entropy/broken vendor backport; try pre-KASLR addresses first.
- Race reliability ~1–5%/attempt; 100–1000 iterations for near-certainty; failed races
  are generally clean (no panic).

### epoll-UAF race mechanism (journal 029)

`ep_loop_check_proc` traverses the epitem list non-safely. Race: parent
`close(epfd_inner)` frees epitems to SLUB (`epi_cache`/kmalloc-128) while child
`epoll_ctl(outer, ADD, …)` drives `ep_loop_check_proc`; freed epitem reclaimed by a
128-byte `sendmsg` `msg_control` spray. v2 would use a fake epitem → fake `eventpoll`
→ redirect kernel read → `addr_limit` clobber (at `thread_info+0x08`) → pipe
kread/kwrite → patch creds (UIDs=0, full caps, SELinux SID=1).

---

## 3. Why this is still blocked at the renderer

PurrTol's mprotect+jump worked on **Chrome 86 / V8 8.6**. This device runs
**Chrome 106 / V8 10.6**, where the call_indirect ABI differs:

- `PrepareCall()` runs `cache_state_.ClearAllCacheRegisters()`, so the cached
  memory-start is dropped; the marshaling then leaves a **V8-heap pointer in `r1`**.
- `r1` is not a wasm param register (`kGpParamRegisters = {r3,r0,r2,r6}`).
- Consequences (all on-device confirmed): direct `mprotect` → `len=r1` huge → ENOMEM;
  `syscall(125,…)` → `addr=r1` = heap ptr → SIGSEGV; memcpy src=r1 → wrong data.
- JIT literal-pool spray is also closed (Liftoff emits `f64.const` via `movw/movt`+`vmov`,
  no contiguous RX pool; TurboFan install is async and incompatible with the trigger's GC
  timing; no asm.js; Sparkplug disabled).

So the single open renderer lever is the **wasm code-memory RWX window race** (see §4).

---

## 4. Next lever: the wasm code-memory RWX window race

Open question (from `CVE2022_4262_NATIVE_EXEC_PLAN.md`): V8 allocates wasm code memory
RW, writes it, then flips it RX (`write_protect_code_memory = true`). If the RW phase
can be caught, the shellcode can be written directly into the already-executable code
section, sidestepping `r1` entirely.

### Mechanism (verified in V8 10.6 `wasm_wasm-code-manager.h` + `wasm-compiler.cc`)

- `WasmCodeManager::protect_code_memory_` = true ⇒ traditional mprotect switching.
- `CodeSpaceWriteScope(native_module)` makes the code space writable for the lifetime of
  the scope: ctor → `AddWriter()` + `MakeWritable(region)`; dtor (last writer) →
  flips all code back to write-protected (RX).
- It wraps `NativeModule::AddCode` + `PublishCode` (e.g. `wasm-compiler.cc:8146,8199`,
  `wasm-objects.cc:1499`). So the RW window is exactly the `AddCode`/`PublishCode`
  block.

### Two tiers, two windows

| Tier | Compile timing | RW window on | Exploitable? |
|---|---|---|---|
| Liftoff | synchronous (`new WebAssembly.*`) | JS thread (blocked) | ✗ — JS thread is inside the scope |
| TurboFan | async (tier-up, background thread) | background thread | ✓ — JS thread is free to `v8_write64` |

### The one open question

TurboFan's async install needs an **event-loop yield**, which runs GC. The CVE-2022-4262
bytecode-aging trigger + corrupted object are GC-sensitive (a 500 ms yield before the
trigger crashed the renderer). The race is viable **iff** the established
`addr_of`/`v8_read64`/`v8_write64` primitives survive the TurboFan-install yield. That
has not been tested and is the next concrete step.

---

## 5. Files / sources

- Local: `firmware/aloha_dump/boot/kernel`, `firmware/aloha_dump/kallsyms.txt`
- PurrTol journals: `portal-freedom/journal/027_mprotect_jump_confirmed.md`,
  `028_syscall_test_confirmed.md`, `029_epoll_uaf_v1_race_test.md`, `019_cve_research_alternative_paths.md`
- PurrTol payload: `portal-freedom/captive-portal/payloads/epoll_uaf.s`
- Repo: <https://github.com/amemefarmer/the-purrtol>
