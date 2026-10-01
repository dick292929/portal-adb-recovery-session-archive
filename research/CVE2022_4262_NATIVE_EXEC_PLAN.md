# CVE-2022-4262 → native-execution marker: assessment & plan

**Date:** 2026-09-29
**Target:** Portal 10-inch Gen 1 captive-portal WebView — Android 9 `PKQ1.191202.001`, Chrome `106.0.5249.126`
**Goal:** turn the confirmed JavaScript read/write primitive candidate into a bounded native-execution marker (getpid), then (gated) an environment probe.
**Status:** Phase 0 confirmed on-device (AArch32 + arbitrary native write); Phase 1 (V8/W^X pinning) complete at source level. **Native-execution marker (getpid) CONFIRMED on-device 2026-09-29** via deterministic direct code-pointer jump (see §2 deterministic-jump update).

### Stage-1 reproduction (2026-09-29, owner re-ran and pasted output)

A second, clean stage-1 run confirmed every claim with concrete values:

- `trigger_observed=true`, `array_length=48` (0x30) — the type-confusion trigger fires.
- `primitive_candidate`: `address_nonzero`, `recovered_object`, `same_object` all
  true — `addr_of`/`fake_obj` round-trip works.
- `pointer_model_hint=32-bit-layout`, `arraybuffer_layout_32=true`,
  `arraybuffer_layout_64=false`, `backing_store_upper32_nonzero=false` —
  **native AArch32 confirmed**.
- `backing_store_rw_{read,write,restore}_match=true` — `v8_write64`/`v8_read64`
  reach **native process memory** (the mmap'd backing store), cross-checked
  against `DataView`. This is the write-what-where primitive a native stage needs.
- `pressure_allocation_{attempts,failures}=6`, `bytes=0` — all six ~2 GiB
  allocations fail, yet the trigger still fires: the OOM-triggered GC still ages
  bytecode. **Gap 3 is therefore already satisfied empirically** (the trigger is
  reliable without a successful huge allocation).
- `heap_limit_bytes=1008000000` (~961 MiB) — the JS heap limit, the input for any
  future GC-induction tuning.

Layout fact pinned from V8 10.6.194 source (32-bit, no external code space):
**`JSFunction.code` is at offset `0x18`** (after map/properties/elements = 0x0c,
then `shared_function_info` 0x0c, `context` 0x10, `feedback_cell` 0x14). This is
the writable code-pointer field the corruption step targets.

---

## 1. Assessment — what the primitive actually is

The pinned public PoC (`mistymntncop/CVE-2022-4262`, blob `1f449ccb…`) is a
bytecode-aging type confusion. After the `0x30` array-length trigger it builds
four primitives:

- `addr_of(obj)` — object address (masked to low 32 bits, `& 0xFFFFFFFFn`).
- `fake_obj(addr)` — forge an object pointer at a chosen 32-bit address.
- `v8_read64(addr)` — read a 64-bit word at a chosen 32-bit address.
- `v8_write64(addr, val)` — write a 64-bit word at a chosen 32-bit address.

Two properties of this code matter for the port:

1. **The PoC is already "32-bit arithmetic."** `addr_of` discards the high 32
   bits; pointers are `ptr(addr) = addr | 1n` with no upper word; a JS object
   header is packed as `map | (props << 32n)` into one double. This is why the
   same source runs on pointer-compressed x64 *and* native 32-bit V8: in both
   cases the reachable addresses collapse to 32-bit values.

2. **The owner-reported run already demonstrated a write into native memory,
   not just intra-heap.** The `--probe-arraybuffer-backing-store-rw` step
   computed the ArrayBuffer backing-store pointer, called
   `v8_write64(backingStore, changedMarker)`, and cross-checked it against the
   same buffer's `DataView` value, then restored it. The backing store is an
   mmap'd region outside the V8 heap, so a matching write/read/restore there is
   direct evidence that `write64` reaches **arbitrary native process memory** —
   exactly the capability a native stage needs. (Owner-reported; not yet
   independently reproduced.)

**Pointer model.** The same run's `pointer_model_hint=32-bit-layout` means the
`JSArrayBuffer` `byte_length_`/`max_byte_length_` fields read as two consecutive
32-bit `size_t` values. `size_t` is 32-bit only on a 32-bit build, so this is
near-definitive evidence of a **native 32-bit (AArch32) WebView process**,
consistent with PurrTol's 32-bit ARM report and `navigator.platform=Linux armv8l`.
A 64-bit V8 with pointer compression still has 64-bit `size_t`, so it cannot
produce that hint.

**Consequence of 32-bit.** The 64-bit-only V8 sandbox (pointer-compression cage,
external pointer table, `external_code_space`) does not exist on a 32-bit build.
That removes the main desktop-Chrome-106 exploit barrier and leaves the 32-bit
WebView structurally closer to the Chrome-86 surface PurrTol already worked
against. The protections that *do* still apply and must be pinned are:

- **Wasm/JIT code-memory W^X** (`--wasm-write-protect-code-memory`,
  `--write-protect-code-memory`): whether generated machine code lives in RWX or
  RX memory in this exact arm32 build.
- **The Chrome OS sandbox / seccomp** around the renderer (unchanged by any of
  this; a renderer marker is not a sandbox escape).

---

## 2. The four gaps, and how to close each

### Gap 1 — ABI: effectively closed, one cheap confirmation

The `32-bit-layout` hint plus `backing_store_upper32_nonzero` already decide it:
on a pointer-compressed 64-bit build the backing-store pointer's high 32 bits
are nonzero (cage base), while a native 32-bit build reports a 32-bit backing
store with zero upper bits. **Confirm** `arraybuffer_layout_32=true`,
`arraybuffer_layout_64=false`, and `backing_store_upper32_nonzero=false` in the
owner's recorded report; that triplet is the ABI confirmation. No new device
step is needed to establish AArch32.

### Gap 2 — V8 build / W^X state: RESOLVED (source, no device)

Pinned to V8 **10.6.194** (the Chrome 106 release branch). Verified in
`src/flags/flag-definitions.h`, `src/heap/heap.cc`, `src/heap/memory-chunk.cc`,
and `src/wasm/wasm-code-manager.cc`:

- `DEFINE_BOOL(write_protect_code_memory, true, ...)` — JIT W^X **on**.
- `DEFINE_BOOL(wasm_write_protect_code_memory, true, ...)` — Wasm W^X **on**.
- Neither flag has an arch guard; `heap.cc` sets `write_protect_code_memory_`
  unconditionally, and `memory-chunk.cc` implements RX-by-default code pages with
  only transient RWX during patching. `wasm-code-manager.cc` allocates Wasm code
  RWX *during* compilation and withdraws write access (`SetWritable(false)`)
  when compilation finishes.

**Conclusion:** on this 32-bit (AArch32) WebView, both JIT and Wasm code memory
are write-protected (RX) by default. There is **no persistent RWX code page**
reachable from the write primitive, so the simple PurrTol Chrome-86 "write
shellcode into a RWX Wasm page and jump" path is **closed** for Chrome 106.

The exploit itself still does **not** need hardcoded offsets (it leaks maps
dynamically). The native stage only needs the layout of `JSFunction`/`Code`
(JIT instruction start) and `WasmInstanceObject`/exported function (jump table,
code entry, imported target). Because this is a 32-bit build with no external
pointer table, those code pointers are **direct fields in the writable V8 heap**,
which is what makes the pivot in Gap 4 possible.

### Gap 3 — trigger hardening: replace the 2 GiB request with bounded GC induction

The trigger already fires: the owner saw `arr1.length == 0x30` even though all
six `0x7fe00000` allocations failed. The failed allocation still runs V8's
OOM-triggered GC path, which advances the bytecode age; `flush_bytecode()`
needs only ~6 GCs (`bytecode_old_age=5`). So the "2 GiB" request is not
semantically required — it is just the PoC's crude way to force a major GC.

Hardening work: replace `gc_major()`'s single 2 GiB request with a **chunked
pressure schedule sized against the measured `heap_limit_bytes`** (the stage-1
report already returns it), forcing exactly 6 major GCs while keeping peak
allocation under a device-safe cap. This reuses the existing calibration-page
machinery (`WeakRef` + `FinalizationRegistry` signals) to *measure* per-chunk GC
onset first, then sets a schedule that reliably ages bytecode without a single
2 GiB allocation. It is a calibration refinement of `build_page()`, not a new
exploit.

### Gap 4 — code-execution primitive: call path pinned (research, no device)

`CodeStubAssembler::GetCodeEntry` (V8 10.6) settles the 32-bit call path. On
32-bit (no `V8_EXTERNAL_CODE_SPACE`) it is:

```cpp
TNode<IntPtrT> object = BitcastTaggedToWord(code);
return IntPtrAdd(object, IntPtrConstant(Code::kHeaderSize - kHeapObjectTag));
```

i.e. the call entry is `untag(code) + Code::kHeaderSize`, computed **directly
from the Code object address with no Code-field read**. (The `code_entry_point`
cached field only exists on 64-bit external code space.)

**Corruption formula.** Set `JSFunction.code` (offset `0x18`) to the tagged value
`T = (S - kHeaderSize) | 1`, where `S` is an RX address holding sprayed bytes.
Calling the function then jumps to `untag(T) + kHeaderSize = S`. No fake Code
object is required, and no write is directed at an RX page.

**kHeaderSize (arm32).** Constant pool enabled, `kCodeAlignment = 32`. Fixed
header = map(4) + 4 tagged(16) + 10 int(40) = 60, padded to 64 ⇒
`kHeaderSize ≈ 0x40` (0x3c/0x44 remain candidates; confirm on-device by scanning
for a sprayed constant, which removes any need to trust this arithmetic).

**Remaining piece — JIT-spray.** Encode the ARM32 `getpid` words as float/double
constants so TurboFan emits them into the RX literal pool, find `S`, corrupt
`code`, call. Result channel options: (a) return the PID as an Smi in `r0` (the
call's JS return value), or (b) write the PID to a known ArrayBuffer backing
store whose address is embedded in the sprayed bytes. The literal-pool emission
order is compiler-determined, so the constant layout will likely need one or two
on-device iterations.

**UPDATE (on-device, 2026-09-29): the literal-pool JIT-spray is CLOSED.** Verified
on-device plus V8 10.6.194 source:

- TurboFan is the *only* tier that materializes a double constant as a contiguous
  8-byte entry in an RX literal pool. Its install is **async** (finalize runs as a
  main-thread task), so it needs an event-loop yield.
- The CVE-2022-4262 bytecode-aging trigger breaks if any GC runs before it; a
  500 ms yield before the exploit crashed the renderer. The async TurboFan install
  and the trigger's heap/GC timing are mutually exclusive in a single page.
- Wasm **Liftoff** (synchronous) emits `f64.const` via `movw`/`movt`+`vmov`, not a
  pool — confirmed by finding the real Wasm code entry through the object graph
  (`WasmInternalFunction.call_target`, `native_wasm_target_valid=true`) yet
  scanning 0x800 bytes for the 5 words yields `word_hits=0`.
- **asm.js was removed from V8 10.6** (no `--validate-asm` flag in
  `flag-definitions.h`; `AsmWasmData` is vestigial). A `"use asm"` function
  silently falls back to normal JS, so there is no synchronous TurboFan path.
- Sparkplug (JS baseline) is disabled by default on Android
  (`ENABLE_SPARKPLUG_BY_DEFAULT false`), so the JS hot loop goes straight to async
  TurboFan; there is no synchronous JS codegen tier either.

**Pivot (open options):** (1) direct code-pointer jump to an existing native
function — leak a library base. Path (all 32-bit, tagged-pointer reads):
`WasmExportedFunction -> SFI(+0x0c) -> function_data(+0x04) ->
WasmInternalFunction(+0x04) -> ref/instance(+0x08) -> WasmInstanceObject.
isolate_root(+0x3c)`. The stored value is `&IsolateData + kRootRegisterBias`;
on ARM32 `kRootRegisterBias == 0xFFF` (`constants-arm.h`), so subtract `0xFFF`
to recover the `IsolateData` base (this is why the raw field is misaligned).
`isolate_root` points to the V8 `IsolateData` mmap (not a library), so the
library leak comes from its **builtin entry table** (an inline array of
~`Builtins::kBuiltinCount` raw pointers into libchrome.so's embedded builtins).
Read the first entry, then scan backward for the `\x7fELF` magic to pin the
library base, then resolve `getpid`. (2) ROP against a leaked library;
(3) the Wasm compilation RWX race.

**UPDATE (2026-09-29 — deterministic libc leak + bionic offsets):**

The `ExternalReferenceTable` (embedded in `IsolateData`, right before
`thread_local_top`) holds direct `libc.so` function pointers:
`ref_addr_[kSize]` then `is_initialized_(u32=1)` then `dummy(u32=0)`, with
`ref_addr_[0]==0`. `printf_function` is `EXTERNAL_REFERENCE_LIST` entry #74 →
table index 74 → byte offset 296, and `external-reference.cc` defines it as
`FUNCTION_ADDR(std::printf)` = libc `printf` (Thumb).

**Signature correction (on-device + source):** `ref_addr_[1] == abort_with_reason`
is a `FUNCTION_REFERENCE` to a libchrome C++ function, and on this build it is
**ARM-mode (even)** — the device's libchrome.so exports a mix of Thumb (3773) and
ARM (372) functions, and `abort_with_reason` is one of the ARM ones. So the old
signature `[0, Thumb, even, even]` never matched the real table (it only found
false positives in the even builtin run and in post-object padding). The working
scan is: (1) locate `is_initialized_(u32=1)` by the `[1, 0, even_ptr]` marker
(`thread_local_top.isolate_` right after it), then (2) scan **forward from
offset 120** (the `roots_table` is all tagged/nonzero) for the first zero word
whose index-1 is a valid pointer and index-74 is Thumb, i.e. `ref_addr_[0]`.

**CONFIRMED on-device (2026-09-29):** `libc_extref_init_off=8936`
(`is_initialized_`), `libc_extref_table_off=3276` (table start → 1415 entries;
`roots_table` = `[120,3276)` = 789 entries), `printf` @ `3276+296=3572`
`Thumb+valid`. The "second run" `[8868,8932]` matches the table's last 17 entries.
So `printf` is leaked = `libc_base + 0x6d539`.

**Bionic offsets — exact, from the device's own 32-bit `libc.so`**
(`firmware/aloha_dump/system/system/lib/libc.so`, ELF32 ARM EABI5, not stripped):

- `printf`  st_value `0x0006d539` (Thumb, bit0=1)
- `getpid`  st_value `0x0001f6a5` (Thumb, bit0=1)
- `__getpid` st_value `0x00060a40` (even; raw syscall impl `getpid` falls back to)

Both are Thumb, so `getpid = printf - 0x4de94` (bit0 carries through).

**Deterministic jump (implemented as `--native-getpid-direct`):** the page leaks
`printf`, computes `getpid = printf - 0x4de94`, overwrites a wasm `g()->i32`
function's `WasmInternalFunction.call_target` (`internal+0x04`) with `getpid`
(read-modify-write 8 bytes to preserve `ref@+0x08`), calls `g()`, and lets the
JS-to-wasm wrapper convert the i32 return (pid) to a clean JS number, then
restores `call_target`. Reported as `native_direct_result` (renderer PID) plus
`native_direct_getpid_valid` / `native_direct_call_target_valid` /
`native_direct_result_is_number`. Fallback if `call_target` is baked into the
wrapper (result would be the wasm constant `42`): overwrite `JSFunction.code`
(`0x18`) with `(getpid - 0x40)|1` instead.

**CONFIRMED on-device (2026-09-29): `native_direct_result=21404`** (plus
`native_direct_getpid_valid=true`, `native_direct_call_target_valid=true`,
`native_direct_result_is_number=true`, `native_direct_attempted=true`). The
result is a plausible renderer PID — not `42` and not `0` — so:
(1) the `printf`→`getpid` leak arithmetic is correct; (2) `call_target` is **not**
baked into the wrapper (the overwrite genuinely redirected control flow); and
(3) a Thumb leaf `getpid` executes cleanly as a call target and returns a real
PID. This is the first confirmed native-code-execution marker on the device.
**The bounded native marker (getpid) objective is met.**

---

## 3. Native-execution mechanism (confirmed) + Phase 5 env probe

### Confirmed mechanism (getpid)

The working primitive is a **direct code-pointer jump**, not JIT-sprayed
shellcode. It calls an existing libc leaf through a wasm export's
`WasmInternalFunction.call_target`:

1. Leak `printf` (Thumb) from the `ExternalReferenceTable` (§2).
2. Derive the target entry from `printf` by a fixed difference (both Thumb, so
   bit0 carries): `getpid = printf - 0x4de94`.
3. Overwrite the wasm `g()->i32` function's `call_target` (8-byte
   read-modify-write to preserve `ref@+0x08`) with the target entry.
4. Call `g()`; the JS-to-wasm wrapper converts the i32 in `r0` to a JS number.
5. Restore `call_target`.

Confirmed on-device with `native_direct_result=21404`. This proves the wrapper
jumps through `call_target` at call time (not baked in), and that a plain AAPCS
leaf runs correctly as a call target.

### Phase 5 — environment probe (UID + /proc/version), implemented

The same call-target overwrite generalises to **any** libc entry that follows
AAPCS (preserves r4–r11 and r7) — including ones with arguments. A wasm
`f(a,b,c)->i32` export lets the wrapper place `a,b,c` in `r0,r1,r2` before the
jump, so argument-taking functions become callable. Pinned from the device
libc.so dynsym (raw `st_value`, Thumb bit included), each relative to the
leaked `printf`:

| fn | st_value | mode | diff from printf |
| --- | --- | --- | --- |
| `getuid` | `0x61440` | ARM (even) | `printf - 0xc0f9` |
| `open`   | `0x242d5` | Thumb | `printf - 0x49264` |
| `read`   | `0x61940` | ARM (even) | `printf - 0xbbf9` |
| `close`  | `0x1e115` | Thumb | `printf - 0x4f424` |

Disassembly confirms all four are well-behaved: `getuid`/`read` are direct
`svc` leaves (`getuid32`=199, `read`=3) that save/restore `r7`; `open` is a
wrapper calling `__openat(AT_FDCWD, path, flags, mode)` (reads a relocated GOT
entry — fine, libc is loaded normally); `close` calls an internal `__close`
helper. `getuid`/`read` being ARM-mode also proves the wrapper's jump handles
even (ARM) targets, not just Thumb.

**Probe flow (`--native-env-probe`):** leak `printf` → derive the four entries
→ build a wasm module exporting `g()->i32` and `f(a,b,c)->i32` → resolve each
function's `call_target` **fresh per call** (avoids a cached raw address going
stale across the ArrayBuffer allocation's moving GC) → call `getuid` → write
`"/proc/version\0"` into a 0x1000 ArrayBuffer, resolve its backing store →
`open(path, O_RDONLY=0)` → `read(fd, buf+0x400, 255)` → `close(fd)` → read the
version bytes back through the Uint8Array view (same backing store) → report.

**Report fields:** `env_probe_attempted`, `env_probe_{getuid,open,read,close}_valid`,
`env_probe_call_target_valid`, `env_probe_getuid_result` (UID), `env_probe_open_fd`,
`env_probe_read_count`, `env_probe_close_result`, `env_probe_version` (printable
ASCII, ≤255 bytes). No raw addresses or arbitrary memory contents are reported.

**Result channel (JS↔native):** results flow back through the wasm wrapper's
i32→number conversion (`r0`), and the version bytes flow through the ArrayBuffer
backing store — the same native-write visibility already proven by the RW
round-trip probe. `getuid`/`open`/`read`/`close` are read-only and bounded (no
process/file/network side effects beyond opening and reading `/proc/version`).

**CONFIRMED on-device (2026-09-29, run 1):** `env_probe_getuid_result=99015`
— the ARM-mode `getuid` executed cleanly and returned a real UID in the
**isolated-process range** (`Process.FIRST_ISOLATED_UID = 99000`), i.e. the
renderer is `u0_i15`. `env_probe_open_fd=-1` with **no crash**: `open` →
`__openat` → `openat` is a *filesystem* syscall, and the Chrome-106 renderer
`baseline_policy.cc` (`sandbox/linux/seccomp-bpf-helpers/baseline_policy.cc`)
returns `Error(EPERM)` for `IsFileSystem()` syscalls (only `uname` is
explicitly `Allow()`ed). So the renderer **cannot open files by path** — a
deliberate sandbox boundary, now characterized empirically.

**v2 (`--native-env-probe`, updated):** since `openat` is seccomp-denied, the
kernel version is obtained via `uname` (ARM, `0x62158`, direct `svc #122`,
explicitly `Allow()`ed) instead — it writes `struct utsname` into the backing
store, giving `sysname`/`release`/`version`/`machine` (the same data
`/proc/version` carries) *and* serving as the argument-passing test (one
pointer in `r0`). The `open` attempt is kept and its errno is captured via
`__errno` (Thumb, `0x1cf7f`, `mrc p15,c13 + 8` → `&errno`, no syscall) to prove
the denial is `EPERM` (1) rather than a bad pointer (`EFAULT`, 14). Offsets:
`uname = printf - 0xb3e1`, `__errno = printf - 0x505ba`.

**CONFIRMED on-device (2026-09-29, run 2 — CRASH):** the `uname` call crashed
the renderer (no report). `uname` is **not** the cause via seccomp — the
renderer policy `sandbox/policy/linux/bpf_renderer_policy_linux.cc` explicitly
`Allow()`s `__NR_uname` (and `__NR_sysinfo`, `__NR_times`). The crash is the
**ARM-target-through-the-3-param-wrapper** combination: `getuid` (ARM) through
the 0-param `g` worked, and `open` (Thumb) through the 3-param `f` worked, but
`uname` (ARM) through `f` crashed. This is a mechanism limitation, not a
sandbox denial.

**v3 (diagnostic):** to isolate the failure, the probe now (1) calls `getuid`
through `f` (ARM + 3-param, dummy args) as a canary — reported as
`env_probe_getuid_arg_result` — and gates `uname` on that succeeding, and
(2) emits synchronous `/api/stage` markers (`env_getuid_g_done`,
`env_getuid_f_done`, `env_uname_done`, `env_probe_done`) so a crash is
localized. If `env_getuid_f_done` is the last marker, the ARM+3-param wrapper
is broken; if `env_uname_done` is missing, `uname` itself is the issue.

**CONFIRMED on-device (2026-09-29, run 3 — CRASH):** `env_getuid_g_done` and
`env_getuid_f_done` both emitted, then crash before `env_uname_done`. So the
ARM+3-param wrapper **does not** crash (`getuid`-via-`f` completed); the crash
is `uname`-specific. `getuid` ignores its args while `uname` *reads* `r0` as a
pointer and writes 390 bytes to it — so the args are **not landing in `r0`**
where AAPCS functions read them, and `uname` writes the `utsname` struct over a
garbage address (a V8 heap object) → crash.

**v4 (register-convention canary):** add `abs` (Thumb, `0x5fb75`, pure leaf
`r0 = |r0|`, no syscall/memory — crash-safe) and call it through `f` as
`abs(-1000,-2000,-3000)`. The result reveals which parameter position lands in
`r0`: `1000` ⇒ position 0 (AAPCS), `2000` ⇒ position 1, `3000` ⇒ position 2,
anything else ⇒ params never reach `r0` (stack-passed or receiver-occupied).
`uname` is now gated on `abs == 1000`. Reported as `env_probe_abs_result` and
via a synchronous `env_abs=<n>` stage marker so the value survives a later
crash.

**CONFIRMED on-device (2026-09-29, run 4):** `env_abs=1000`. **Arguments DO
land in `r0` (position 0 = AAPCS).** The run-3 "args never reach r0" theory is
disproven. So `uname`'s crash is a *buffer-address* problem, not a register
problem.

**Disassembly of `uname` (0x62158, ARM):** `mov r12,r7; mov r7,#122; svc 0;
mov r7,r12; cmn r0,#4096; bxls lr; …` — a **pure leaf, structurally identical
to `getuid`** (save/restore r7 via r12, no stack access, return via `bx lr`).
The only difference is that `uname` reads `r0` as a pointer and the kernel
writes 390 bytes (`new_utsname`) to it. Crucially, a *bad* buffer address
would make the syscall return `-EFAULT` (errno 14), **not crash** — so the
crash implies the address in `r0` was *valid-writable-but-wrong* (e.g. a V8
heap object), i.e. the address bits were mangled before `uname` read them.

**Backing-store resolution re-verified against V8 10.6 source**
(`src/objects/js-array-buffer.tq`): `JSArrayBuffer` fields are `byte_length`
(`uintptr`), `max_byte_length` (`uintptr`), `backing_store` (`RawPtr`),
`extension`, `bit_field`. The 32-bit scan (adjacent `0x1000`/`0x1000` pair →
`backing_store` at +8) is therefore **correct**, matching the earlier
`backing_store_rw_*_match=true` proof. The resolved address is not the bug.

**v5 (i32-conversion canary + signed-address fix):** the remaining suspect is
the wasm JS→i32 conversion of an *unsigned* 32-bit address with bit 31 set
(Android heap backing stores are typically ≥ `0x80000000`). If the JS→wasm
wrapper truncates (`TruncateDoubleToInt32`) instead of wrapping (`ToInt32`),
the unsigned value saturates to `INT32_MIN` and `uname` writes to `0x80000000`.
Fix + canary: (1) pass every address arg through `signed32(v)` =
`v >= 0x80000000 ? Number(v) - 0x100000000 : Number(v)`, so the value is
already within `[-2^31, 2^31-1]` and wrap/truncate agree; (2) add a wasm
identity export `id(a)->i32` (`local.get 0`) and call it normally with the
unsigned `Number(backing)` to observe the wrapper's conversion. Reported as
`env_probe_backing_rt_kind` (0=not-attempted, 1=match/wrap, 2=truncated→
`INT32_MIN`, 3=other), `env_probe_backing_rt_match`
(`rt === signed32(backing)`), `env_probe_backing_signed` (bit 31 set) — the
kind code avoids leaking the raw address — and via `env_backing_resolved` /
`env_backing_rt_match` synchronous stage markers. Outcomes: `match=false` +
`env_uname_done` ⇒ truncation confirmed, fix works; `match=true` ⇒ conversion
was never the bug (rethink); no `env_uname_done` with the markers present ⇒
`uname` still crashes (different cause).

**CONFIRMED on-device (2026-09-29, run 5 — CRASH before `env_backing_resolved`):**
the new `env_backing_resolved` marker **did not fire**, so the crash is **not**
`uname` at all — it is in the buffer-setup region that runs between `env_abs`
and `env_backing_resolved` (`new ArrayBuffer(0x1000)` → `new Uint8Array` →
`addr_of(envBuf)` → the `v8_read64` scan). The identical allocation + `addr_of`
+ scan in the pointer-model probe (a `0x2000` buffer) succeeds because it runs
**before** the `call_target`-overwrite native calls; the env probe ran it
**after** `getuid`/`abs` via `f`, and that late heap state is what faults. The
run-2/3/4 "uname crashed" attribution was therefore wrong (uname never ran).

**v6 (allocate/resolve buffer before native calls + per-statement markers):**
move `envBuf`/`envView` allocation, the `addr_of(envBuf)` backing scan, and the
`signed32`/`id` round-trip canary to the **top** of the env probe — before
`getuid`/`abs` — so they run against the clean pre-native heap that the
pointer-model probe proved. The backing-store pointer (a malloc'd off-heap
address) is stable across any GC, so resolving it early is safe; `envView` keeps
`envBuf` alive through the late reads. Added `env_buf_alloc`/`env_buf_view`/
`env_buf_addrof` markers to localize any remaining fault. If run 6 emits all
markers through `env_probe_done`, the buffer allocation was the trigger and
`uname` should now run (→ `env_probe_version`). If it stops at
`env_buf_alloc`/`env_buf_view`/`env_buf_addrof`, the allocation/`addr_of` path
itself faults regardless of timing.

**CONFIRMED on-device (2026-09-29, run 6 — CRASH before `env_abs`):** the early
buffer path now **works** — `env_buf_alloc`, `env_buf_view`, `env_buf_addrof`,
`env_backing_resolved=true`, and `env_backing_rt_match=true,kind=1,signed=false`
all fired. Two conclusions: (1) the wasm JS→i32 conversion **wraps correctly**
(`kind=1`), and the backing address had bit 31 **clear** (`signed=false`), so the
signed-address/truncation theory is disproven and moot; (2) the crash moved to
the **abs canary** (after `env_getuid_f_done`, before `env_abs`) — i.e. the
first run where the `id` round-trip call actually executed. Across runs 1–6 the
pattern is: **more native calls (`callViaTarget` overwrites) + more allocations
→ crash, at a shifting point.** Run 1 (getuid-g + open-f = 2 native calls)
succeeded; runs with 3 native calls + extra wrappers/allocations crash.

**v7 (minimal native-call path):** drop the now-redundant canaries — `getuid`-via-
`f` (ARM+3-param proven), `abs` (args-reach-r0 proven = 1000), and the `id`
round-trip (wrap proven = kind 1) — and run the goal directly with **two native
calls**: `getuid`-via-`g` (sanity) then `uname`-via-`f`. The `abs == 1000` gate
is removed (that fact is already established). Removed open/read/close too
(`open` is always EPERM, so it can never read `/proc/version`). Report fields for
the removed probes stay at their "not attempted" defaults.

**CONFIRMED on-device (2026-09-29, run 7 — ✅ SUCCESS, Phase 5 MET):** all
markers fired through `report_sending`, and the report carries the goal:

- `env_probe_uname_result=0`, `env_probe_uname_valid=true` — `uname` ran.
- `env_probe_version="Linux 4.4.153+ #1 SMP PREEMPT Fri Sep 15 16:57:16 PDT 2023 armv8l"`
  → **kernel `4.4.153+`** (vendor-backported build dated 2023-09-15), machine
  `armv8l` (32-bit userland on ARMv8), `SMP PREEMPT`.
- `env_probe_getuid_result=99021` — **isolated process** (UID in the `99xxx`
  `FIRST_ISOLATED_UID` range; run 1 saw `99015`, so the isolated slot varies per
  renderer instance, but every sample is ≥ `99000`).

**Root cause of the run-2…6 crashes:** allocating the buffer and running extra
native calls (`getuid`-via-`f`, `abs`, the `id` round-trip) *after* the first
`call_target` overwrite faults the renderer — a native-call/GC interaction, not
`uname`, not the buffer address, and not the i32 conversion. The minimal path
(buffer resolved **first**, then exactly two native calls `getuid` + `uname`)
succeeds. `uname` (a pure `svc #122` leaf) writes its `utsname` into the backing
store with the argument in `r0`, proving **argument-passing and native write to
a JS buffer both work**.

---

## 3.6 Phase 6 — sandbox surface & escalation (started)

**Seccomp surface (Chrome 106 renderer, from source — `bpf_renderer_policy_linux.cc`
+ `baseline_policy.cc` + `syscall_sets.h`):** the allow-list is narrow and
rendering-oriented.

- **Info (proven):** `uname`, `sysinfo`, `times`, `getcpu`, `getpid/gettid/getuid/
  geteuid/getppid/getresuid…`, `clock_gettime/getres` (restricted), `sched_get*`.
- **Memory:** `mmap`/`mmap2` and `mprotect` are **restricted (W^X)**; `munmap`,
  `mremap` (explicit Allow), `brk`, `mincore`, `madvise` (restricted set),
  `mlock*`; `memfd_create` (Allow, for Mojo).
- **Fd/IO:** `read/write/readv/writev/pread64/pwrite64/lseek`, `close/dup/dup2/
  dup3`, `fcntl` (restricted), `fsync/fdatasync/ftruncate`, `epoll_*`, `eventfd`,
  `poll/select`.
- **IPC:** `socketpair` AF_UNIX only; `getsockopt/setsockopt` SO_PEEK_OFF only.
- **Threads/signals:** `clone` (threads only, fork→EPERM), `futex` (restricted),
  `rt_sig*`, `set_robust_list`.

**Denied:** filesystem (`open/openat/stat/access`…→EPERM), network (`socket/
connect/bind`→SIGSYS), exec (`execve`→SIGSYS), process creation (`fork/vfork`→
EPERM), privilege change (`setuid/setgid/setres*`→EPERM), `prctl` (restricted),
`kill/tgkill` (own pid only), seccomp/SysV → EPERM. Everything else → SIGSYS.

**Conclusion:** no trivial syscall escape; native exec is strictly inside the
isolated renderer. Escalation options: (A) kernel exploit via an allowed syscall
(4.4.153+ has many known CVEs); (B) Chromium 106 renderer→browser IPC escape;
(C) device-specific captive-portal WebView surface (intents/schemes) + lock state.

### Phase 6A — Door A: renderer → browser (system UID)

**Goal:** escape the isolated renderer into the `CaptivePortalLogin` browser
process (system UID), then fire the exported `com.facebook.alohaapps.settings`
`DEBUG_TAB`/`PROD_DEBUG_TAB` activity or write `Settings.Global.ADB_ENABLED`.

**Why not direct:** seccomp denies `open` (no `/dev/binder`), and `ioctl` is
restricted to `TCGETS/FIONREAD/DMA_BUF_SYNC` — so `BINDER_WRITE_READ` → SIGSYS.
Direct `startActivity`/binder from the renderer is impossible; the browser is
the shortest hop that already holds the privilege.

**New libc offsets (printf-relative, from `libc.so` dynsym; raw st_value with
Thumb bit):**

| symbol | raw st_value | mode | rel printf |
| --- | --- | --- | --- |
| `getsockname` | 0x613f8 | ARM (even) | `printf - 0xC141` |
| `getpeername` | 0x612d8 | ARM | `printf - 0xC261` |
| `fstat`/`fstat64` | 0x611b8 | ARM | `printf - 0xC381` |
| `fcntl` | 0x701e5 | Thumb | `printf + 0x2CAC` |
| `getsockopt` | 0x61418 | ARM | `printf - 0xC121` |
| `setsockopt` | 0x61e40 | ARM | `printf - 0xB6F9` |
| `getppid` | 0x61318 | ARM | `printf - 0xC221` |
| `getresuid` | 0x61378 | ARM | `printf - 0xC1C1` |
| `sysinfo` | 0x61ff8 | ARM | `printf - 0xB541` |

**Recon step (next):** enumerate open fds via `getsockname(fd, buf, &len)`
(ARM, 3-param — fits the existing `f` wrapper). Return `0` ⇒ socket, `-ENOTSOCK
(-88)` ⇒ open non-socket (binder/chardev/pipe), `-EBADF (-9)` ⇒ closed. For
sockets, read the `sa_family` (first 2 bytes) and `sun_path` prefix to identify
the Mojo/WebView channel. Native-call fragility (runs 1–6) means the loop must
allocate the buffer once and reuse one wrapper; fd range is kept small (3–7)
until the call-count limit is characterized.

### Phase 6A — candidate selected: CVE-2022-4135 (GPU validating-command-decoder heap overflow)

Research (see `chrome106-android-renderer-browser-escapes.md`) shortlisted the
late-2022 renderer→browser escapes fixed in 107/108 (target 106.0.5249.126 is
vulnerable to all of them). Ranked:

1. **CVE-2022-4135** — `gpu::command_buffer::TextureManager::SetLevelCleared`
   OOB write on the `level_infos` vector (non-linear overflow, controlled
   offset). Full Project Zero RCA (Sergei Glazunov) + 3-line WebGL2 repro. TAG
   in-the-wild Android chain: `3723 (V8) → 4135 (GPU escape) → 38181 (Mali
   kernel)`. In Android **WebView** the command buffer runs **in-process in the
   host/browser process** (`gpu/ipc/in_process_command_buffer.cc` "scheduler for
   non-WebView cases"), so for us it lands in `CaptivePortalLogin` = **system
   UID**. **This is the Door A escape.**
2. CVE-2022-3656 (File System data validation) — renderer→browser file bypass,
   in-the-wild, but **no public RCA/PoC** (patch RE only).
3. CVE-2022-4178 (Mojo UAF) — clean renderer→browser UAF, fixed 108, **no PoC**
   (patch-diff only).

**Key reachability preconditions for 4135** (all verifiable cheaply):

- The bug is in the **validating** command decoder, not the passthrough decoder.
  PZ's own `repro.diff` forces `PassthroughCommandDecoderSupported() = false`,
  so on modern 106 the default is passthrough — but older GPUs (Android 9
  Adreno) fall back to validating. Detect via the GL backend string
  (`UNMASKED_RENDERER_WEBGL`: native `Adreno` ⇒ validating; `ANGLE` ⇒
  passthrough).
- The trigger uses Chromium-private APIs (`SharedImageInterface::CreateSharedImage`
  → `CreateAndTexStorage2DSharedImageCHROMIUM` → framebuffer-attach at level 1 →
  `DiscardFramebufferEXT`), **not reachable from plain JS** — the PZ repro
  patches Blink's `blendColor` to inject them. ⇒ **requires renderer RCE to
  drive, which we already have** (Phase 4/5 native exec).
- Needs `EXT_discard_framebuffer` + a WebGL2 context.

**First step (implemented):** `--probe-webgl` standalone page reports WebGL2
availability, the GL backend strings, `EXT_discard_framebuffer`, and
software-vs-hardware rendering — no native stage, no memory writes. If it shows
native Adreno + WebGL2 + `EXT_discard_framebuffer`, proceed to port/weaponize
4135 (trigger via renderer RCE → OOB → "corrupted memory bucket" leak for ASLR →
ROP in the system-UID browser process).

**PROBE RESULT (2026-09-30, on-device) — 4135 REACHABLE:**

- `webgl2_supported=true`, `webgl2_software_rendering=false` (hardware).
- `webgl2_unmasked_vendor="Qualcomm"`, `webgl2_unmasked_renderer="Adreno (TM) 540"`
  → **native GLES, no ANGLE ⇒ the validating command decoder is active** (the
  bug's decoder). Also resolves the SoC discrepancy: **Adreno 540 = Snapdragon
  835 (MSM8998)**, not SDM660/Adreno 512.
- `webgl2_version="WebGL 2.0 (OpenGL ES 3.0 Chromium)"`.
- `webgl2_discard_framebuffer=false` — the *JS* `EXT_discard_framebuffer`
  extension is absent, but this does **not** block the trigger: the repro calls
  `GLES2Interface::DiscardFramebufferEXT` directly (a core command-buffer
  command), not the JS extension, and we reach it via renderer RCE.
- `webgl2_max_texture_size=4096` (a cap; not relevant — the trigger uses 32×32).

**Decision:** proceed to port/weaponize CVE-2022-4135. Next phases:
B1 reach `GLES2Interface`/`SharedImageInterface` from the JS WebGL context via
renderer RCE (Blink object-graph walk); B2 drive the trigger sequence and
confirm the browser process (CaptivePortalLogin) OOB-crashes; B3 weaponize
(corrupted memory bucket → ASLR leak → ROP in system UID); B4 enable ADB.

## 4. Staging plan (phased, gated, one-shot)

| Phase | Kind | Action | Gate to proceed |
| --- | --- | --- | --- |
| 0 | device, read-only | ✅ Confirmed 2026-09-29: AArch32 triplet, heap limit ~1.008 GB, native backing-store RW. | Done |
| 1 | research | ✅ Pin V8 (`10.6.194`) and settle W^X (Gap 2): **W^X is ON for JIT and Wasm.** | Done |
| 2 | device, read-only | ✅ Confirmed 2026-09-29: `jsfunc`/`wasm` `code` field at `0x18` is a valid tagged pointer to a Code object in a separate RX region (`*_valid` and `*_region_far` all true). | Done |
| 3 | device, bounded | Trigger-hardening calibration (GC induction vs `heap_limit_bytes`). No native stage. | 6-GC schedule reliable |
| 4 | device, one-shot | ✅ Bounded getpid marker confirmed 2026-09-29 via **direct code-pointer jump** (leak `printf`, compute `getpid`, overwrite wasm `call_target`) — `native_direct_result=21404`. JIT-spray path is closed; see §2. | `getpid` marker confirmed — **MET** |
| 5 | device, one-shot | ✅ **MET 2026-09-29**: renderer is an **isolated process** (`getuid=99021`, ≥`99000`); kernel **`4.4.153+`** (`armv8l`, `SMP PREEMPT`, 2023-09-15) via `uname`. Arg-passing into `r0` and native write to a JS buffer both proven (§3). | `getpid` confirmed — **MET** |

---

## 5. Risks & discipline

- Large-allocation steps and the final code-pointer corruption can terminate the
  WebView or reboot the Portal; they are one-shot and owner-attended. No write is
  directed at an RX code page (W^X is on), so the corruption target is a writable
  heap pointer, not executable memory.
- Keep the one-shot gating, drop-privileges-after-bind, no-raw-pointer report,
  and CSP hardening already in place.
- All results remain owner-reported until independently reproduced; a renderer
  getpid marker is **not** sandbox escape, Android access, or ADB, and must not
  be labelled as such.
