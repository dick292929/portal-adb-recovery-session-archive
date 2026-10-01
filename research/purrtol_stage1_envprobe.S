/*
 * PurrTol follow-up: bounded ARM32 renderer-environment probe.
 *
 * Entry ABI: r4 points to the PurrTol WebAssembly memory mapping. The payload
 * records only getpid(), getuid32(), and a bounded read of /proc/version.
 * It does not read process maps, device nodes, kernel pointer settings, or
 * credentials belonging to other processes, and performs no writes outside
 * its WebAssembly mapping.
 *
 * Result words are compatible with the retained PurrTol page decoder:
 *   wasm_mem+0x1408: /proc/version byte count (0 on read failure)
 *   wasm_mem+0x140c: PID
 *   wasm_mem+0x141c: real UID
 *   wasm_mem+0x1420: negative open/read errno, or 0
 *   wasm_mem+0x3000: up to 255 bytes of /proc/version plus NUL
 *
 * Returns the existing bounded completion marker 0xCC01.
 */
.syntax unified
.arch armv7-a
.text
.arm
.align 2
.global purrtol_stage1_envprobe
.type purrtol_stage1_envprobe, %function

.equ NR_read, 3
.equ NR_open, 5
.equ NR_close, 6
.equ NR_getpid, 20
.equ NR_getuid32, 199

purrtol_stage1_envprobe:
    push    {r4-r11, lr}
    sub     sp, sp, #16
    mov     r10, r4                 /* wasm_mem */
    add     r11, r10, #0x1400       /* result words */

    mov     r7, #NR_getuid32
    svc     #0
    str     r0, [r11, #0x1c]

    mov     r7, #NR_getpid
    svc     #0
    str     r0, [r11, #0x0c]

    mov     r0, #0
    str     r0, [r11, #0x08]        /* version length */
    str     r0, [r11, #0x20]        /* syscall error */

    /* Build "/proc/version\0" at wasm_mem+0x400. */
    add     r0, r10, #0x400
    ldr     r1, =0x6f72702f         /* "/pro" */
    str     r1, [r0]
    ldr     r1, =0x65762f63         /* "c/ve" */
    str     r1, [r0, #4]
    ldr     r1, =0x6f697372         /* "rsio" */
    str     r1, [r0, #8]
    ldr     r1, =0x0000006e         /* "n\0\0\0" */
    str     r1, [r0, #12]

    add     r0, r10, #0x400
    mov     r1, #0                  /* O_RDONLY */
    mov     r7, #NR_open
    svc     #0
    cmp     r0, #0
    blt     open_failed
    mov     r8, r0

    mov     r0, r8
    add     r1, r10, #0x3000
    mov     r2, #255
    mov     r7, #NR_read
    svc     #0
    cmp     r0, #0
    ble     read_failed

    str     r0, [r11, #0x08]
    add     r1, r10, #0x3000
    add     r1, r1, r0
    mov     r2, #0
    strb    r2, [r1]
    b       close_file

read_failed:
    str     r0, [r11, #0x20]

close_file:
    mov     r0, r8
    mov     r7, #NR_close
    svc     #0
    b       finish

open_failed:
    str     r0, [r11, #0x20]

finish:
    movw    r0, #0xcc01
    add     sp, sp, #16
    pop     {r4-r11, pc}

.size purrtol_stage1_envprobe, .-purrtol_stage1_envprobe
