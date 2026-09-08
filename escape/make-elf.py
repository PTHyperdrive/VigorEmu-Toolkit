#!/usr/bin/env python3
"""Wrap raw AArch64 shellcode into a loadable image for the DrayOS lab.

You supply the bytes; this only packages them. It emits:
  * <out>.bin  -- the raw bytes, ready to load at the target address
  * <out>.elf  -- an ELF32 / EM_AARCH64 (ILP32) container: one R+X PT_LOAD at
                  the load address, entry at its start. Same class as
                  sohod64.bin, so Ghidra/objdump open it as AARCH64:LE:32:ilp32
                  with no fiddling, and you can disassemble to check your bytes.

Two ways to give it your shellcode:
    python3 make-elf.py --bin payload.bin              # from an assembled file
    (or edit SHELLCODE below and run with no --bin)

Assemble your payload however you like, e.g.:
    aarch64-linux-gnu-as payload.s -o p.o
    aarch64-linux-gnu-objcopy -O binary p.o payload.bin
or keystone-engine, or any A64 assembler that emits a flat binary.

Target notes for whatever you put here (see cve-2024-41592/README.md):
  * DrayOS is AArch64 ILP32, running as a QEMU guest. No NX, no ASLR, so the
    bytes execute wherever they are loaded and every address is fixed.
  * Default load 0x461eb000 is unused httpd task stack
    (stack 0x461ea800..0x461fa7f0, live SP ~0x461f6510).
  * The escape itself is a call to virtcons_out(w0=buf, w1=len) @ 0x40422e20
    with buf pointing at a "frmsave <addr> <size> <path>\\n" string --
    documented in gen-frmsave.py. That part is yours to build.
"""
import argparse
import struct

DEFAULT_LOAD = 0x461EB000

# ---------------------------------------------------------------------------
# PLACEHOLDER. Replace with your own assembled AArch64 bytes, or pass --bin.
# The default is a single `ret` (0xD65F03C0) -- a valid, harmless image so the
# builder produces something you can immediately open in a disassembler.
# ---------------------------------------------------------------------------
SHELLCODE = bytes.fromhex("c0035fd6")     # ret  -- <<< YOUR SHELLCODE HERE >>>


EM_AARCH64 = 183
ET_EXEC = 2
PT_LOAD = 1
PF_R, PF_X = 4, 1


def elf32(load, blob):
    """Minimal ELF32 (EM_AARCH64) with one R+X PT_LOAD segment."""
    ehsize, phentsize = 52, 32
    align = 0x1000
    data_off = align + (load & (align - 1))          # keep p_offset ~ p_vaddr (mod align)

    ehdr = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8          # ELF32, LE, SysV
    ehdr += struct.pack("<HHIIIIIHHHHHH",
                        ET_EXEC, EM_AARCH64, 1,
                        load,            # e_entry
                        ehsize,          # e_phoff (phdr right after ehdr)
                        0,               # e_shoff
                        0,               # e_flags
                        ehsize, phentsize, 1,   # ehsize, phentsize, phnum
                        0, 0, 0)                # shentsize, shnum, shstrndx

    phdr = struct.pack("<IIIIIIII",
                       PT_LOAD, data_off, load, load,
                       len(blob), len(blob), PF_R | PF_X, align)

    out = bytearray(ehdr + phdr)
    out += b"\x00" * (data_off - len(out))
    out += blob
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", help="raw shellcode file; overrides the inline SHELLCODE")
    ap.add_argument("--load", default=hex(DEFAULT_LOAD),
                    help="load / entry virtual address (default 0x461eb000)")
    ap.add_argument("--out", default="payload", help="output basename")
    a = ap.parse_args()

    blob = open(a.bin, "rb").read() if a.bin else SHELLCODE
    load = int(a.load, 0)
    if len(blob) % 4:
        print("warning: length %d is not a multiple of 4 (A64 is fixed 4-byte)" % len(blob))
    if blob == SHELLCODE and not a.bin:
        print("note: using the placeholder `ret` -- pass --bin or edit SHELLCODE")

    open(a.out + ".bin", "wb").write(blob)
    open(a.out + ".elf", "wb").write(elf32(load, blob))

    print("load/entry : 0x%08x" % load)
    print("size       : %d bytes" % len(blob))
    print("wrote      : %s.bin, %s.elf" % (a.out, a.out))
    print("hexdump    : %s" % blob.hex())
    print("disassemble: aarch64-linux-gnu-objdump -D -b binary -m aarch64 %s.bin" % a.out)
    print("       or  : gdb-multiarch -batch -ex 'set arch aarch64' "
          "-ex 'file %s.elf' -ex 'disassemble 0x%x,+%d'" % (a.out, load, len(blob)))


if __name__ == "__main__":
    main()
