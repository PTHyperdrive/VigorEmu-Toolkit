#!/usr/bin/env python3
"""Recover DrayOS function symbols from sohod64.bin's section names.

sohod64.bin is stripped of a normal symbol table, but the Linux-derived layer
leaves its export table behind as *section names*: each `___ksymtab+<func>`
section is PROGBITS whose 4-byte body is that function's address. Around 1200
names come back, which turns blind address-chasing into named work.

    python3 syms.py sohod64.bin                 # list all
    python3 syms.py sohod64.bin -g alloc,http   # filter (case-insensitive)
    python3 syms.py sohod64.bin --gdb > s.gdb   # gdb symbol-file commands
    python3 syms.py sohod64.bin --ida > s.py    # IDAPython renamer

Credit: the section-name trick is from the kanxue write-up
(bbs.kanxue.com/thread-289520).
"""
import argparse, re, struct, sys

TEXT_LO, TEXT_HI = 0x40000000, 0x44000000


def recover(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 1:
        sys.exit("not an ELF32 (sohod64.bin is ILP32 aarch64)")
    e_shoff = struct.unpack_from("<I", d, 32)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 46)
    sh = lambda i: struct.unpack_from("<10I", d, e_shoff + i * e_shentsize)
    _, _, _, _, so, ss, *_ = sh(e_shstrndx)
    shstr = d[so:so + ss]

    def nm(o):
        return shstr[o:shstr.index(b"\x00", o)].decode("latin-1")

    out = {}
    for i in range(e_shnum):
        n_off, sh_type, _fl, _ad, off, size, *_ = sh(i)
        n = nm(n_off)
        if "___ksymtab" not in n or sh_type != 1 or size < 4:
            continue
        addr = struct.unpack_from("<I", d, off)[0]
        if TEXT_LO < addr < TEXT_HI:
            out[n.split("+")[-1]] = addr
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("-g", "--grep", help="comma-separated substrings to match")
    ap.add_argument("--gdb", action="store_true", help="emit gdb commands")
    ap.add_argument("--ida", action="store_true", help="emit an IDAPython script")
    a = ap.parse_args()

    syms = recover(a.image)
    if a.grep:
        pats = [p.strip().lower() for p in a.grep.split(",") if p.strip()]
        syms = {k: v for k, v in syms.items() if any(p in k.lower() for p in pats)}

    if a.gdb:
        # gdb has no symbols for a stripped image; define convenience vars so
        # breakpoints can be written by name: b *$sscanf
        for k, v in sorted(syms.items()):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                print("set $%s = 0x%x" % (k, v))
    elif a.ida:
        print("import idc, idaapi")
        for k, v in sorted(syms.items()):
            print("idc.create_insn(0x%x); idc.add_func(0x%x); "
                  "idc.set_name(0x%x, %r, idc.SN_NOWARN)" % (v, v, v, k))
        print("idaapi.refresh_idaview_anyway()")
    else:
        for k, v in sorted(syms.items()):
            print("%#010x  %s" % (v, k))
        print("\n%d symbols" % len(syms), file=sys.stderr)


if __name__ == "__main__":
    main()
