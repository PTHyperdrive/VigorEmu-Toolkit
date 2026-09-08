#!/usr/bin/env python3
"""Find what references an address (or a string) in sohod64.bin.

AArch64 has no absolute addresses in code: a pointer is built with an
`adrp` (page) plus an `add` (offset within the page). Neither half on its own
tells you the target, which is why a plain byte search for an address finds
nothing. This decodes the pairs.

    python3 xref.py sohod64.bin --string "GetCGI(): input"
    python3 xref.py sohod64.bin --addr 0x41922408
"""
import argparse
import struct
import sys


def load(path):
    d = open(path, "rb").read()
    e_phoff = struct.unpack_from("<I", d, 28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", d, 42)
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_off, p_va, _pa, p_fsz, _msz, _fl, _al = struct.unpack_from("<8I", d, o)
        if p_type == 1:
            segs.append((p_off, p_va, p_fsz))
    return d, segs


def va_of(segs, off):
    for p_off, p_va, p_fsz in segs:
        if p_off <= off < p_off + p_fsz:
            return p_va + (off - p_off)
    return None


def off_of(segs, va):
    for p_off, p_va, p_fsz in segs:
        if p_va <= va < p_va + p_fsz:
            return p_off + (va - p_va)
    return None


def sxt(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m


def scan(d, segs, want, window=12):
    """adrp Rd,page ; ... ; add Rd2,Rd,#imm  ->  page+imm"""
    hits = []
    for p_off, p_va, p_fsz in segs:
        end = p_off + (p_fsz & ~3)
        for off in range(p_off, end, 4):
            insn = struct.unpack_from("<I", d, off)[0]
            if (insn & 0x9F000000) != 0x90000000:      # ADRP
                continue
            rd = insn & 0x1F
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm = sxt((immhi << 2) | immlo, 21) << 12
            pc = va_of(segs, off)
            page = (pc & ~0xFFF) + imm
            if want < page or want >= page + 0x1000:
                continue                                # page cannot hold it
            for k in range(1, window + 1):
                o2 = off + 4 * k
                if o2 + 4 > end:
                    break
                i2 = struct.unpack_from("<I", d, o2)[0]
                # ADD immediate, 32- or 64-bit
                if (i2 & 0x7F000000) not in (0x11000000, 0x91000000):
                    continue
                rn = (i2 >> 5) & 0x1F
                if rn != rd:
                    continue
                imm12 = (i2 >> 10) & 0xFFF
                if (i2 >> 22) & 1:
                    imm12 <<= 12
                if page + imm12 == want:
                    hits.append((pc, va_of(segs, o2)))
                break
    return hits


STP_FP_LR = 0x2A6          # stp x29,x30,[sp,#-N]!  (64-bit, pre-index)


def func_start(d, segs, va, back=0x3000):
    """Nearest preceding `stp x29,x30,[sp,#-N]!`, plus a `sub sp` before it."""
    off = off_of(segs, va)
    if off is None:
        return None
    lo = max(0, off - back)
    for o in range(off & ~3, lo, -4):
        insn = struct.unpack_from("<I", d, o)[0]
        if (((insn >> 22) & 0x3FF) == STP_FP_LR and (insn & 0x1F) == 29
                and ((insn >> 10) & 0x1F) == 30 and ((insn >> 5) & 0x1F) == 31):
            prev = struct.unpack_from("<I", d, o - 4)[0] if o >= 4 else 0
            # `sub sp,sp,#imm` immediately before is still part of the prologue
            if (prev & 0x7F8003FF) == 0x510003FF:
                return va_of(segs, o - 4)
            return va_of(segs, o)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--string")
    ap.add_argument("--addr")
    a = ap.parse_args()

    d, segs = load(a.image)

    targets = []
    if a.string:
        needle = a.string.encode()
        start = 0
        while True:
            i = d.find(needle, start)
            if i < 0:
                break
            start = i + 1
            v = va_of(segs, i)
            if v is not None:
                nul = d.index(b"\x00", i)
                targets.append((v, d[i:nul][:70].decode("latin-1")))
    if a.addr:
        targets.append((int(a.addr, 0), ""))

    if not targets:
        sys.exit("no such string/address in a LOAD segment")

    for va, text in targets:
        print("target 0x%08x  %s" % (va, text))
        for site, addsite in scan(d, segs, va):
            fs = func_start(d, segs, site)
            print("    referenced at 0x%08x (add at 0x%08x)  function starts ~0x%08x"
                  % (site, addsite, fs or 0))
        print()


if __name__ == "__main__":
    main()
