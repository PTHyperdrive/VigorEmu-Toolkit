#!/usr/bin/env python3
"""Write a copy of sohod64.bin that carries a real ELF symbol table.

Ghidra reads `.symtab` natively, so this needs no scripting at all -- no
Jython, no PyGhidra, no Script Manager. Import the output and every recovered
function already has its name.

Two sources feed it:
  * ~1200 names from the ___ksymtab section-name export table (syms.py)
  * every CGI handler from the .data dispatch table (cgimap.py), named cgi_<x>

    python3 mksymbols.py sohod64.bin sohod64.symbols.elf

The original is not modified. Section headers are relocated to the end of the
file and three sections are appended (.symtab, .strtab and a new .shstrtab
carrying their names), so existing offsets stay valid.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syms as _syms          # noqa: E402
import cgimap as _cgimap      # noqa: E402

STT_FUNC, STB_GLOBAL = 2, 1
SHT_SYMTAB, SHT_STRTAB = 2, 3


def sections(d):
    e_shoff = struct.unpack_from("<I", d, 32)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 46)
    out = []
    for i in range(e_shnum):
        out.append(struct.unpack_from("<10I", d, e_shoff + i * e_shentsize))
    return e_shoff, e_shentsize, e_shnum, e_shstrndx, out


# Functions identified by walking the live call stack at a CGI dispatch, then
# resolving each return address back to its prologue. Not recoverable from any
# table in the image, so they are recorded here.
MEASURED = {
    0x40139364: "httpd_main",          # the RTOS task, priority 11
    0x40129f5c: "http_handler",        # names itself in a debug string
    0x4014469c: "http_parse_request",  # "Invalid HTTP/0.9 method."
    0x40141b3c: "cgi_stub",            # DrayTek's own name for the dispatcher
    0x40141578: "add_common_vars",     # builds the fake CGI environment
    0x40143134: "get_mime_headers",    # parses Content-length via sscanf("%ld")
    0x40a4b9d0: "drayos_linear_malloc",
    0x400bba14: "DrayOS_TaskReturn",   # seeded on every task stack by OSTaskCreate
    # In the httpd chain but not otherwise identifiable; a neutral name beats
    # gdb attributing it to the nearest preceding export 456 KB away.
    0x401291e0: "sub_401291e0",
}


def collect(image):
    """{addr: name}, CGI handlers winning over generic export names."""
    named = {}
    for name, addr in _syms.recover(image).items():
        clean = "".join(c if (c.isalnum() or c == "_") else "_" for c in name)
        named.setdefault(addr, clean)

    d = _cgimap.load(image)
    for table in _cgimap.find_tables(d):
        for _ent, nm, hnd, _flags in table:
            stem = nm[:-4].replace(".", "_").replace("-", "_")
            named[hnd] = "cgi_%s" % stem        # override: more specific

    named.update(MEASURED)                  # measured names win over all
    return named


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("output")
    a = ap.parse_args()

    d = bytearray(open(a.image, "rb").read())
    if d[:4] != b"\x7fELF" or d[4] != 1:
        sys.exit("not an ELF32 (sohod64.bin is ILP32 aarch64)")

    e_shoff, e_shentsize, e_shnum, e_shstrndx, secs = sections(d)
    if e_shentsize != 40:
        sys.exit("unexpected section header size %d" % e_shentsize)

    # index of .text, so symbols bind to a real section
    _, _, _, so, ss, sz, *_ = secs[e_shstrndx][0:6] + (0,) * 4
    sh_off, sh_size = secs[e_shstrndx][4], secs[e_shstrndx][5]
    shstr = bytes(d[sh_off:sh_off + sh_size])

    def secname(i):
        n = secs[i][0]
        return shstr[n:shstr.index(b"\x00", n)].decode("latin-1")

    text_idx = next((i for i in range(e_shnum) if secname(i) == ".text"), 1)

    named = collect(a.image)
    print("symbols to write: %d" % len(named), file=sys.stderr)

    # --- .strtab -------------------------------------------------------------
    strtab = bytearray(b"\x00")
    offs = {}
    for addr in sorted(named):
        nm = named[addr].encode("latin-1", "replace")
        offs[addr] = len(strtab)
        strtab += nm + b"\x00"

    # --- .symtab (index 0 must be the null symbol) --------------------------
    symtab = bytearray(struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0))
    for addr in sorted(named):
        info = (STB_GLOBAL << 4) | STT_FUNC
        symtab += struct.pack("<IIIBBH", offs[addr], addr, 0, info, 0, text_idx)

    # --- a new .shstrtab: old content plus our two names ---------------------
    new_shstr = bytearray(shstr)
    def addname(s):
        o = len(new_shstr)
        new_shstr.extend(s.encode() + b"\x00")
        return o
    n_symtab = addname(".symtab")
    n_strtab = addname(".strtab")
    n_shstr = addname(".shstrtab_ext")

    # --- lay the new blobs out at the end ------------------------------------
    def align(n, a=16):
        return (n + a - 1) & ~(a - 1)

    pos = align(len(d))
    d.extend(b"\x00" * (pos - len(d)))

    off_strtab = pos;  d.extend(strtab);      pos = align(len(d)); d.extend(b"\x00" * (pos - len(d)))
    off_symtab = pos;  d.extend(symtab);      pos = align(len(d)); d.extend(b"\x00" * (pos - len(d)))
    off_shstr = pos;   d.extend(new_shstr);   pos = align(len(d)); d.extend(b"\x00" * (pos - len(d)))

    i_symtab, i_strtab, i_shstr = e_shnum, e_shnum + 1, e_shnum + 2

    # --- rebuild the section header table at the end -------------------------
    new_shoff = pos
    sht = bytearray()
    for s in secs:
        sht += struct.pack("<10I", *s)
    # name, type, flags, addr, off, size, link, info, align, entsize
    sht += struct.pack("<10I", n_symtab, SHT_SYMTAB, 0, 0, off_symtab,
                       len(symtab), i_strtab, 1, 4, 16)
    sht += struct.pack("<10I", n_strtab, SHT_STRTAB, 0, 0, off_strtab,
                       len(strtab), 0, 0, 1, 0)
    sht += struct.pack("<10I", n_shstr, SHT_STRTAB, 0, 0, off_shstr,
                       len(new_shstr), 0, 0, 1, 0)
    d.extend(sht)

    struct.pack_into("<I", d, 32, new_shoff)          # e_shoff
    struct.pack_into("<HHH", d, 46, e_shentsize, e_shnum + 3, i_shstr)

    open(a.output, "wb").write(bytes(d))
    print("wrote %s  (%d bytes, %d symbols, .text is section %d)"
          % (a.output, len(d), len(named), text_idx), file=sys.stderr)


if __name__ == "__main__":
    main()
