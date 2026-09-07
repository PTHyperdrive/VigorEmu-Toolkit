#!/usr/bin/env python3
"""Recover DrayOS's CGI dispatch table from sohod64.bin.

DrayOS has no /cgi-bin directory -- it is an RTOS, and every CGI handler is a
function compiled into the image. The URL-to-handler mapping lives in .data as
an array of 12-byte entries:

    struct { const char *name; void (*handler)(void); uint32_t flags; }

Finding it is mechanical: locate a known name string (e.g. "wlogin.cgi"), find
the 4-byte pointer to it, and walk outwards while entries keep decoding.

    python3 cgimap.py sohod64.bin              # the whole table
    python3 cgimap.py sohod64.bin -g login     # filter by name
    python3 cgimap.py sohod64.bin --gdb        # gdb breakpoints on every handler

This is the practical equivalent of "extracting cgi-bin": it enumerates the
reachable request handlers and gives each one an address to break on.
"""
import argparse
import struct
import sys

BASE, OFF = 0x40000000, 0x10000
TEXT_HI = 0x41D89000          # end of .text; .data starts above this


def load(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 1:
        sys.exit("not an ELF32 (sohod64.bin is ILP32 aarch64)")
    return d


def cstr(d, addr, maxlen=64):
    f = addr - BASE + OFF
    if not (0 <= f < len(d)):
        return None
    e = d.find(b"\x00", f)
    if e < 0 or e - f >= maxlen:
        return None
    s = d[f:e]
    return s.decode("latin-1") if s and all(32 <= c < 127 for c in s) else None


def entry_at(d, addr):
    """Decode a 12-byte {name, handler, flags} entry, or None."""
    f = addr - BASE + OFF
    if not (0 <= f + 12 <= len(d)):
        return None
    name_p, hnd, flags = struct.unpack_from("<III", d, f)
    nm = cstr(d, name_p)
    if not nm or not nm.endswith(".cgi"):
        return None
    if not (BASE < hnd < TEXT_HI):
        return None
    return nm, hnd, flags


def find_tables(d, anchor="wlogin.cgi"):
    """Locate every dispatch table by anchoring on a known CGI name."""
    # 1. find the anchor string
    needle = anchor.encode() + b"\x00"
    saddrs = [BASE + (i - OFF) for i in range(OFF, len(d) - len(needle))
              if d[i:i + len(needle)] == needle]
    if not saddrs:
        sys.exit("anchor %r not found in image" % anchor)

    # 2. find 4-byte pointers to it -- those are table entries
    starts = []
    for sa in saddrs:
        pat = struct.pack("<I", sa)
        for i in range(0, len(d) - 4, 4):
            if d[i:i + 4] == pat:
                starts.append(BASE + (i - OFF))

    tables = []
    for p in starts:
        if entry_at(d, p) is None:
            continue
        # walk back to the table head, then forward to its end
        head = p
        while entry_at(d, head - 12) is not None:
            head -= 12
        out, a = [], head
        while True:
            e = entry_at(d, a)
            if e is None:
                break
            out.append((a,) + e)
            a += 12
        if out and not any(t[0][0] == head for t in tables):
            tables.append(out)
    return tables


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("-g", "--grep", help="only names containing this")
    ap.add_argument("--anchor", default="wlogin.cgi",
                    help="known CGI name used to locate the table")
    ap.add_argument("--gdb", action="store_true",
                    help="emit gdb breakpoints on every handler")
    a = ap.parse_args()

    d = load(a.image)
    tables = find_tables(d, a.anchor)
    if not tables:
        sys.exit("no dispatch table found")

    total = 0
    for t in tables:
        rows = [r for r in t
                if not a.grep or a.grep.lower() in r[1].lower()]
        if not rows:
            continue
        if not a.gdb:
            print("=== table @ %#010x : %d entries ===" % (t[0][0], len(t)))
        for ent, nm, hnd, flags in rows:
            total += 1
            if a.gdb:
                print("break *%#010x   # %s" % (hnd, nm))
            else:
                print("  %-26s handler %#010x  flags %#06x" % (nm, hnd, flags))
    if not a.gdb:
        print("\n%d handlers" % total, file=sys.stderr)


if __name__ == "__main__":
    main()
