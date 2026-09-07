#!/usr/bin/env python3
"""Carve real files out of sohod64.bin: ELF sections and the embedded web tree.

Two kinds of extractable content live in the image:

  * **ELF sections.** 1258 section headers, of which ~32 carry real bytes --
    .text, .data, .init.text, .got, __ksymtab_strings and friends. Written out
    individually so a disassembler can be pointed at one piece at a time.

  * **The web filesystem.** DrayOS serves its UI from a PFS archive stored as a
    DrayTek LZ4-chunked blob inside .text. It decompresses to ~6 MB holding
    ~1330 files -- .htm, .cgi, .js, .css, images -- and *each file is itself*
    LZ4-chunked, so every entry needs a second pass. This is the closest thing
    to a cgi-bin the firmware has.

    python3 sohod_files.py sohod64.bin outdir
"""
import argparse
import os
import struct
import sys

BASE, OFF = 0x40000000, 0x10000
CHUNKED_MAGIC = bytes.fromhex("aa1d7f50")
PFS_MAGICS = (b"PFS/1.0", b"DLM/1.0")

# Reuse the toolkit's own decoders rather than a second copy.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drayunpack as du  # noqa: E402


def dump_sections(d, out):
    """Write every section that has bytes on disk."""
    e_shoff = struct.unpack_from("<I", d, 32)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 46)

    def sh(i):
        return struct.unpack_from("<10I", d, e_shoff + i * e_shentsize)

    _, _, _, _, so, ss, *_ = sh(e_shstrndx)
    shstr = d[so:so + ss]

    def nm(o):
        return shstr[o:shstr.index(b"\x00", o)].decode("latin-1")

    os.makedirs(out, exist_ok=True)
    written = []
    for i in range(e_shnum):
        n_off, sh_type, _fl, addr, off, size, *_ = sh(i)
        name = nm(n_off)
        # SHT_NOBITS (8) occupies no file space; ksymtab entries are 4 bytes of
        # address, useful as symbols (syms.py) but pointless as files.
        if sh_type == 8 or size == 0 or "___ksymtab" in name:
            continue
        if off + size > len(d):
            continue
        safe = name.lstrip(".").replace("/", "_") or "unnamed"
        path = os.path.join(out, "%s.bin" % safe)
        with open(path, "wb") as fh:
            fh.write(d[off:off + size])
        written.append((name, addr, size))
    return written


def find_web_pfs(d):
    """Locate the LZ4-chunked blob that decompresses to a PFS archive."""
    found = []
    start = 0
    while True:
        i = d.find(CHUNKED_MAGIC, start)
        if i < 0:
            break
        start = i + 4
        try:
            blob, _blocks = du.chunked(d[i:])
        except Exception:
            continue
        if blob[:7] in PFS_MAGICS and len(blob) > 0x10000:
            found.append((i, blob))
    return found


def extract_web(blob, out):
    """Write the PFS entries out, decompressing each file's own LZ4 wrapper."""
    os.makedirs(out, exist_ok=True)
    n_files = n_nested = n_bytes = 0
    for entry in du.pfs_entries(blob):
        body = entry.data
        # Each stored file is itself a chunked container.
        if body[:4] == CHUNKED_MAGIC:
            try:
                body = du.chunked(body)[0]
                n_nested += 1
            except Exception:
                pass  # keep the raw bytes rather than lose the file
        rel = entry.name.replace("\\", "/").lstrip("/")
        dst = os.path.abspath(os.path.join(out, rel))
        if os.path.commonpath((os.path.abspath(out), dst)) != os.path.abspath(out):
            continue                      # refuse traversal
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as fh:
            fh.write(body)
        n_files += 1
        n_bytes += len(body)
    return n_files, n_nested, n_bytes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("outdir")
    a = ap.parse_args()

    d = open(a.image, "rb").read()

    secs = dump_sections(d, os.path.join(a.outdir, "sections"))
    print("    sections/          %d files" % len(secs))
    for name, addr, size in sorted(secs, key=lambda r: -r[2])[:6]:
        print("      %-22s %#010x  %d bytes" % (name, addr, size))

    hits = find_web_pfs(d)
    if not hits:
        print("    web/               no embedded PFS found")
        return 0
    for off, blob in hits:
        files, nested, nbytes = extract_web(blob, os.path.join(a.outdir, "web"))
        print("    web/               %d files, %d bytes  (PFS from LZ4 blob @ %#x)"
              % (files, nbytes, off))
        print("                       %d were individually LZ4-compressed" % nested)
    return 0


if __name__ == "__main__":
    sys.exit(main())
