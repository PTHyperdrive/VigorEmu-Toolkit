#!/bin/bash
# Take sohod64.bin apart into something readable, for Ghidra work.
#
#   ./sohod-extract.sh <sohod64.bin> [outdir]     default outdir: ./sohod-extract
#
# sohod64.bin is DrayOS itself: an ELF32 with EM_AARCH64 -- ARM64 in ILP32 --
# linked at 0x40000000, stripped of a normal symbol table. Loaded raw into a
# disassembler it is 29 MB of FUN_4xxxxxxx. This pulls out everything that
# makes it navigable:
#
#   LAYOUT.txt        ELF header, load segment, the runtime memory map
#   symbols.txt       ~1200 names from the ___ksymtab section-name table
#   cgi-handlers.txt  the CGI dispatch table: URL -> handler address
#   strings/          categorised strings (cgi, formats, paths, errors, all)
#   sections/         each ELF section with real bytes, as its own file
#   web/              the embedded web filesystem: ~1330 real files
#                     (.htm .js .css images) including V2000/CGI-BIN/.
#                     Note the .cgi files there are 2-byte stubs: they exist
#                     so the URL resolves, and the real work is the compiled
#                     handler in cgi-handlers.txt.
#   ghidra/           a Jython script that applies every recovered name
#
# Nothing here modifies the image; it is all read-only extraction.
set -euo pipefail

HERE=$(dirname "$(readlink -f "$0")")

IMG=${1:-}
OUT=${2:-./sohod-extract}
if [ -z "$IMG" ]; then
    sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 1
fi
[ -f "$IMG" ] || { echo "no such file: $IMG" >&2; exit 1; }
command -v python3 >/dev/null || { echo "need python3" >&2; exit 1; }

IMG=$(readlink -f "$IMG")
mkdir -p "$OUT"/{strings,ghidra}
OUT=$(readlink -f "$OUT")

echo "[*] $IMG -> $OUT"

# --- 0. a copy, so the extraction is self-contained --------------------------
cp -n "$IMG" "$OUT/sohod64.bin" 2>/dev/null || true

# --- 1. layout ---------------------------------------------------------------
# The runtime addresses are DrayOS's own, printed at boot; recording them here
# means the Ghidra image base and the segment split are not guesswork later.
python3 - "$IMG" > "$OUT/LAYOUT.txt" <<'PY'
import struct, sys, hashlib
d = open(sys.argv[1], "rb").read()
print("file            : %s" % sys.argv[1])
print("size            : %d bytes (%.1f MB)" % (len(d), len(d) / 1048576))
print("sha256          : %s" % hashlib.sha256(d).hexdigest())
print()
if d[:4] != b"\x7fELF":
    print("NOT an ELF"); raise SystemExit
cls = {1: "ELF32", 2: "ELF64"}.get(d[4], "?")
mach = struct.unpack_from("<H", d, 18)[0]
entry, phoff, shoff = struct.unpack_from("<III", d, 24)
phentsize, phnum = struct.unpack_from("<HH", d, 42)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 46)
print("class           : %s   machine: %d (%s)"
      % (cls, mach, "EM_AARCH64" if mach == 183 else "?"))
print("  -> ELF32 + EM_AARCH64 means ARM64 ILP32: pointers are 32-bit.")
print("     In Ghidra pick AARCH64:LE:32:ilp32 if it is not auto-detected.")
print()
print("entry           : 0x%08x" % entry)
print("phoff/phnum     : 0x%x / %d      shoff/shnum: 0x%x / %d"
      % (phoff, phnum, shoff, shnum))
print()
print("program headers (LOAD only):")
for i in range(phnum):
    o = phoff + i * phentsize
    p_type, p_off, p_va, p_pa, p_fsz, p_msz, p_fl, p_al = struct.unpack_from("<8I", d, o)
    if p_type != 1:
        continue
    print("  LOAD  off 0x%08x  vaddr 0x%08x  filesz 0x%08x  memsz 0x%08x"
          % (p_off, p_va, p_fsz, p_msz))
    print("        file offset -> vaddr:  vaddr = 0x%08x + (off - 0x%x)" % (p_va, p_off))
    print("        memsz > filesz by 0x%x  (that tail is .bss)" % (p_msz - p_fsz))
print()
print("runtime map, as DrayOS prints it at boot (for orientation):")
for line in [
    ".text        0x40000058 - 0x41d8986c",
    ".data        0x41d89880 - 0x41e2dbc8",
    ".heap        0x41e34b58 - 0x45e34b58",
    ".stack       0x45e34b58 - 0x45f34b58   (grows down)",
    ".bss         0x46035000 - 0x4d7c22f0",
    "slab kmalloc 0x4d843324 - 0x55844323",
    "linear malloc 0x55844323 - 0x5cbffe00",
    "flash window 0x5cc00000   config 0x5fd10000   dtb 0x5ff00000",
    "exmem        0x60000000 +",
]:
    print("  " + line)
PY
echo "    LAYOUT.txt"

# --- 2. symbols from the export table ---------------------------------------
python3 "$HERE/syms.py" "$IMG" > "$OUT/symbols.txt" 2>/dev/null || true
echo "    symbols.txt        $(wc -l < "$OUT/symbols.txt") names"

# --- 3. the CGI dispatch table ----------------------------------------------
python3 "$HERE/cgimap.py" "$IMG" > "$OUT/cgi-handlers.txt" 2>/dev/null || true
echo "    cgi-handlers.txt   $(grep -c 'handler' "$OUT/cgi-handlers.txt" || echo 0) handlers"

# --- 4. strings, split by what they are useful for ---------------------------
# One pass, bucketed, because grepping 29 MB repeatedly is the slow way to do
# this and the categories are what you actually reach for.
python3 - "$IMG" "$OUT/strings" <<'PY'
import re, sys, os
d = open(sys.argv[1], "rb").read()
out = sys.argv[2]
BASE, OFF = 0x40000000, 0x10000
def va(f): return BASE + (f - OFF)

buckets = {
    "cgi":     re.compile(rb"[A-Za-z0-9_./\-]{2,48}\.cgi"),
    "html":    re.compile(rb"[A-Za-z0-9_./\-]{2,48}\.(?:htm|html|js|css|gif|png)"),
    "formats": re.compile(rb"[ -~]{0,40}%[-0-9.lzhu]*[dsxXfpc][ -~]{0,40}"),
    "paths":   re.compile(rb"/(?:tmp|cfg|app|firmware|data|etc|var)/[ -~]{1,60}"),
    "errors":  re.compile(rb"[ -~]{0,30}(?:rror|ailed|verflow|assert|BUG|panic)[ -~]{0,40}"),
}
counts = {}
for name, rx in buckets.items():
    seen, lines = set(), []
    for m in rx.finditer(d):
        s = m.group()
        if s in seen:
            continue
        seen.add(s)
        lines.append("%#010x  %s" % (va(m.start()), s.decode("latin-1")))
    counts[name] = len(lines)
    open(os.path.join(out, name + ".txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")

# everything printable >= 6 chars, for grepping
allr = re.compile(rb"[ -~]{6,}")
with open(os.path.join(out, "all.txt"), "w", encoding="utf-8") as fh:
    for m in allr.finditer(d):
        fh.write("%#010x  %s\n" % (va(m.start()), m.group().decode("latin-1")))
for k, v in counts.items():
    print("    strings/%-11s %d" % (k + ".txt", v))
PY

# --- 4b. real files: ELF sections and the embedded web tree ------------------
# The image is not only code. It carries the whole DrayOS web UI as a PFS
# archive inside a DrayTek LZ4-chunked blob, and every file in that archive is
# separately compressed again. That tree is where the .cgi pages actually live
# -- DrayOS has no cgi-bin directory anywhere else.
python3 "$HERE/sohod_files.py" "$IMG" "$OUT"

# --- 5. the Ghidra script ----------------------------------------------------
python3 "$HERE/ghidra_export.py" "$IMG" > "$OUT/ghidra/sohod_names.py" 2>/dev/null || true
echo "    ghidra/sohod_names.py"

cat > "$OUT/ghidra/README.md" <<'EOF'
# Loading sohod64.bin in Ghidra

`sohod64.bin` is an **ELF32 with `EM_AARCH64`** — ARM64 in ILP32, so pointers
are 32-bit while the instruction set is AArch64. That combination is unusual
and is the one thing likely to trip the import.

1. **File > Import File** → `sohod64.bin`.
2. If the language is not detected, set it manually:
   `AARCH64:LE:32:ilp32`. Confirm the image base is **`0x40000000`** —
   the single LOAD segment maps file offset `0x10000` there, so
   `vaddr = 0x40000000 + (fileoff - 0x10000)`.
3. Let auto-analysis finish. You will have ~29 MB of `FUN_4xxxxxxx`.
4. **Window > Script Manager**, add this directory to the script paths, and run
   **`sohod_names.py`**. It applies:
   - ~1200 function names recovered from the `___ksymtab+<name>` section-name
     export table (`sscanf`, `snprintf`, `strcpy`, the driver layer, …);
   - every CGI handler from the dispatch table, prefixed `cgi_` — so
     `cgi_wlogin` is the handler the login form posts to.

## The web tree, and why the .cgi files look empty

`web/V2000/` is the UI DrayOS serves: 1331 files, ~15 MB once decompressed.
Everything is stored twice-compressed — a PFS archive inside a DrayTek
LZ4-chunked blob, with each file separately chunked again — so it does not
show up to `strings` or `binwalk` on the raw image.

`web/V2000/CGI-BIN/` holds 147 `.cgi` files and **most are two bytes**
(`
`). They are routing placeholders: their presence makes the httpd's
path lookup succeed, and the request is then dispatched to a function
compiled into the image. So the CGI *logic* is never in the web tree — look
up the endpoint in `cgi-handlers.txt` and go to that address instead.

## Where to start reading

| what | why |
|---|---|
| `cgi_wlogin` | the endpoint the login form posts to |
| `sscanf` xrefs | `get_mime_headers` parses `Content-length` with `%ld` here |
| `strings/formats.txt` | `frmsave %d %d %s` / `memsave` are the host-escape primitives |
| `strings/cgi.txt` | 263 endpoint names — the reachable attack surface |

`conn + 0x3450` is the parsed `Content-Length` field; searching for that
displacement finds the code that consumes it.
EOF
echo "    ghidra/README.md"

echo
echo "[+] done. Start with $OUT/ghidra/README.md"
