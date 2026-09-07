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

# --- 5. an ELF that carries the symbols ---------------------------------------
# The important output. Ghidra reads .symtab natively, so importing this needs
# no scripting at all -- which matters, because Ghidra 11 dropped Jython and
# script-based renaming is the fragile path.
python3 "$HERE/mksymbols.py" "$IMG" "$OUT/ghidra/sohod64.symbols.elf" 2>/dev/null   && echo "    ghidra/sohod64.symbols.elf   <- import THIS into Ghidra"   || echo "    ghidra/sohod64.symbols.elf   FAILED"

# Kept as a fallback for anyone who would rather script it.
python3 "$HERE/ghidra_export.py" "$IMG" > "$OUT/ghidra/sohod_names.py" 2>/dev/null || true
echo "    ghidra/sohod_names.py        (fallback; needs PyGhidra)"

cat > "$OUT/ghidra/README.md" <<'EOF'
# Loading DrayOS in Ghidra

## Import `sohod64.symbols.elf`, not `sohod64.bin`

`sohod64.symbols.elf` is the same image with a real ELF `.symtab` appended,
carrying ~1330 names. Ghidra reads `.symtab` natively, so **no script is
needed** — which matters because Ghidra 11 dropped Jython, and script-based
renaming is the part that breaks.

1. **File > Import File** → `sohod64.symbols.elf`
2. If the language is not auto-detected, set it by hand: **`AARCH64:LE:32:ilp32`**.
   The image is ELF32 with `EM_AARCH64` — ARM64 with 32-bit pointers, which is
   the one thing likely to confuse the import. Image base is **`0x40000000`**.
3. Run auto-analysis. Functions arrive already named.

Verify it took: the Symbol Tree should contain `cgi_wlogin` at `0x40cd47cc`
and `sscanf` at `0x40013e30`.

## Do not import the .cgi files

`web/V2000/CGI-BIN/*.cgi` contain **no code**. Most are two bytes (`
`) —
they exist so the httpd's URL lookup resolves, and the request is then handed
to a function compiled into `sohod64.bin`. Ghidra has nothing to disassemble
in them, which is why it cannot "give an exact function" for one.

To go from a URL to its code, look the endpoint up in `cgi-handlers.txt` and
jump to that address — or just use the `cgi_` symbols, which are exactly that
mapping already applied:

    cgi_wlogin        0x40cd47cc     the login form's POST target
    cgi_frmup         0x40be9384     firmware upload
    cgi_cfgimport                    config import
    ...115 in total

## Where to start reading

| symbol / address | why |
|---|---|
| `cgi_wlogin` | the endpoint the login form posts to |
| `0x40143134` | `get_mime_headers` — parses `Content-length` via `sscanf("%ld")` |
| `0x40141578` | `add_common_vars` — builds the CGI environment |
| `0x40141d18` | the dispatcher: `blr x7` into the handler |
| `0x40a4b9d0` | DrayOS's linear allocator |

`conn + 0x3450` is the parsed `Content-Length`; searching for that
displacement finds its consumers. Measured on the live emulator, it is read
exactly once, to build the `CONTENT_LENGTH` env string.

EOF
echo "    ghidra/README.md"

echo
echo "[+] done. Start with $OUT/ghidra/README.md"
