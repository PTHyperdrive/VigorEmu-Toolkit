#!/bin/bash
# Unpack a DrayTek .all image and stage it for emulation, in one step.
#
#   ./unpack.sh <firmware.all> [outdir]        default outdir: ./out
#   ./unpack.sh <firmware.all> out --qemu path/to/qemu-system-aarch64
#
# Wraps the vendored drayunpack.py (a self-contained copy of vigorlab's
# unpacker) and then runs stage.sh, so the result is a firmware/ directory
# ready for supervise.sh + qemu.sh. No vigorlab checkout required.
set -euo pipefail

HERE=$(dirname "$(readlink -f "$0")")

FW=""
OUT="./out"
QEMU=""
DTBS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --qemu)  QEMU=$2; shift 2 ;;
        --dtbs)  DTBS=1; shift ;;
        -h|--help)
            sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)      echo "unknown option: $1" >&2; exit 1 ;;
        *)
            if [ -z "$FW" ]; then FW=$1; else OUT=$1; fi
            shift ;;
    esac
done
[ -n "$FW" ] || { echo "usage: unpack.sh <firmware.all> [outdir] [--qemu <bin>] [--dtbs]" >&2; exit 1; }
[ -f "$FW" ] || { echo "no such file: $FW" >&2; exit 1; }

command -v python3 >/dev/null || { echo "need python3" >&2; exit 1; }

echo "[*] unpacking $FW -> $OUT"
py_args=("$HERE/drayunpack.py" "$FW" "$OUT")
[ "$DTBS" = 1 ] && py_args+=(--dtbs)
python3 "${py_args[@]}"

# Stage, so qemu.sh has its layout. stage.sh checks for sohod64.bin and
# magic_file and symlinks qemu.sh in.
if [ -d "$OUT/rootfs/firmware" ]; then
    echo
    echo "[*] staging $OUT/rootfs"
    if [ -n "$QEMU" ]; then
        "$HERE/stage.sh" "$OUT/rootfs" "$QEMU"
    else
        "$HERE/stage.sh" "$OUT/rootfs"
    fi
else
    echo "[!] no rootfs/firmware in $OUT -- a MIPS image or an encrypted one;"
    echo "    those are not bootable through this toolkit."
fi
