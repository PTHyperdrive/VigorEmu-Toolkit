#!/bin/bash
# Put the unpacked firmware into the layout qemu.sh expects, and copy the
# scripts in beside it.
#
#   ./stage.sh <unpacked-rootfs> [qemu-system-aarch64]
#
# qemu.sh uses relative paths and must run from firmware/ :
#
#   ./qemu-system-aarch64        the build from build-qemu.sh
#   ./vqemu/sohod64.bin          DrayOS itself
#   ./magic_file                 the gDefault sentinel, from the firmware
#   ../usr/share/qemu            QEMU data dir (efi-virtio.rom lives here)
#   ../data/uffs/                flash filesystem backing store
set -euo pipefail

ROOTFS=$(readlink -f "${1:?usage: stage.sh <unpacked-rootfs> [qemu-binary]}")
HERE=$(dirname "$(readlink -f "$0")")
FW="$ROOTFS/firmware"

[ -d "$FW" ]                  || { echo "no firmware/ under $ROOTFS" >&2; exit 1; }
[ -f "$FW/vqemu/sohod64.bin" ]|| { echo "no vqemu/sohod64.bin under $FW" >&2; exit 1; }
[ -f "$FW/magic_file" ]       || { echo "no magic_file under $FW" >&2; exit 1; }

mkdir -p "$ROOTFS/data/uffs" "$ROOTFS/usr/share/qemu"
cp "$HERE/qemu.sh" "$FW/qemu.sh"
chmod +x "$FW/qemu.sh"

if [ $# -ge 2 ]; then
    cp "$(readlink -f "$2")" "$FW/qemu-system-aarch64"
    chmod +x "$FW/qemu-system-aarch64"
    echo "[+] qemu-system-aarch64 -> $FW/"
else
    echo "[!] no QEMU given; build one with build-qemu.sh and copy it to $FW/"
fi

# efi-virtio.rom is what -L points at. The firmware ships one; fall back to
# the host QEMU's copy.
if [ ! -f "$ROOTFS/usr/share/qemu/efi-virtio.rom" ]; then
    for c in /usr/share/qemu/efi-virtio.rom /usr/share/seabios/efi-virtio.rom; do
        [ -f "$c" ] && cp "$c" "$ROOTFS/usr/share/qemu/" && break
    done
fi

echo "[+] staged. Now:"
echo "      sudo $HERE/net.sh          # once, as root"
echo "      cd $FW && sudo ./qemu.sh"
