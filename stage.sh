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
# Symlink, not copy: a copy goes stale the moment the repo is updated, and
# the staged one is what actually runs. This way git pull takes effect with no
# re-staging. STAGE_COPY=1 copies instead, for moving the tree elsewhere.
rm -f "$FW/qemu.sh"
if [ "${STAGE_COPY:-0}" = 1 ]; then
    cp "$HERE/qemu.sh" "$FW/qemu.sh"; chmod +x "$FW/qemu.sh"
else
    ln -s "$HERE/qemu.sh" "$FW/qemu.sh"
fi

# qemu.sh runs "./qemu-system-aarch64" -- a relative path -- so the binary has
# to sit in firmware/ itself. Symlink rather than copy unless LINK=0, so the
# build tree stays the single copy and a rebuild is picked up automatically.
QBIN=""
if [ $# -ge 2 ]; then
    QBIN=$(readlink -f "$2")
    rm -f "$FW/qemu-system-aarch64"
    if [ "${LINK:-1}" = 1 ]; then
        ln -s "$QBIN" "$FW/qemu-system-aarch64"
        echo "[+] qemu-system-aarch64 -> symlink to $QBIN"
    else
        cp "$QBIN" "$FW/qemu-system-aarch64"
        chmod +x "$FW/qemu-system-aarch64"
        echo "[+] qemu-system-aarch64 -> copied into $FW/"
    fi
else
    echo "[!] no QEMU given; build one with build-qemu.sh and pass it here."
fi

# efi-virtio.rom is what -L points at. The firmware ships one; fall back to
# the host QEMU's copy.
if [ ! -f "$ROOTFS/usr/share/qemu/efi-virtio.rom" ]; then
    # -L points at ../usr/share/qemu, so the option ROM the virtio NICs need
    # must be there. Prefer the one from the build we just made.
    cands=(/usr/share/qemu/efi-virtio.rom /usr/share/seabios/efi-virtio.rom)
    [ -n "$QBIN" ] && cands=("$(dirname "$QBIN")/../pc-bios/efi-virtio.rom" "${cands[@]}")
    for c in "${cands[@]}"; do
        [ -f "$c" ] && cp "$c" "$ROOTFS/usr/share/qemu/"             && echo "[+] efi-virtio.rom from $c" && break
    done
fi

echo "[+] staged. Now:"
echo "      sudo $HERE/net.sh          # once, as root"
echo "      cd $FW && sudo ./qemu.sh"
