#!/bin/bash
# Build DrayTek's own QEMU from the GPL release.
#
#   ./build-qemu.sh <v3910_gpl.tar.bz2> [workdir]
#
# The release is a tarball of tarballs; QEMU is one nested member, so there is
# no need to unpack all 670 MB or to run their ./build.
set -euo pipefail

GPL=$(readlink -f "${1:?usage: build-qemu.sh <v3910_gpl.tar.bz2> [workdir]}")
WORK=$(readlink -f "${2:-./qemu-build}")
mkdir -p "$WORK"; cd "$WORK"

INNER=Vigor3910_v396_GPL_release/source/qemu-2.12.1.tar.bz2
if [ ! -d qemu-2.12.1 ]; then
    echo "[*] extracting $INNER (streams the outer archive; takes a few minutes)"
    tar -xjf "$GPL" "$INNER"
    tar -xjf "$INNER"
    # It unpacks to source/linux/cavium-rootfs/src_dir/qemu-2.12.1
    src=$(find . -maxdepth 6 -type d -name 'qemu-2.12.1' -not -path './qemu-2.12.1' | head -1)
    [ -n "$src" ] && [ "$src" != "./qemu-2.12.1" ] && mv "$src" ./qemu-2.12.1
fi

cd qemu-2.12.1
echo "[*] configuring"
# --disable-werror matters: this is 2018 code and modern gcc finds new
# warnings in it. Only the aarch64 target is needed.
./configure --target-list=aarch64-softmmu --disable-werror --disable-docs

echo "[*] building"
make -j"$(nproc)"

BIN=$(readlink -f aarch64-softmmu/qemu-system-aarch64)
echo
echo "[+] $BIN"
echo "    Copy it next to qemu.sh, i.e. into the firmware/ directory:"
echo "      cp '$BIN' <rootfs>/firmware/"
echo
echo "    Confirm the patch is in: this build accepts '-dtb DrayTek', which"
echo "    makes it relocate the generated device tree to 0x5ff00000."
