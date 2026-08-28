#!/bin/bash
# Verbatim from the kanxue write-up (thread-289520), which took it from the
# GPL release. Run it from the unpacked root filesystem's firmware/ directory,
# with the QEMU built from source/qemu-2.12.1.tar.bz2 sitting beside it.
#
# 1. do "fw_setenv purelinux 1" first , then reboot
# 2. do setup_qemu_linux.sh (default P3 as WAN, P4 as LAN, for both 1Gbps connection only)
# 3. remember to recover to normal mode by "fw_setenv purelinux 0"

rangen() {
printf "%02x" `shuf -i 1-255 -n 1`
}

rangen1() {
printf "%x" `shuf -i 1-15 -n 1`
}

wan_mac(){
idx=$1
printf "%02x\n" $((0x${C}+0x$idx)) | tail -c 3 # 3 = 2 digit + 1 terminating character
}

A=$(rangen); B=$(rangen); C=$(rangen);
LAN_MAC="00:1d:aa:${A}:${B}:${C}"

if [ ! -p serial0 ]; then
mkfifo serial0
fi
if [ ! -p serial1 ]; then
mkfifo serial1
fi

platform_path="./platform"
echo "x86" > $platform_path
enable_kvm_path="./enable_kvm"
echo "kvm" > $enable_kvm_path

# NOTE: magic_file is NOT created here. It comes from the firmware itself --
# firmware/magic_file in the unpacked root filesystem, holding the string
# "Using Default Config by Extract gDefault in DrayOS". stage.sh puts it in
# place. gci_magic below is written but never loaded; it is vestigial, left
# over from the 2962 version of this script.
cfg_path="./magic_file"

echo "GCI_SKIP" > gci_magic

mkdir -p ../data/uffs
touch ../data/uffs/v3910_ram_flash.bin
uffs_flash="../data/uffs/v3910_ram_flash.bin"

echo "1" > memsize

(sleep 20 && ethtool -K qemu-lan tx off) &

model="./model"
echo "3" > ./model

rm -rf ./app && mkdir -p ./app/gci
GCI_PATH="./app/gci"
GCI_FAIL="./app/gci_exp_fail"
GDEF_FILE="$GCI_PATH/draycfg.def"
GEXP_FLAG="$GCI_PATH/EXP_FLAG"
GEXP_FILE="$GCI_PATH/draycfg.exp"
GDEF_FILE_ADDR="0x4de0000"
GEXP_FLAG_ADDR="0x55e0000"
GEXP_FILE_ADDR="0x55e0010"

echo "0#" > $GEXP_FLAG
echo "19831026" > $GEXP_FILE
echo "GCI_SKIP" > $GDEF_FILE

SHM_SIZE=16777216
./qemu-system-aarch64 -M virt,gic_version=3 -cpu cortex-a57 -m 1024 -L ../usr/share/qemu \
-kernel ./vqemu/sohod64.bin $serial_option -dtb DrayTek \
-nographic $gdb_serial_option $gdb_remote_option \
-device virtio-net-pci,netdev=network-lan,mac=${LAN_MAC} \
-netdev tap,id=network-lan,ifname=qemu-lan,script=no,downscript=no \
-device virtio-net-pci,netdev=network-wan,mac=00:1d:aa:${A}:${B}:$(wan_mac 1) \
-netdev tap,id=network-wan,ifname=qemu-wan,script=no,downscript=no \
-device virtio-serial-pci -chardev pipe,id=ch0,path=serial0 \
-device virtserialport,chardev=ch0,name=serial0 \
-device loader,file=$platform_path,addr=0x25fff0 \
-device loader,file=$cfg_path,addr=0x260000 \
-device loader,file=$uffs_flash,addr=0x00be0000 \
-device loader,file=$enable_kvm_path,addr=0x25ffe0 \
-device loader,file=memsize,addr=0x25ff67 \
-device loader,file=$model,addr=0x25ff69 \
-device loader,file=$GDEF_FILE,addr=$GDEF_FILE_ADDR \
-device loader,file=$GEXP_FLAG,addr=$GEXP_FLAG_ADDR \
-device loader,file=$GEXP_FILE,addr=$GEXP_FILE_ADDR \
-device nec-usb-xhci,id=usb \
-device ivshmem-plain,memdev=hostmem \
-object memory-backend-file,size=${SHM_SIZE},share,mem-path=/dev/shm/ivshmem,id=hostmem
