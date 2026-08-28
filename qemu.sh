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

# DEVIATION: persist the MAC.
#
# The original picks a fresh random one on every launch. That is harmless for
# a single throwaway run, but with config persistence working it is fatal:
# DrayOS saves board info containing the MAC, sees different hardware on the
# next boot, and re-provisions -- so it never stops asking to be restarted.
# The real device has a fixed MAC from board info. Delete lan_mac for a new one.
if [ -s ./lan_mac ]; then
    read -r A B C < ./lan_mac
else
    A=$(rangen); B=$(rangen); C=$(rangen)
    echo "$A $B $C" > ./lan_mac
fi
LAN_MAC="00:1d:aa:${A}:${B}:${C}"
echo "[*] LAN MAC $LAN_MAC"

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

# DEVIATION from the verbatim script, and the only one in this file.
#
# On the device, cfg_path is /cfg/draycfg.cfg -- a real config on the Linux
# side -- and magic_file is only the fallback. Here there is no /cfg, so the
# first boot gets the sentinel, finds no config, extracts gDefault, and writes
# a real one out through the patched QEMU:
#
#   [_virtcons_out:2752]======memsave 1257540056 5673080 x86
#   Memsave Config addr 0x4af489d8 size 5673080
#
# It then asks the host to restart it ("reboot qemu"), which on the device is
# recvCmd running /etc/runcommand/reboot: killall qemu-system-aarch64, then
# run.sh again. From the second boot on, that config is what should be loaded,
# so pick it up if it exists. Delete draycfg.cfg to start from defaults again.
if [ -s ./draycfg.cfg ]; then
    cfg_path="./draycfg.cfg"
    echo "[*] using the config DrayOS saved ($(stat -c%s ./draycfg.cfg) bytes)"
else
    echo "[*] first boot: no saved config, DrayOS will extract gDefault and"
    echo "    ask to reboot. Stop it when you see \"Memsave Config\", then"
    echo "    run this again."
fi

echo "GCI_SKIP" > gci_magic

# DEVIATION: load the flash image back from where DrayOS actually writes it.
#
# The original loads ../data/uffs/v3910_ram_flash.bin, but DrayOS sends
#
#   frmsave <addr> <size> ./v3910_ram_flash.bin
#
# and the patched QEMU writes that relative to its own cwd, which is this
# directory. The binary carries both prefixes -- "/data/uffs/" for cavium and
# "./" for x86 -- and platform is x86 here, so the saved image never went back
# into the path the original reloads. UFFS came up unformatted every boot,
# which is what kept [SS] invalid ("do convert") and kept DrayOS asking to be
# restarted. Point both ends at the same file.
mkdir -p ../data/uffs
uffs_flash="./v3910_ram_flash.bin"
[ -f "$uffs_flash" ] || touch "$uffs_flash"

# DEVIATION: pick memsize the way run.sh does, from the session count.
#
# This is what the endless "reboot qemu" actually is. check_max_portmap_sessions
# compares the session tables memsize gives it against what the config asks
# for; on a mismatch it writes the wanted value out and reboots so the launcher
# can re-read it:
#
#   frmsave <addr> <size> /app/gci/max_portmap_sessions
#   ## Drv software rebooting : cmd=1, fun=check_max_portmap_sessions ##
#
# run.sh line 99 reads that file and maps it to a memsize digit. The write-up's
# script hardcodes "1" and never looks, so the mismatch survives every restart
# and DrayOS asks again forever.
#
# The path is ABSOLUTE. The QEMU patch hands whatever path DrayOS sends
# straight to qmp_memsave, so it lands at /app/gci on the host, not ./app/gci
# -- and if that directory is missing the write fails silently, because the
# patch ignores the Error it is handed.
mkdir -p /app/gci
session_path="/app/gci/max_portmap_sessions"
if [ -s "$session_path" ]; then
    case "$(cat "$session_path")" in
        300K)  echo "1" > memsize ;;
        500K)  echo "2" > memsize ;;
        1000K) echo "3" > memsize ;;
        *)     echo "0" > memsize ;;
    esac
    echo "[*] max_portmap_sessions=$(cat "$session_path") -> memsize $(cat memsize)"
else
    echo "1" > memsize
    echo "[*] no session count yet; memsize 1. DrayOS will write one and ask"
    echo "    to restart -- that is the handshake, not a failure."
fi

(sleep 20 && ethtool -K qemu-lan tx off) &

model="./model"
echo "3" > ./model

GCI_PATH="/app/gci"
GCI_FAIL="/app/gci_exp_fail"
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
