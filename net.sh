#!/bin/bash
# Host networking for qemu.sh.
#
#   sudo ./net.sh              tap devices only  (default, safe)
#   sudo ./net.sh down         remove them again
#   sudo BRIDGE=1 ./net.sh     the write-up's full bridge topology
#
# The original script from the write-up is kept beside this one as
# net.sh.kanxue. It does not run on current Kali: brctl was dropped from
# bridge-utils' default install, and it is not idempotent -- a second run
# fails with "RTNETLINK answers: File exists" and "ioctl(TUNSETIFF): Device
# or resource busy" because it never removes what it made. This version does
# the same thing with iproute2, and cleans up first.
#
# DEFAULT MODE creates only the tap devices and puts 192.168.1.2 on the LAN
# side. That is all you need to reach DrayOS at 192.168.1.1 from this host,
# and it leaves your real NIC alone.
#
# BRIDGE MODE reproduces the write-up: it enslaves two physical interfaces to
# bridges and FLUSHES THEIR IP ADDRESSES. On a VMware guest with one adapter
# that disconnects you, ssh included. Only use it if you have a second NIC
# and want other machines on the physical network to reach the router.
set -euo pipefail

IFLAN=${IFLAN:-eth0}
IFWAN=${IFWAN:-eth1}
MYLANIP=${MYLANIP:-192.168.1.2/24}

[ "$(id -u)" = 0 ] || { echo "run me as root" >&2; exit 1; }
command -v ip >/dev/null || { echo "need iproute2: apt install iproute2" >&2; exit 1; }

teardown() {
    for br in br-lan br-wan; do ip link del "$br" 2>/dev/null || true; done
    for t  in qemu-lan qemu-wan; do ip link del "$t" 2>/dev/null || true; done
}

if [ "${1:-}" = down ]; then
    teardown; echo "[+] removed"; exit 0
fi

# Always start from a clean slate; this is what made the original fail on a
# second run.
teardown

for t in qemu-lan qemu-wan; do
    ip tuntap add "$t" mode tap
    ip link set "$t" up
done

if [ "${BRIDGE:-0}" = 1 ]; then
    for i in "$IFLAN" "$IFWAN"; do
        ip link show "$i" >/dev/null 2>&1 || {
            echo "[x] no such interface: $i" >&2
            echo "    available:" >&2
            ip -br link show | awk '{print "      " $1}' >&2
            echo "    set IFLAN= and IFWAN= to two of these." >&2
            teardown; exit 1
        }
    done
    echo "[!] flushing addresses on $IFLAN and $IFWAN -- this will drop any"
    echo "    connection running over them. Ctrl-C within 5s to abort."
    sleep 5

    ip link add br-lan type bridge
    ip link set "$IFLAN"  master br-lan
    ip link set qemu-lan  master br-lan
    ip addr flush dev "$IFLAN"
    ip addr add "$MYLANIP" dev br-lan
    ip link set br-lan up
    ip link set "$IFLAN" up

    ip link add br-wan type bridge
    ip link set "$IFWAN"  master br-wan
    ip link set qemu-wan  master br-wan
    ip addr flush dev "$IFWAN"
    ip link set br-wan up
    ip link set "$IFWAN" up

    LANDEV=br-lan
else
    # No bridge: the host end of the LAN tap carries the address directly.
    ip addr add "$MYLANIP" dev qemu-lan
    LANDEV=qemu-lan
fi

# Checksum offload has to be off or DrayOS receives frames it rejects; the
# write-up disables it for the same reason ("for telnet from linux to drayos").
if command -v ethtool >/dev/null; then
    for d in "$LANDEV" qemu-lan qemu-wan; do
        ethtool -K "$d" gro off gso off tx off 2>/dev/null || true
    done
else
    echo "[!] no ethtool (apt install ethtool); offload left on, which can"
    echo "    stop traffic reaching DrayOS even once it boots."
fi

echo
ip -br addr show qemu-lan qemu-wan ${BRIDGE:+br-lan br-wan} 2>/dev/null || true
echo
echo "[+] host is ${MYLANIP%%/*} on $LANDEV; DrayOS will be 192.168.1.1"
