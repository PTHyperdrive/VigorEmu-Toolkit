#!/bin/bash
# Host networking, following the write-up exactly.
#
#   sudo ./net.sh          set it up
#   sudo ./net.sh down     tear it down
#
# The write-up does this in two steps, and the first one is easy to misread:
#
#   sudo ip tuntap add dev eth0 mode tap      <- eth0 and eth1 are TAP
#   sudo ip tuntap add dev eth1 mode tap         devices it CREATES, not
#   sudo ip link set eth0 up                     physical NICs
#   sudo ip link set eth1 up
#
# then rc.41.setupif.sh bridges each of them to the tap QEMU attaches to:
#
#   br-lan = eth0 + qemu-lan,  192.168.1.2
#   br-wan = eth1 + qemu-wan
#
# So the whole topology is virtual. No second network adapter is needed, and
# nothing touches the interface this machine actually uses.
#
# The original calls brctl, which current Kali no longer installs, and never
# removes what it made, so a second run fails with "RTNETLINK answers: File
# exists" and "ioctl(TUNSETIFF): Device or resource busy". Same topology here,
# with iproute2, and torn down first.
set -euo pipefail

IFLAN=${IFLAN:-eth0}
IFWAN=${IFWAN:-eth1}
MYLANIP=${MYLANIP:-192.168.1.2}

[ "$(id -u)" = 0 ] || { echo "run me as root" >&2; exit 1; }

is_tap() { [ -d "/sys/class/net/$1/tun_flags" ]; }

teardown() {
    for d in br-lan br-wan qemu-lan qemu-wan; do ip link del "$d" 2>/dev/null || true; done
    for d in "$IFLAN" "$IFWAN"; do is_tap "$d" && ip link del "$d" 2>/dev/null || true; done
}

if [ "${1:-}" = down ]; then teardown; echo "[+] removed"; exit 0; fi

# Refuse to touch a real interface. On a VMware Kali the adapter is often
# called eth0, which is exactly the name the write-up wants for its tap.
for d in "$IFLAN" "$IFWAN"; do
    if ip link show "$d" >/dev/null 2>&1 && ! is_tap "$d"; then
        echo "[x] $d already exists and is not a tap -- it looks like a real" >&2
        echo "    interface, and bridging it would take this machine off the" >&2
        echo "    network. Pick unused names instead, e.g." >&2
        echo "      sudo IFLAN=dray0 IFWAN=dray1 $0" >&2
        exit 1
    fi
done

teardown

# Step 1: the two "NICs", which are taps.
for d in "$IFLAN" "$IFWAN"; do
    ip tuntap add dev "$d" mode tap
    ip link set "$d" up
done

# Step 2: the taps QEMU attaches to, bridged to those.
ip tuntap add qemu-lan mode tap
ip tuntap add qemu-wan mode tap

ip link add br-lan type bridge
ip link set "$IFLAN" master br-lan
ip link set qemu-lan master br-lan
ip addr flush dev "$IFLAN"
ip addr add "$MYLANIP/24" dev br-lan
ip link set br-lan up
ip link set qemu-lan up
ip link set "$IFLAN" up

ip link add br-wan type bridge
ip link set "$IFWAN" master br-wan
ip link set qemu-wan master br-wan
ip addr flush dev "$IFWAN"
ip link set br-wan up
ip link set qemu-wan up
ip link set "$IFWAN" up

# The write-up turns these off "for telnet from linux to drayos 192.168.1.1";
# with offload on, frames reach DrayOS with checksums it rejects.
if command -v ethtool >/dev/null; then
    for d in "$IFLAN" "$IFWAN" qemu-lan qemu-wan; do
        ethtool -K "$d" gro off gso off 2>/dev/null || true
    done
    ethtool -K br-lan tx off 2>/dev/null || true
else
    echo "[!] no ethtool (apt install ethtool); offload left on, which can stop"
    echo "    traffic reaching DrayOS even once it boots." >&2
fi

echo
ip -br addr show br-lan br-wan qemu-lan qemu-wan "$IFLAN" "$IFWAN" 2>/dev/null || true
echo
echo "[+] host is $MYLANIP on br-lan; DrayOS will be 192.168.1.1"
