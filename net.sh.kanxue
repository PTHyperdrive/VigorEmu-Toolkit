#!/bin/bash
# Verbatim from the kanxue write-up (thread-289520), which took it from
# drayrt-release-gpl/output/rootfs/draytek/drayrc/rc.d/rc.41.setupif.sh
#
# Bridges the two host NICs to the two tap devices QEMU attaches to.
# Run as root, once, before qemu.sh.
#
# eth0/eth1 must exist. Under VMware, add a second network adapter to the VM
# so eth1 is present; "ip link" will show what they are actually called
# (Kali often uses eth0/eth1 already, but predictable names like ens33/ens37
# are common -- edit iflan/ifwan below if so).

iflan=eth0
ifwan=eth1
mylanip="192.168.1.2"

brctl delbr br-lan
brctl delbr br-wan

ip link add br-lan type bridge
ip tuntap add qemu-lan mode tap
brctl addif br-lan $iflan
brctl addif br-lan qemu-lan
ip addr flush dev $iflan
ifconfig br-lan $mylanip
ifconfig br-lan up
ifconfig qemu-lan up
ifconfig $iflan up

ip link add br-wan type bridge
ip tuntap add qemu-wan mode tap
brctl addif br-wan $ifwan
brctl addif br-wan qemu-wan
ip addr flush dev $ifwan
ifconfig br-lan $mylanip
ifconfig br-wan up
ifconfig qemu-wan up
ifconfig $ifwan up

brctl show

#for speed test
ethtool -K $iflan gro off
ethtool -K $iflan gso off

ethtool -K $ifwan gro off
ethtool -K $ifwan gso off

ethtool -K qemu-lan gro off
ethtool -K qemu-lan gso off

ethtool -K qemu-wan gro off
ethtool -K qemu-wan gso off

#for telnet from linux to drayos 192.168.1.1
ethtool -K br-lan tx off
