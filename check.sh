#!/bin/bash
# One-shot diagnosis of why 192.168.1.1 is not answering.
# Run as root, in another terminal, while DrayOS is up.
#
#   sudo ./check.sh
LAN=${LAN:-qemu-lan}
BR=${BR:-br-lan}
IP=${IP:-192.168.1.1}

[ "$(id -u)" = 0 ] || { echo "run me as root" >&2; exit 1; }

echo "=== 1. links ==="
ip -br link show "$BR" "$LAN" 2>/dev/null
ip -br addr show "$BR" 2>/dev/null
carrier=$(cat "/sys/class/net/$LAN/carrier" 2>/dev/null || echo 0)
echo "    $LAN carrier=$carrier  (1 means QEMU is attached)"

echo
echo "=== 2. is DrayOS answering ARP? ==="
# ARP is the lowest level that proves the guest's stack is alive on this link.
( timeout 8 tcpdump -ni "$LAN" -c 20 -l arp or icmp or tcp 2>/dev/null > /tmp/cap.txt ) &
CAP=$!
sleep 1
if command -v arping >/dev/null; then
    arping -c 3 -I "$BR" "$IP" 2>&1 | tail -3
else
    echo "    (no arping; apt install iputils-arping for a cleaner answer)"
fi
ping -c 3 -W 1 -I "$BR" "$IP" 2>&1 | tail -3
wait $CAP 2>/dev/null
echo "--- captured on $LAN ---"
cat /tmp/cap.txt 2>/dev/null | head -20
echo

echo "=== 3. arp table ==="
ip neigh show dev "$BR" 2>/dev/null | sed 's/^/    /'

echo
echo "=== 4. is anything listening? ==="
for p in 80 443 23 21; do
    timeout 2 bash -c "echo > /dev/tcp/$IP/$p" 2>/dev/null \
        && echo "    port $p  OPEN" || echo "    port $p  no answer"
done

echo
echo "=== verdict ==="
if ! grep -q . /tmp/cap.txt 2>/dev/null; then
    echo "  Nothing at all on $LAN. DrayOS is not transmitting: its LAN"
    echo "  interface never came up, or it is bound to a different NIC than"
    echo "  the one on this tap. Check the guest with the Command Line"
    echo "  Console (option 2 on its Main Menu)."
elif grep -qi 'arp.*reply\|is-at' /tmp/cap.txt; then
    echo "  DrayOS answers ARP, so the link is fine and the guest's stack is"
    echo "  up. If no port answers, the problem is inside DrayOS -- httpd is"
    echo "  running but not serving, or bound elsewhere."
else
    echo "  Traffic on $LAN but no ARP reply from $IP. The guest is on the"
    echo "  link but not at that address, or its LAN MAC differs from the one"
    echo "  QEMU gave the virtio device (compare 'LAN MAC Address' on the"
    echo "  DrayOS console against ./lan_mac)."
fi
rm -f /tmp/cap.txt
