#!/bin/bash
# The host side of the serial pipe: recvCmd plus /etc/runcommand/reboot, in
# one loop. Run it with sudo -- the tap devices need root, and so does the
# state qemu.sh writes.
#
#   sudo ./supervise.sh [path/to/qemu.sh]
#   sudo ./supervise.sh --reset [path/to/qemu.sh]     start from scratch
#
# DrayOS provisions itself over several boots, writing what it produces back
# to the host through the patched QEMU (memsave / frmsave) and then asking to
# be restarted so it can load it. On the device recvCmd reads that off serial0
# and runs /etc/runcommand/reboot: killall qemu-system-aarch64, then run.sh.
set -uo pipefail

RESET=0
if [ "${1:-}" = "--reset" ]; then RESET=1; shift; fi

QEMU_SH=$(readlink -f "${1:-./qemu.sh}")
[ -x "$QEMU_SH" ] || { echo "no qemu.sh at $QEMU_SH" >&2; exit 1; }
cd "$(dirname "$QEMU_SH")"

[ "$(id -u)" = 0 ] || echo "[!] not root: the tap devices and the state files" \
                           "qemu.sh writes both need it. Use sudo." >&2

MAX=${MAX:-10}

if [ "$RESET" = 1 ]; then
    echo "[supervise] clearing saved state"
    rm -f draycfg.cfg draycert.cfg drayf2.cfg license.cfg draycfg.default \
          v3910_ram_flash.bin lan_mac ../data/uffs/* 2>/dev/null
fi

# A QEMU left over from a previous run still holds qemu-lan, and the next one
# fails with "could not configure /dev/net/tun: Device or resource busy".
if pgrep -x qemu-system-aarch64 >/dev/null 2>&1; then
    echo "[supervise] killing a leftover qemu-system-aarch64"
    pkill -x qemu-system-aarch64
    sleep 2
    pkill -9 -x qemu-system-aarch64 2>/dev/null
fi

# QEMU's pipe chardev prefers <path>.in and <path>.out when both exist, and
# falls back to one bidirectional FIFO otherwise. Two one-way pipes stop QEMU
# and the reader racing on the same one.
for p in serial0.in serial0.out serial1.in serial1.out; do
    [ -p "$p" ] || { rm -f "$p"; mkfifo "$p"; }
done

# Held open for the whole run so a QEMU restart is not seen as EOF.
exec 3<> serial0.out
exec 4<> serial0.in

QPID=""
stop_qemu() {
    [ -n "$QPID" ] || return 0
    kill "$QPID" 2>/dev/null
    for _ in $(seq 25); do kill -0 "$QPID" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$QPID" 2>/dev/null
    wait "$QPID" 2>/dev/null
    QPID=""
}
drain() { while read -r -t 0.1 -u 3 _ 2>/dev/null; do :; done; }
trap 'echo; echo "[supervise] stopping"; stop_qemu; exit 0' INT TERM

boot=0
while [ "$boot" -lt "$MAX" ]; do
    boot=$((boot + 1))
    # Anything still buffered belongs to the QEMU we just killed. Without this
    # its last "reboot qemu" lines fire instant restarts and the loop spins
    # without ever really booting.
    drain
    echo "[supervise] ---- boot $boot ----"
    started=$SECONDS
    "$QEMU_SH" &
    QPID=$!

    restart=0
    while kill -0 "$QPID" 2>/dev/null; do
        if IFS= read -r -t 2 -u 3 line; then
            case "$line" in
                *"reboot qemu"*)
                    echo "[supervise] DrayOS asked for a restart"; restart=1; break ;;
                *halt*|*"reboot linux"*)
                    echo "[supervise] DrayOS asked to halt"; break ;;
            esac
        fi
    done

    if [ "$restart" = 0 ] && ! kill -0 "$QPID" 2>/dev/null; then
        wait "$QPID" 2>/dev/null; rc=$?
        QPID=""
        if [ $((SECONDS - started)) -lt 5 ]; then
            echo "[supervise] QEMU exited after $((SECONDS - started))s (rc=$rc)."
            echo "    That is a startup failure, not a boot. Run it directly to"
            echo "    see the error:   sudo $QEMU_SH"
            echo "    Common ones: 'Device or resource busy' means a leftover"
            echo "    QEMU or a tap still held; 'Permission denied' means state"
            echo "    files owned by root and you are not."
            exit 1
        fi
        echo "[supervise] QEMU exited on its own after $((SECONDS - started))s"
        break
    fi

    stop_qemu
    [ "$restart" = 1 ] || break
    sleep 2
done

stop_qemu
if [ "$boot" -ge "$MAX" ]; then
    echo "[supervise] gave up after $MAX boots. If the same memsave or frmsave"
    echo "    line repeats every time, that file is not being reloaded --"
    echo "    check the path DrayOS sends against the one qemu.sh passes to"
    echo "    -device loader."
fi
