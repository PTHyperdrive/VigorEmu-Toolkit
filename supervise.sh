#!/bin/bash
# The host side of the serial pipe: recvCmd plus /etc/runcommand/reboot, in
# one loop.
#
#   sudo ./supervise.sh [path/to/qemu.sh]
#
# DrayOS provisions itself over several boots. On each one it writes what it
# has produced back to the host through the patched QEMU --
#
#   memsave <addr> <size> x86      -> draycfg.cfg, draycert.cfg, ...
#   frmsave <addr> <size> <file>   -> v3910_ram_flash.bin
#
# -- and then asks to be restarted so it can load it:
#
#   [_virtcons_out:2752]======reboot qemu
#
# On the device recvCmd reads that off serial0 and runs /etc/runcommand/reboot,
# which is "killall qemu-system-aarch64; sleep 1; run.sh &". With nothing
# listening the request just repeats forever and the boot never settles.
set -uo pipefail

QEMU_SH=$(readlink -f "${1:-./qemu.sh}")
[ -x "$QEMU_SH" ] || { echo "no qemu.sh at $QEMU_SH" >&2; exit 1; }
cd "$(dirname "$QEMU_SH")"

MAX=${MAX:-10}

# QEMU's pipe chardev prefers <path>.in and <path>.out when both exist, and
# only falls back to a single bidirectional FIFO when they do not. Creating
# them gives one clean direction each -- guest output on .out, host input on
# .in -- instead of everyone sharing one FIFO and racing to read it.
for p in serial0.in serial0.out serial1.in serial1.out; do
    [ -p "$p" ] || { rm -f "$p"; mkfifo "$p"; }
done

# Hold both ends open for the whole run so a QEMU restart is not seen as EOF.
exec 3<> serial0.out
exec 4<> serial0.in

QPID=""
stop_qemu() {
    [ -n "$QPID" ] || return 0
    kill "$QPID" 2>/dev/null
    for _ in $(seq 20); do kill -0 "$QPID" 2>/dev/null || break; sleep 0.2; done
    kill -9 "$QPID" 2>/dev/null
    wait "$QPID" 2>/dev/null
    QPID=""
}
trap 'echo; echo "[supervise] stopping"; stop_qemu; exit 0' INT TERM EXIT

boot=0
while [ "$boot" -lt "$MAX" ]; do
    boot=$((boot + 1))
    echo "[supervise] ---- boot $boot ----"
    "$QEMU_SH" &
    QPID=$!

    restart=0
    while IFS= read -r -u 3 line; do
        case "$line" in
            *"reboot qemu"*)
                echo "[supervise] DrayOS asked for a restart"
                restart=1; break ;;
            *"halt"*|*"reboot linux"*)
                echo "[supervise] DrayOS asked to halt"
                restart=0; break ;;
        esac
    done

    stop_qemu
    [ "$restart" = 1 ] || break
    sleep 2
done

if [ "$boot" -ge "$MAX" ]; then
    echo "[supervise] gave up after $MAX boots. If it never settles, DrayOS is"
    echo "    asking for the same thing each time -- check which memsave or"
    echo "    frmsave line repeats, and whether that file is being written."
fi
