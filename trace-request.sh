#!/bin/bash
# Watch a live HTTP request travel through DrayOS, and print the real call
# stack from the RTOS task down to the CGI handler.
#
#   sudo ./trace-request.sh                       # traces /cgi-bin/wlogin.cgi
#   sudo ./trace-request.sh /cgi-bin/frmup.cgi
#   sudo ./trace-request.sh --resume              # just un-halt a stuck guest
#
# Needs the guest running with a gdb stub:  sudo GDBWAIT=1 supervise.sh ./qemu.sh
#
# It breaks on the dispatcher's `blr x7` -- the instruction that calls a CGI
# handler -- then walks the frame-pointer chain. AArch64 frame records are 16
# bytes (fp at +0, lr at +8); using +4 gives zeroes, which is the easy mistake.
set -uo pipefail

HERE=$(dirname "$(readlink -f "$0")")
IMG=${IMG:-$HOME/out/sohod64.symbols.elf}
HOSTIP=${HOSTIP:-192.168.1.1}
PORT=${PORT:-1234}
DISPATCH=0x40141d18          # cgi_stub(): blr x7

# A gdb that is killed while the target is stopped leaves the guest HALTED and
# the router dead. Always resume on the way out.
resume() {
    printf 'set pagination off\nset confirm off\nset architecture aarch64\n%s\ndelete breakpoints\ndetach\nquit\n' \
        "target remote :$PORT" > /tmp/.resume.gdb
    timeout 40 gdb-multiarch -batch -x /tmp/.resume.gdb >/dev/null 2>&1
    rm -f /tmp/.resume.gdb
}
trap resume EXIT

if [ "${1:-}" = "--resume" ]; then
    echo "[*] resuming the guest"; resume; trap - EXIT
    curl -s -m 6 --noproxy '*' -o /dev/null -w "  router HTTP %{http_code}\n" "http://$HOSTIP/" || true
    exit 0
fi

URLPATH=${1:-/cgi-bin/wlogin.cgi}
[ -f "$IMG" ] || { echo "no symbol image at $IMG (set IMG=...)" >&2; exit 1; }
pkill -f '[g]db-multiarch' 2>/dev/null; sleep 1

cat > /tmp/.trace.gdb <<GDB
set pagination off
set confirm off
set architecture aarch64
file $IMG
target remote :$PORT
break *$DISPATCH
continue

printf "\n=== cgi_stub() is about to call a handler ===\n"
printf "  handler   x7 = 0x%08x  ", \$x7
info symbol \$x7
printf "  args         w0=0x%x w1=0x%x w2=0x%x w3=0x%x\n", \$x0, \$x1, \$x2, \$x3
printf "  sp=0x%08x fp=0x%08x\n", \$sp, \$x29

printf "\n=== call stack: RTOS task -> handler ===\n"
printf "  (frame record is 16 bytes: fp at +0, lr at +8)\n"
set \$f = \$x29
set \$n = 0
set \$base = \$x29
while \$f > 0x40000000 && \$f < 0x50000000 && \$n < 16
  set \$ret = *(unsigned int*)(\$f + 8)
  printf "  #%-2d fp=0x%08x  ret=0x%08x  ", \$n, \$f, \$ret
  info symbol \$ret
  set \$f = *(unsigned int*)\$f
  set \$n = \$n + 1
end
printf "\n  stack used from task entry to here: %d bytes\n", \$f - \$base
printf "  (the last frame returns to DrayOS_TaskReturn -- the bottom of the\n"
printf "   task stack that OSTaskCreate seeded)\n"
detach
quit
GDB

echo "[*] tracing http://$HOSTIP$URLPATH"
timeout 100 gdb-multiarch -batch -x /tmp/.trace.gdb > /tmp/.trace.out 2>&1 &
GPID=$!
sleep 6
curl -s -m 5 --noproxy '*' -o /dev/null "http://$HOSTIP$URLPATH" 2>/dev/null &
wait $GPID 2>/dev/null

grep -vE '^warning|^Reading|^\[New|Try using|^The target|^0x0000' /tmp/.trace.out
rm -f /tmp/.trace.gdb /tmp/.trace.out
echo
echo "[*] resuming the guest"
