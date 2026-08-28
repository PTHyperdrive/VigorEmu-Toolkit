# vigorlab-cn-demo

A verbatim reproduction of the kanxue write-up
([bbs.kanxue.com/thread-289520](https://bbs.kanxue.com/thread-289520.1.htm)),
kept deliberately separate from `vigorlab`'s own `scripts/run-drayos.sh`.

`vigorlab` adapts the vendor scripts to stock QEMU. This does not adapt
anything: same binary, same flags, same values, same relative paths. If the
two behave differently, the difference is the finding.

## What differs from vigorlab's script

| | vigorlab | here |
|---|---|---|
| QEMU | stock, from the distro | DrayTek's, built from GPL source |
| device tree | `-device loader,file=virt.dtb,addr=0x5FF00000` | `-dtb DrayTek` |
| UFFS backing | 51.2 MB of zeros (`dd`) | empty file (`touch`) |
| serial | `null` chardev | `pipe` on real FIFOs |
| networking | user-mode | tap on bridges to real NICs |
| ivshmem | on Linux | always |

`-dtb DrayTek` is the reason their QEMU is needed. It is a magic value their
`hw/arm/boot.c` matches; `hw/core/loader.c` then relocates the generated tree
to `0x60000000 - 0x100000`, which is `0x5ff00000`. Stock QEMU has no such
handling and will fail trying to open a file called `DrayTek`.

## Steps

**1. Unpack the firmware**

```sh
vigorlab unpack v3910_3971.all out/
```

Gives `out/rootfs/` with `firmware/vqemu/sohod64.bin`, `firmware/run.sh` and
`firmware/magic_file`.

**2. Build DrayTek's QEMU**

```sh
sudo apt install -y build-essential libglib2.0-dev libpixman-1-dev
./build-qemu.sh ~/v3910_gpl.tar.bz2
```

The GPL release is a tarball of tarballs; QEMU is one nested member
(`source/qemu-2.12.1.tar.bz2`), so this extracts just that rather than
unpacking 670 MB or running their `./build`.

**3. Stage**

```sh
./stage.sh out/rootfs qemu-build/qemu-2.12.1/aarch64-softmmu/qemu-system-aarch64
```

**4. Network**

```sh
sudo ./net.sh          # tap devices only -- what you want
sudo ./net.sh down     # remove them again
```

The host takes `192.168.1.2` on the LAN tap; DrayOS is `192.168.1.1`. Your
real NIC is untouched.

`net.sh.kanxue` is the write-up's original, kept for reference. It does not
run on current Kali: `brctl` is no longer installed by default, and the
script is not idempotent, so a second run gives `RTNETLINK answers: File
exists` and `ioctl(TUNSETIFF): Device or resource busy` -- it never removes
the bridges and taps it created. `net.sh` does the same work with iproute2
and tears down first.

It also defaults to **not** bridging. The original enslaves two physical
interfaces and flushes their addresses; on a VMware guest with one adapter
that disconnects you. Bridging is only needed if other machines on the
physical network must reach the router:

```sh
sudo BRIDGE=1 IFLAN=ens33 IFWAN=ens37 ./net.sh
```

Both interfaces must exist -- add a second adapter to the VM first, and check
`ip -br link` for their real names.

**5. Boot**

```sh
cd out/rootfs/firmware
sudo ./qemu.sh
```

**It takes two boots.** There is no `/cfg` here, so the first boot finds no
configuration, extracts the built-in `gDefault`, and writes a real config out
through the patched QEMU:

```
[_virtcons_out:2752]======memsave 1257540056 5673080 x86
Memsave Config addr 0x4af489d8 size 5673080
```

Then it asks the host to restart it, forever:

```
[_virtcons_out:2752]======reboot qemu
```

That is not an error. On the device `recvCmd` reads those lines off `serial0`
and dispatches them through `/etc/runcommand/`, and `reboot qemu` is:

```sh
killall qemu-system-aarch64
sleep 1
/firmware/run.sh &
```

Nothing is listening here, so it repeats. Stop QEMU once `draycfg.cfg` has
appeared and run `./qemu.sh` again -- it picks the saved config up
automatically:

```sh
ls -l draycfg.cfg          # ~5.6 MB
sudo ./qemu.sh             # [*] using the config DrayOS saved
```

Then `http://192.168.1.1/weblogin.htm`. To go back to defaults, delete
`draycfg.cfg`.

## Notes on the script itself

`magic_file` is **not** created by `qemu.sh` — it comes from the firmware, and
holds `Using Default Config by Extract gDefault in DrayOS`. `stage.sh` checks
it is present.

`gci_magic` is written and then never loaded. It is vestigial, left over from
the 2962 version of the script; `draycfg.def` carries `GCI_SKIP` instead.

`$serial_option`, `$gdb_serial_option` and `$gdb_remote_option` are referenced
but never assigned, so they expand to nothing. Add `-s` to
`gdb_remote_option` for a gdb stub on :1234.

The UFFS store is created with `touch`, so it is empty and `-device loader`
places nothing. DrayOS formats the region itself on first boot.
