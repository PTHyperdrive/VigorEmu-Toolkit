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
sudo ./net.sh          # set up
sudo ./net.sh down     # tear down
```

The write-up does this in two steps, and the first is easy to misread:

```sh
sudo ip tuntap add dev eth0 mode tap
sudo ip tuntap add dev eth1 mode tap
```

`eth0` and `eth1` are **tap devices it creates**, not physical NICs. Its
`rc.41.setupif.sh` then bridges each to the tap QEMU attaches to:

```
br-lan = eth0 + qemu-lan,  192.168.1.2
br-wan = eth1 + qemu-wan
```

So the whole topology is virtual. **No second network adapter is needed**, and
nothing touches the interface this machine actually uses. `net.sh` does both
steps.

If your real adapter is already called `eth0` -- common on a VMware Kali --
the script refuses rather than bridging it, and you pick other names:

```sh
sudo IFLAN=dray0 IFWAN=dray1 ./net.sh
```

`net.sh.kanxue` is the original, kept for reference. It calls `brctl`, which
current Kali does not install, and never removes what it made, so a second run
fails with `RTNETLINK answers: File exists` and `ioctl(TUNSETIFF): Device or
resource busy`.

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

Nothing is listening here, so it repeats. And it is not one restart: DrayOS
provisions itself over several boots, writing the config, then the
certificate, then the 48 MB flash image, asking to be restarted after each.

`supervise.sh` is that missing half -- `recvCmd` and `/etc/runcommand/reboot`
in one loop. Run it instead of `qemu.sh`:

```sh
cd out/rootfs/firmware
sudo /path/to/supervise.sh --reset ./qemu.sh
```

**Always use sudo.** The tap devices need root, and so do the state files
`qemu.sh` writes. Mixing a root run with a plain one leaves files root owns
and the next plain run fails with `./platform: Permission denied`.

`--reset` clears saved state first: the config, certificate, flash image and
`lan_mac`. Use it whenever you change something that affects provisioning,
because a config saved under the old settings will be reloaded otherwise.

```
[supervise] ---- boot 1 ----
[*] first boot: no saved config ...
Memsave Config addr 0x4af489d8 size 5673080
[supervise] DrayOS asked for a restart
[supervise] ---- boot 2 ----
[*] using the config DrayOS saved (5673080 bytes)
...
```

It stops when DrayOS stops asking, or after `MAX` boots (default 10).

Then `http://192.168.1.1/weblogin.htm`. To start over, delete `draycfg.cfg`,
`draycert.cfg`, `v3910_ram_flash.bin` and `lan_mac`.

### Two fixes the original needs before it can settle

Both only matter once config persistence works, which is why the write-up
does not hit them in a single run.

**The MAC must not change.** `qemu.sh` picks a random one on every launch.
DrayOS saves board info containing it, sees different hardware next boot and
re-provisions, so it never stops asking to restart. It is now generated once
into `lan_mac` and reused.

**The flash image must be reloaded from where it is written.** DrayOS sends

```
frmsave <addr> <size> ./v3910_ram_flash.bin
```

and the patched QEMU writes that relative to its own working directory --
this one. The original then reloads `../data/uffs/v3910_ram_flash.bin`, a
different and empty file, so UFFS came up unformatted every time. That is
what kept the settings store invalid (`[SS][Init] Unknown Signature ... do
convert`) and kept the restart requests coming. The binary carries both
prefixes, `/data/uffs/` for cavium and `./` for x86, and this runs as x86.

`supervise.sh` also creates `serial0.in` and `serial0.out`. QEMU's pipe
chardev prefers those over a single bidirectional FIFO, which gives guest
output and host input one direction each instead of both sides racing to read
the same pipe.

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
