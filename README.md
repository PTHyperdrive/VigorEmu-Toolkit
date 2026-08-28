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
sudo ./net.sh
```

Needs two host NICs. Under VMware, add a second adapter to the VM. If they
are not called `eth0`/`eth1`, edit `iflan`/`ifwan` at the top of `net.sh` --
check with `ip link`. The host takes `192.168.1.2`; DrayOS is `192.168.1.1`.

**5. Boot**

```sh
cd out/rootfs/firmware
sudo ./qemu.sh
```

Then `http://192.168.1.1/weblogin.htm`.

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
