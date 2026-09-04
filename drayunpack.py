#!/usr/bin/env python3
"""Standalone DrayTek .all unpacker — no dependencies, no vigorlab checkout.

This is a single-file vendor of vigorlab's lz4 + archives + images modules
(github.com/PTHyperdrive/vigorlab), folded together so VigorEmu-Toolkit can
unpack an image on its own. The canonical, documented source is vigorlab; keep
the two in step if either changes.

    python3 drayunpack.py <firmware.all> <outdir> [--dtbs]

Produces, for an ARM64 image: outdir/Image, outdir/rootfs/, and outdir/
sohod64.bin (DrayOS itself, surfaced with its sha256). For a MIPS image:
bootloader.bin, kernel.bin, memory.bin and webfs.pfs.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import sys
from dataclasses import dataclass, field

# The images code below refers to lz4.X and archives.X; everything lives in
# this one module, so point those names at ourselves.
lz4 = archives = sys.modules[__name__]

# ===========================================================================
# LZ4 — block, DrayTek chunked container (aa1d7f50), LZ4 legacy frame
# ===========================================================================

CHUNKED_MAGIC = bytes.fromhex("aa1d7f50")
LEGACY_MAGIC = bytes.fromhex("02214c18")
CHUNKED_BLOCK_MAX = 0x10000
LEGACY_BLOCK_MAX = 8 << 20
STORED_FLAG = 0x90000000
MIN_MATCH = 4
_EXTEND = 0xFF


class Lz4Error(Exception):
    pass


def _extended_length(src, ip, length):
    n = len(src)
    while True:
        if ip >= n:
            raise Lz4Error("truncated length extension at offset %d" % ip)
        b = src[ip]
        ip += 1
        length += b
        if b != _EXTEND:
            return length, ip


def block(src, expected_size=None):
    n = len(src)
    if n == 0:
        return b""
    out = bytearray()
    ip = 0
    while ip < n:
        token = src[ip]
        ip += 1
        literals = token >> 4
        if literals == 15:
            literals, ip = _extended_length(src, ip, literals)
        if literals:
            if ip + literals > n:
                raise Lz4Error("literal run of %d overruns input at %d" % (literals, ip))
            out += src[ip:ip + literals]
            ip += literals
        if ip == n:
            break
        if ip + 2 > n:
            raise Lz4Error("truncated match offset at %d" % ip)
        offset = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if offset == 0:
            raise Lz4Error("zero match offset at %d" % (ip - 2))
        if offset > len(out):
            raise Lz4Error("match offset %d reaches before %d decoded bytes"
                           % (offset, len(out)))
        match = token & 0x0F
        if match == 15:
            match, ip = _extended_length(src, ip, match)
        match += MIN_MATCH
        start = len(out) - offset
        if offset >= match:
            out += out[start:start + match]
        else:
            for i in range(start, start + match):
                out.append(out[i])
    if expected_size is not None and len(out) != expected_size:
        raise Lz4Error("decompressed %d bytes, expected %d" % (len(out), expected_size))
    return bytes(out)


def _frame(data, offset, block_max, honour_stored, stop_after=None):
    pos, chunks, count = offset, [], 0
    while pos + 4 <= len(data):
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if size == 0:
            break
        if honour_stored and size & STORED_FLAG:
            size &= ~STORED_FLAG
            chunks.append(data[pos:pos + size])
        else:
            if size > 2 * block_max or pos + size > len(data):
                pos -= 4
                break
            chunks.append(block(data[pos:pos + size]))
        pos += size
        count += 1
        if stop_after and count >= stop_after:
            break
    return b"".join(chunks), count, pos


def chunked(data):
    if data[:4] != CHUNKED_MAGIC:
        raise Lz4Error("bad container magic %s, expected %s"
                       % (data[:4].hex(), CHUNKED_MAGIC.hex()))
    out, count, _ = _frame(data, 4, CHUNKED_BLOCK_MAX, honour_stored=True)
    return out, count


def legacy(data, offset, stop_after=None):
    if data[offset:offset + 4] != LEGACY_MAGIC:
        raise Lz4Error("no LZ4 legacy magic at 0x%X" % offset)
    out, _, _ = _frame(data, offset + 4, LEGACY_BLOCK_MAX, honour_stored=False,
                       stop_after=stop_after)
    return out


# ===========================================================================
# Archives — PFS/1.0 (MIPS web fs) and cpio newc (ARM64 initramfs)
# ===========================================================================

PFS_MAGICS = (b"PFS/1.0", b"DLM/1.0")
PFS_HEADER = 16
PFS_COUNT_OFFSET = 14
CPIO_MAGIC = b"070701"
CPIO_HEADER = 110
CPIO_TRAILER = "TRAILER!!!"
S_IFMT, S_IFDIR, S_IFLNK, S_IFREG = 0o170000, 0o040000, 0o120000, 0o100000


@dataclass
class Entry:
    name: str
    mode: int
    data: bytes

    @property
    def is_dir(self):
        return self.mode & S_IFMT == S_IFDIR

    @property
    def is_symlink(self):
        return self.mode & S_IFMT == S_IFLNK

    @property
    def is_file(self):
        return self.mode & S_IFMT == S_IFREG


def is_pfs(buf):
    return buf[:7] in PFS_MAGICS


def pfs_entries(buf):
    if not is_pfs(buf):
        raise ValueError("not a PFS archive: %r" % buf[:7])
    count = struct.unpack_from("<H", buf, PFS_COUNT_OFFSET)[0]
    name_len = buf.find(b"\0", PFS_HEADER) - PFS_HEADER
    while buf[PFS_HEADER + name_len] == 0:
        name_len += 1
    node_size = name_len + 12
    pos = PFS_HEADER + node_size * count
    for i in range(count):
        node = buf[PFS_HEADER + i * node_size: PFS_HEADER + (i + 1) * node_size]
        name = node[:name_len].split(b"\0")[0].replace(b"\\", b"/").decode("latin-1")
        _inode, _offset, size = struct.unpack("<III", node[name_len:])
        body = buf[pos:pos + size]
        pos += size
        if name:
            yield Entry(name, S_IFREG, body)


def cpio_entries(buf):
    off = 0
    while off + CPIO_HEADER <= len(buf):
        if buf[off:off + 6] != CPIO_MAGIC:
            break
        try:
            fields = [int(buf[off + 6 + i * 8: off + 14 + i * 8], 16) for i in range(13)]
        except ValueError:
            break
        mode, size, namesize = fields[1], fields[6], fields[11]
        name = buf[off + CPIO_HEADER: off + CPIO_HEADER + namesize - 1]
        body = (off + CPIO_HEADER + namesize + 3) & ~3
        off = (body + size + 3) & ~3
        decoded = name.decode("latin-1")
        if decoded == CPIO_TRAILER:
            break
        yield Entry(decoded, mode, buf[body:body + size])


def extract(entries, out_dir, on_file=None):
    root = os.path.abspath(out_dir)
    os.makedirs(root, exist_ok=True)
    stats = {"files": 0, "dirs": 0, "symlinks": 0, "unlinked": 0,
             "bytes": 0, "skipped": 0}
    unlinked = []
    for entry in entries:
        dst = os.path.abspath(os.path.join(root, entry.name.lstrip("/")))
        if os.path.commonpath((root, dst)) != root:
            stats["skipped"] += 1
            continue
        if entry.is_dir:
            os.makedirs(dst, exist_ok=True)
            stats["dirs"] += 1
        elif entry.is_symlink:
            target = entry.data.split(b"\0")[0].decode("latin-1")
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                if not os.path.lexists(dst):
                    os.symlink(target, dst)
                stats["symlinks"] += 1
            except OSError:
                unlinked.append("%s -> %s" % (entry.name, target))
                stats["unlinked"] += 1
        else:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            body = on_file(entry.data) if on_file else entry.data
            with open(dst, "wb") as fh:
                fh.write(body)
            stats["files"] += 1
            stats["bytes"] += len(body)
    if unlinked:
        with open(os.path.join(root, "symlinks.txt"), "w") as fh:
            fh.write("\n".join(unlinked) + "\n")
    return stats


# ===========================================================================
# Images — RTOS (MIPS) and ARM64 families
# ===========================================================================

BOOT_MARKER = 0xA55AA55A
RTOS_HEADER = 0x100
MD5_TAG = b"DrayTekImageMD5\x00"
ARM64_HEADERS = {bytes.fromhex("06020106"): 0x28, b"6216": 0x0D}
ARM64_MAGIC = b"ARM\x64"
ARM64_MAGIC_OFFSET = 0x38
FDT_MAGIC = bytes.fromhex("d00dfeed")
RTOS, ARM64 = "rtos", "arm64"
PLAIN, ENCRYPTED = "plain", "encrypted"
DRAYOS_PAYLOADS = (("firmware", "vqemu", "sohod64.bin"),
                   ("firmware", "vqemu", "sohod.bin"))
DRAYTEK_RUN_SH = ("firmware", "run.sh")


@dataclass
class Section:
    name: str
    offset: int
    size: int
    note: str = ""


@dataclass
class Image:
    data: bytes
    family: str
    kind: str = PLAIN
    model: str = ""
    version: str = ""
    sections: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    bootloader: bytes = b""
    kernel: bytes = b""
    webfs: bytes = b""
    kernel_offset: int = None
    text_offset: int = 0
    image_size: int = 0
    dtbs: list = field(default_factory=list)
    initramfs_offset: int = None

    @property
    def bootable(self):
        return self.kind == PLAIN


def _u32be(data, off):
    return struct.unpack_from(">I", data, off)[0]


def verify_md5(data):
    tag = data.rfind(MD5_TAG)
    if tag < 0:
        return None
    start = tag + len(MD5_TAG)
    claimed = data[start:start + 32].decode("ascii", "replace")
    actual = hashlib.md5(data[:tag]).hexdigest()
    return claimed == actual, claimed, actual


def looks_like_rtos(data):
    if len(data) < 0x8000:
        return False
    size = _u32be(data, 0)
    if not (RTOS_HEADER < size <= len(data)):
        return False
    limit = min(len(data) - 4, 0x80000)
    return any(_u32be(data, o) == BOOT_MARKER for o in range(RTOS_HEADER, limit, 4))


def looks_like_arm64(data):
    if len(data) < 0x10000:
        return False
    if not any(data[:len(m)] == m for m in ARM64_HEADERS):
        return False
    return _find_kernel(data) is not None or b"vmlinuz" in data[:0x400]


def identify(data):
    if looks_like_rtos(data):
        return RTOS
    if looks_like_arm64(data):
        return ARM64
    return None


def _find_kernel(data):
    for m in re.finditer(re.escape(ARM64_MAGIC), data):
        head = m.start() - ARM64_MAGIC_OFFSET
        if head < 0 or head + 0x40 > len(data):
            continue
        text_offset, image_size, flags = struct.unpack_from("<QQQ", data, head + 8)
        if 0 < image_size < (1 << 32):
            return head, text_offset, image_size, flags
    return None


def _find_dtbs(data):
    out = []
    for m in re.finditer(re.escape(FDT_MAGIC), data):
        o = m.start()
        if o + 28 > len(data):
            continue
        _, total, off_s, off_str, _, ver, _ = struct.unpack_from(">7I", data, o)
        if ver in (16, 17) and 0x30 < total < (1 << 21) and o + total <= len(data) \
                and off_s < total and off_str < total:
            out.append(Section("dtb", o, total))
    return out


def find_initramfs(data):
    for m in re.finditer(re.escape(LEGACY_MAGIC), data):
        try:
            head = legacy(data, m.start(), stop_after=1)
        except Exception:
            continue
        if head[:6] == CPIO_MAGIC:
            return m.start()
    return None


def _parse_rtos(data):
    img = Image(data, RTOS)
    img.model = data[0x1A:0x20].split(b"\0")[0].decode("latin-1")
    img.version = data[0x20:0x40].split(b"\0")[0].decode("latin-1")
    checked = verify_md5(data)
    if checked is None:
        img.notes.append("no DrayTekImageMD5 trailer")
    elif checked[0]:
        img.notes.append("image MD5 %s verified" % checked[1])
    else:
        img.notes.append("image MD5 MISMATCH: %s != %s" % (checked[1], checked[2]))
    off = RTOS_HEADER
    while off + 4 <= len(data) and _u32be(data, off) != BOOT_MARKER:
        off += 4
    if off + 4 > len(data):
        raise ValueError("bootloader end marker A55AA55A not found")
    img.bootloader = data[RTOS_HEADER:off]
    img.sections.append(Section("bootloader", RTOS_HEADER, off - RTOS_HEADER,
                                "raw big-endian MIPS"))
    size = _u32be(data, off + 4)
    start = off + 8
    img.kernel, blocks = chunked(data[start:start + size])
    img.sections.append(Section("kernel", start, size,
                                "LZ4, %d blocks -> %d bytes" % (blocks, len(img.kernel))))
    bin_size = _u32be(data, 0)
    if bin_size + 8 < len(data):
        web_len = _u32be(data, bin_size + 4)
        img.webfs, blocks = chunked(data[bin_size + 8:bin_size + 8 + web_len])
        img.sections.append(Section("webfs", bin_size + 8, web_len,
                                    "LZ4 -> PFS, %d bytes" % len(img.webfs)))
    return img


def _parse_arm64(data):
    version_offset = next(o for m, o in ARM64_HEADERS.items() if data[:len(m)] == m)
    img = Image(data, ARM64)
    img.version = data[version_offset:version_offset + 0x18].split(b"\0")[0] \
        .decode("latin-1", "replace")
    found = _find_kernel(data)
    if found is None:
        img.kind = ENCRYPTED
        img.notes.append("ChaCha20 encrypted; the key lives in the bootloader, "
                         "not in the image")
        nonce = data.find(b"nonce")
        if nonce >= 0:
            img.notes.append("nonce %r is in the clear"
                             % data[nonce + 9:nonce + 21].decode("latin-1", "replace"))
        return img
    img.kernel_offset, img.text_offset, img.image_size, _flags = found
    img.sections.append(Section("kernel", img.kernel_offset,
                                len(data) - img.kernel_offset, "ARM64 Linux Image"))
    img.dtbs = _find_dtbs(data)
    img.initramfs_offset = find_initramfs(data)
    if img.initramfs_offset is not None:
        img.sections.append(Section("initramfs", img.initramfs_offset, 0,
                                    "LZ4 legacy frame -> cpio, inside the kernel"))
    return img


def parse(data):
    family = identify(data)
    if family == RTOS:
        return _parse_rtos(data)
    if family == ARM64:
        return _parse_arm64(data)
    raise ValueError("unrecognised image: starts %s" % data[:8].hex())


def kernel_bytes(img):
    if img.family == RTOS:
        return img.bootloader + img.kernel
    if img.kernel_offset is None:
        raise ValueError("no kernel in this image")
    return img.data[img.kernel_offset:]


def rootfs_entries(img):
    if img.family == RTOS:
        if not img.webfs:
            return iter(())
        return pfs_entries(img.webfs)
    if img.initramfs_offset is None:
        raise ValueError("no initramfs found")
    return cpio_entries(legacy(img.data, img.initramfs_offset))


def find_drayos_payload(rootfs):
    for parts in DRAYOS_PAYLOADS:
        path = os.path.join(rootfs, *parts)
        if os.path.exists(path):
            return path
    return None


# ===========================================================================
# CLI
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(description="Unpack a DrayTek .all firmware image.")
    ap.add_argument("firmware")
    ap.add_argument("outdir")
    ap.add_argument("--dtbs", action="store_true",
                    help="also write the ARM64 board device trees to outdir/dtb/")
    args = ap.parse_args()

    with open(args.firmware, "rb") as fh:
        data = fh.read()
    img = parse(data)

    print("[+] %s" % os.path.basename(args.firmware))
    print("    family : %s" % ("MIPS DrayOS" if img.family == RTOS else "ARM64 Linux"))
    if img.model:
        print("    model  : %s" % img.model)
    print("    version: %s" % img.version)
    for s in img.sections:
        print("    section: %-11s @ 0x%08X  %s" % (s.name, s.offset, s.note))
    for n in img.notes:
        print("    note   : %s" % n)

    if not img.bootable:
        print("\n[x] Encrypted image: nothing to unpack without the key.")
        return 1

    out = args.outdir
    os.makedirs(out, exist_ok=True)

    def write(name, blob):
        path = os.path.join(out, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        print("[+] %-16s %10d bytes" % (name, len(blob)))

    write("header.bin", data[:RTOS_HEADER] if img.family == RTOS else data[:0x40])
    if img.family == RTOS:
        write("bootloader.bin", img.bootloader)
        write("kernel.bin", img.kernel)
        write("memory.bin", kernel_bytes(img))
        if img.webfs:
            write("webfs.pfs", img.webfs)
    else:
        write("Image", kernel_bytes(img))
        if args.dtbs and img.dtbs:
            dtb_dir = os.path.join(out, "dtb")
            os.makedirs(dtb_dir, exist_ok=True)
            for i, d in enumerate(img.dtbs):
                with open(os.path.join(dtb_dir, "board_%02d.dtb" % i), "wb") as fh:
                    fh.write(data[d.offset:d.offset + d.size])
            print("[+] %-16s %10d trees" % ("dtb/", len(img.dtbs)))

    try:
        entries = rootfs_entries(img)
    except ValueError as exc:
        print("[*] no root filesystem: %s" % exc)
        return 0

    def maybe_nested(blob):
        if blob[:4] == CHUNKED_MAGIC:
            try:
                return chunked(blob)[0]
            except Lz4Error:
                pass
        return blob

    rootfs = os.path.join(out, "rootfs")
    st = extract(entries, rootfs, on_file=maybe_nested)
    print("[+] rootfs           %d files (%d bytes), %d dirs, %d symlinks"
          % (st["files"], st["bytes"], st["dirs"], st["symlinks"]))
    if st["skipped"]:
        print("    %d entries skipped (path traversal)" % st["skipped"])

    payload = find_drayos_payload(rootfs)
    if payload:
        dest = os.path.join(out, os.path.basename(payload))
        with open(payload, "rb") as fh:
            blob = fh.read()
        with open(dest, "wb") as fh:
            fh.write(blob)
        print("[+] %-16s %10d bytes  DrayOS itself" % (os.path.basename(dest), len(blob)))
        print("    sha256 %s" % hashlib.sha256(blob).hexdigest())
        run_sh = os.path.join(rootfs, *DRAYTEK_RUN_SH)
        if os.path.exists(run_sh):
            print("    DrayTek's own launch script: %s"
                  % os.path.relpath(run_sh, out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
