# IDAPython: apply the names from sohod64.symbols.elf to the CURRENTLY OPEN DB.
#
# Use this when you already have a database on the raw sohod64.bin and don't want
# to reload. It parses the ELF .symtab in pure Python (no IDA ELF loader, no
# "Load IDS file" -- that menu is for IDA's own .ids format and rightly refuses
# an .elf) and calls set_name at each function VA.
#
#   IDA:  File > Script file...  > ida_load_symtab.py   (Alt+F7)
#         pick sohod64.symbols.elf when prompted
#         (default: out/ghidra/sohod64.symbols.elf next to this script)
#
# Image base must be 0x40000000 (the symbols' st_value are runtime VAs).

import os, struct
import idc, ida_funcs, ida_name, ida_kernwin

STT_FUNC = 2
SHT_SYMTAB = 2


def parse_symbols(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 1:
        raise ValueError("not an ELF32 (expected sohod64.symbols.elf)")
    e_shoff = struct.unpack_from("<I", d, 32)[0]
    e_shentsize, e_shnum = struct.unpack_from("<HH", d, 46)
    secs = [struct.unpack_from("<10I", d, e_shoff + i * e_shentsize) for i in range(e_shnum)]
    # each section: name, type, flags, addr, off, size, link, info, align, entsize
    syms = []
    for s in secs:
        if s[1] != SHT_SYMTAB:
            continue
        off, size, link, _info, _al, entsize = s[4], s[5], s[6], s[7], s[8], s[9]
        entsize = entsize or 16
        str_off, str_size = secs[link][4], secs[link][5]
        strtab = d[str_off:str_off + str_size]
        for o in range(off, off + size, entsize):
            st_name, st_value, _st_size, st_info, _st_other, _st_shndx = \
                struct.unpack_from("<IIIBBH", d, o)
            if st_name == 0 or st_value == 0:
                continue
            end = strtab.index(b"\x00", st_name)
            name = strtab[st_name:end].decode("latin-1")
            if not name:
                continue
            syms.append((st_value, name, (st_info & 0xF) == STT_FUNC))
    return syms


def main():
    here = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else ""
    default = os.path.join(here, "out", "ghidra", "sohod64.symbols.elf")
    path = ida_kernwin.ask_file(0, default if os.path.exists(default) else "*.elf",
                                "Pick sohod64.symbols.elf")
    if not path:
        print("[symtab] cancelled")
        return
    syms = parse_symbols(path)
    named = made = 0
    for va, name, is_func in syms:
        if is_func and ida_funcs.get_func(va) is None:
            if ida_funcs.add_func(va):
                made += 1
        if ida_name.set_name(va, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
            named += 1
    print("[symtab] %d symbols, %d names applied, %d functions created" % (len(syms), named, made))


main()
