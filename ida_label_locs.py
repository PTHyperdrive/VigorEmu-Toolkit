# IDAPython: make loc_XXXXXXXX labels readable by their ROLE, so control flow in
# the big DrayOS switch-dispatch functions is skimmable. A loc_ is an intra-
# function branch target and has no "name" to recover, but its role usually can:
#
#   loop_<addr>   this label is the target of a BACKWARD branch (a loop head)
#   err_<addr>    the block only leads to an error/abort/log call (skip it)
#   L_<slug>      the block references one distinctive string (its purpose)
#   (loc_ kept)   ordinary fall-through / case target with no signal
#
# Run after the function-naming scripts (it uses their names to spot err/log
# callees). Only touches loc_/locret_ labels; never a real name.
#   IDA:  File > Script file...  (Alt+F7)

import re
import idc, idautils, ida_funcs, ida_name, ida_idaapi

ERR_HINTS = ("printf", "abort", "panic", "assert", "error", "_err", "fatal",
             "bug", "warn", "log", "_die", "reboot", "trap")
MAXWIN = 28                                  # instructions to scan per block

STOP = {"error", "Error", "ERROR", "fail", "failed", "NULL", "info", "debug",
        "assert", "value", "Type", "Status", "index", "length", "Name"}


def is_loc(n):
    return bool(n) and (n.startswith("loc_") or n.startswith("locret_"))


def good_string(b):
    return (5 <= len(b) <= 80 and re.search(rb"[A-Za-z]", b)
            and sum(c.isalpha() for c in b.decode("latin-1")) >= 4)


def slug(b):
    return re.sub(rb"[^A-Za-z0-9]+", b"_", b).strip(b"_").decode("latin-1")[:26]


def block(ea, end):
    """Instruction addresses from ea until a flow terminator or the next label."""
    out, cur, n = [], ea, 0
    while cur != idc.BADADDR and cur < end and n < MAXWIN:
        if cur != ea and is_loc(ida_name.get_name(cur)):
            break                            # next block starts here
        out.append(cur)
        m = idc.print_insn_mnem(cur).lower()
        if m in ("ret", "b", "br", "eret") or m.startswith("b."):
            break                            # unconditional flow end
        cur = idc.next_head(cur, end)
        n += 1
    return out


def is_loop_head(ea):
    for src in idautils.CodeRefsTo(ea, 1):
        if src > ea:                         # a branch coming from further down
            return True
    return False


def block_err(items):
    for it in items:
        for cref in idautils.CodeRefsFrom(it, 0):
            f = ida_funcs.get_func(cref)
            if not f:
                continue
            nm = (ida_name.get_name(f.start_ea) or "").lower()
            if any(h in nm for h in ERR_HINTS):
                return True
    return False


def block_string(items):
    best, best_key = None, None
    for it in items:
        for dref in idautils.DataRefsFrom(it):
            b = idc.get_strlit_contents(dref, -1, idc.STRTYPE_C)
            if b and good_string(b):
                key = -len(b)
                if best_key is None or key < best_key:
                    best_key, best = key, b
    if best:
        for pat in (re.compile(rb"\[([A-Za-z_][A-Za-z0-9_]{2,31})\]"),
                    re.compile(rb"([A-Za-z_][A-Za-z0-9_]{2,31})\(\)")):
            m = pat.search(best)
            if m and m.group(1).decode("latin-1") not in STOP:
                return m.group(1).decode("latin-1")
        return slug(best)
    return None


def main():
    used = set(ida_name.get_name(ea) for ea in idautils.Functions())
    stat = {"loop": 0, "err": 0, "str": 0}
    for fea in idautils.Functions():
        f = ida_funcs.get_func(fea)
        if not f:
            continue
        for ea in list(idautils.FuncItems(fea)):
            cur = ida_name.get_name(ea)
            if not is_loc(cur):
                continue
            items = block(ea, f.end_ea)
            new = None
            if is_loop_head(ea):
                new = "loop_%08x" % ea; stat["loop"] += 1
            elif block_err(items):
                new = "err_%08x" % ea; stat["err"] += 1
            else:
                s = block_string(items)
                if s:
                    base = "L_" + s
                    name, n = base, 2
                    while name in used:
                        name = "%s_%d" % (base, n); n += 1
                    new = name; stat["str"] += 1
            if new and ida_name.set_name(ea, new, ida_name.SN_NOCHECK | ida_name.SN_FORCE | ida_name.SN_LOCAL):
                used.add(new)

    print("[label_locs] relabelled loc_ targets:")
    print("   loop_ (loop heads)        : %d" % stat["loop"])
    print("   err_  (error/abort blocks): %d" % stat["err"])
    print("   L_    (string-bearing)    : %d" % stat["str"])
    print("   (all other loc_ kept as-is)")


main()
