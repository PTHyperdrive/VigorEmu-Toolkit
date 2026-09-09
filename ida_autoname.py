# IDAPython: auto-name the remaining sub_40xxxxxx functions from the debug
# strings they reference. DrayOS is full of self-identifying strings --
# "GetCGI(): ...", "[virtcons_out] ...", "Linear malloc() ...", "%s: bad ..." --
# so a function that references one almost always IS that function (or its
# helper). This fills in the sea of anonymous functions after you've applied
# the real symbols.
#
#   Run order:  ida_load_symtab.py  ->  ida_names.py  ->  ida_autoname.py
#   IDA:  File > Script file...  (Alt+F7)
#
# Conservative: only touches functions still named sub_/nullsub_/unnamed, never
# overwrites a real name. Auto-derived names get an "a_" prefix so you can tell
# them apart from confirmed ones, and clashes get _2, _3, ...

import re
import idc, idautils, ida_funcs, ida_name, ida_bytes

# identifier hidden in a self-naming string. Only the bracket and paren forms
# are reliable -- a "foo:" label matches HTTP headers and protocol constants
# (Location:, Host:, Type:) and produces garbage, so it is deliberately omitted.
PATTERNS = [
    re.compile(rb"\[([A-Za-z_][A-Za-z0-9_]{2,31})\]"),        # [virtcons_out]
    re.compile(rb"([A-Za-z_][A-Za-z0-9_]{2,31})\(\)"),        # GetCGI()
]
DEFAULT_PREFIXES = ("sub_", "nullsub_", "unknown_", "unnamed_", "loc_", "j_")
# generic words / protocol labels that aren't useful function names
STOP = {"error", "Error", "ERROR", "warning", "Warning", "fail", "failed",
        "assert", "NULL", "null", "true", "false", "info", "Info", "debug",
        "DEBUG", "func", "the", "and", "for", "not", "with", "size", "len",
        "buf", "data", "value", "VALUE", "Value", "Type", "type", "TYPE",
        "Status", "status", "Location", "Host", "index", "Index", "INDEX",
        "idx", "length", "Length", "Name", "name", "Usage", "Block", "payload",
        "option", "Connection", "Packet", "WEB", "DOS", "printf", "sprintf",
        "malloc", "free", "memcpy", "strcpy", "strcmp"}


def is_default(name):
    return (not name) or any(name.startswith(p) for p in DEFAULT_PREFIXES)


def strings_in_func(ea):
    """Every string constant referenced from inside function at ea."""
    out = []
    for item in idautils.FuncItems(ea):
        for dref in idautils.DataRefsFrom(item):
            s = idc.get_strlit_contents(dref, -1, idc.STRTYPE_C)
            if s and 4 <= len(s) <= 120:
                out.append(s)
    return out


def candidate(strs):
    """Pick the best identifier from a function's strings."""
    for pat in PATTERNS:               # honour the best-form order
        hits = {}
        for s in strs:
            for m in pat.finditer(s):
                ident = m.group(1).decode("latin-1")
                if ident in STOP or ident.isdigit():
                    continue
                hits[ident] = hits.get(ident, 0) + 1
        if hits:
            # most frequent, then longest, for stability
            return max(hits, key=lambda k: (hits[k], len(k)))
    return None


def main():
    used = set()
    for ea in idautils.Functions():
        nm = ida_name.get_name(ea)
        if not nm:
            continue
        used.add(nm)

    named = 0
    for ea in idautils.Functions():
        cur = ida_name.get_name(ea)
        if not is_default(cur):
            continue
        cand = candidate(strings_in_func(ea))
        if not cand:
            continue
        base = "a_" + cand
        name = base
        n = 2
        while name in used:
            name = "%s_%d" % (base, n)
            n += 1
        if ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
            used.add(name)
            named += 1
    print("[autoname] named %d previously-anonymous functions from their strings" % named)
    print("           (a_ prefix = auto-derived from a debug string, verify before trusting)")


main()
