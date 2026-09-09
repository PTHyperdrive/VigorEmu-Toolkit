# IDAPython: give EVERY still-anonymous function the best readable name it can
# get, from several sources, with a prefix that encodes how it was derived so
# you always know how much to trust it. General-purpose -- not tied to the CVE
# work. Run it LAST, after the confirmed symbols are in:
#
#   ida_load_symtab.py  ->  ida_names.py  ->  ida_rename_all.py
#   IDA:  File > Script file...  (Alt+F7)
#
# Prefixes:
#   (none)  confirmed symbol (ksymtab / cgi_* / hand-verified) -- left untouched
#   a_      auto: the function logs its own name  "[foo]" / "foo()"
#   s_      auto: named after the most DISTINCTIVE string it references
#   w_      auto: thin wrapper -- calls exactly one named function
#   (sub_)  genuinely un-nameable (no strings, no distinctive callee) -- kept
#
# Nothing here overwrites a real name; every derived name is verify-before-trust.

import re
import idc, idautils, idaapi, ida_funcs, ida_name

DEFAULT_PREFIXES = ("sub_", "nullsub_", "unknown_", "unnamed_", "loc_", "j_", "def_")

SELF = [re.compile(rb"\[([A-Za-z_][A-Za-z0-9_]{2,31})\]"),
        re.compile(rb"([A-Za-z_][A-Za-z0-9_]{2,31})\(\)")]

STOP = {"error","Error","ERROR","warning","Warning","fail","failed","assert",
        "NULL","null","info","Info","debug","DEBUG","func","value","VALUE",
        "Value","Type","type","Status","status","Location","Host","index",
        "Index","idx","length","Length","Name","name","Usage","Block","payload",
        "option","Connection","Packet","WEB","DOS","printf","sprintf","malloc",
        "free","memcpy","strcpy","strcmp","true","false","the","and","for"}


def is_default(n):
    return (not n) or any(n.startswith(p) for p in DEFAULT_PREFIXES)


def slug(b):
    s = re.sub(rb"[^A-Za-z0-9]+", b"_", b).strip(b"_")
    return s.decode("latin-1")[:28]


def good_string(b):
    if not (5 <= len(b) <= 80):
        return False
    if not re.search(rb"[A-Za-z]", b):
        return False
    letters = sum(c.isalpha() for c in b.decode("latin-1"))
    return letters >= 4                      # skip "%s=%d" style noise


def collect():
    """{func_ea: [strings]} and {string: num_funcs_referencing}."""
    per_func, str_funcs = {}, {}
    for fea in idautils.Functions():
        strs = []
        for item in idautils.FuncItems(fea):
            for dref in idautils.DataRefsFrom(item):
                b = idc.get_strlit_contents(dref, -1, idc.STRTYPE_C)
                if b and good_string(b):
                    strs.append(b)
        per_func[fea] = strs
        for b in set(strs):
            str_funcs[b] = str_funcs.get(b, 0) + 1
    return per_func, str_funcs


def self_name(strs):
    for pat in SELF:
        for b in strs:
            for m in pat.finditer(b):
                ident = m.group(1).decode("latin-1")
                if ident not in STOP and not ident.isdigit():
                    return ident
    return None


def distinctive(strs, str_funcs):
    """The string this function references that fewest OTHER functions do."""
    best, best_key = None, None
    for b in strs:
        # prefer unique (count 1), then longer
        key = (str_funcs.get(b, 999), -len(b))
        if best_key is None or key < best_key:
            best_key, best = key, b
    return best


def one_named_callee(fea):
    callees = set()
    for item in idautils.FuncItems(fea):
        for cref in idautils.CodeRefsFrom(item, 0):     # calls/jumps out
            f = ida_funcs.get_func(cref)
            if f and f.start_ea != fea:
                nm = ida_name.get_name(f.start_ea)
                if nm and not is_default(nm):
                    callees.add(nm)
    return next(iter(callees)) if len(callees) == 1 else None


def main():
    per_func, str_funcs = collect()
    used = set()
    for ea in idautils.Functions():
        nm = ida_name.get_name(ea)
        if nm:
            used.add(nm)

    stat = {"a": 0, "s": 0, "w": 0, "skip": 0, "kept": 0}
    for ea in idautils.Functions():
        cur = ida_name.get_name(ea)
        if not is_default(cur):
            stat["skip"] += 1                # already a real name
            continue
        strs = per_func.get(ea, [])
        pref = base = None
        ident = self_name(strs)
        if ident:
            pref, base = "a", ident
        else:
            d = distinctive(strs, str_funcs)
            if d is not None and str_funcs.get(d, 99) <= 6:   # fairly specific
                pref, base = "s", slug(d)
            else:
                callee = one_named_callee(ea)
                if callee:
                    pref, base = "w", callee.lstrip("_")
        if not base:
            stat["kept"] += 1                # leave as sub_ -- nothing to go on
            continue
        name = "%s_%s" % (pref, base)
        n = 2
        while name in used:
            name = "%s_%s_%d" % (pref, base, n); n += 1
        if ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
            used.add(name); stat[pref] += 1

    total = sum(stat[k] for k in ("a", "s", "w"))
    print("[rename_all] named %d functions:" % total)
    print("   a_ (self-logged name)   : %d" % stat["a"])
    print("   s_ (distinctive string) : %d" % stat["s"])
    print("   w_ (single-callee wrap) : %d" % stat["w"])
    print("   already had real names  : %d" % stat["skip"])
    print("   left as sub_ (no signal): %d" % stat["kept"])


main()
