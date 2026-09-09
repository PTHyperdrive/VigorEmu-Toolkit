# IDAPython: name the leftover anonymous DrayOS internals by their SUBSYSTEM,
# inferred from their named callers. These are non-exported statics / RTOS /
# libc helpers with no strings of their own, so string-naming can't touch them
# -- but a helper called mostly by netif_* / ip_* / OS* functions belongs to
# that subsystem, and that hint is what you need to navigate.
#
# Run LAST, after every other naming script (it reads their names):
#   ida_load_symtab -> ida_names -> ida_rename_all -> ida_label_locs -> this
#   IDA:  File > Script file...  (Alt+F7)
#
#   k_<subsys>_<addr>   >=60% of named callers share a subsystem prefix
#   (sub_ kept)         no named callers, or callers too scattered to cluster
#
# k_ = kernel/internal, clustered by caller. A hint, not a proven identity.

import re
from collections import Counter
import idc, idautils, ida_funcs, ida_name

DEFAULT_PREFIXES = ("sub_", "nullsub_", "unknown_", "unnamed_", "loc_", "j_", "def_")
STRIP = ("a_", "s_", "w_", "k_", "cgi_", "drayos_")


def is_default(n):
    return (not n) or any(n.startswith(p) for p in DEFAULT_PREFIXES)


def subsystem(name):
    """Leading subsystem token of a caller name: netif_rx->netif, OSSemPend->OS,
    ip_rcv->ip, a_IGMP->IGMP, s_PPPoE_x->PPPoE."""
    for p in STRIP:
        if name.startswith(p):
            name = name[len(p):]
            break
    if not name:
        return None
    m = re.match(r"([A-Z]{2,})[A-Z][a-z]", name)      # OSSemPend -> OS
    if m:
        return m.group(1)
    m = re.match(r"([A-Za-z][A-Za-z0-9]*?)(?:_|$)", name)  # netif_rx -> netif
    tok = m.group(1) if m else name
    return tok if len(tok) >= 2 else None


def named_callers(fea):
    subs = []
    for src in idautils.CodeRefsTo(fea, 0):
        f = ida_funcs.get_func(src)
        if not f or f.start_ea == fea:
            continue
        nm = ida_name.get_name(f.start_ea)
        if nm and not is_default(nm):
            s = subsystem(nm)
            if s:
                subs.append(s)
    return subs


def main():
    used = set(ida_name.get_name(ea) for ea in idautils.Functions())
    named = 0
    for ea in idautils.Functions():
        if not is_default(ida_name.get_name(ea)):
            continue
        subs = named_callers(ea)
        if len(subs) < 2:
            continue
        top, cnt = Counter(subs).most_common(1)[0]
        if cnt / float(len(subs)) < 0.60:      # callers too scattered
            continue
        name = "k_%s_%08x" % (top, ea)
        if name not in used and ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
            used.add(name)
            named += 1
    print("[cluster_internal] gave %d internal helpers a subsystem hint (k_<subsys>_)" % named)
    print("                   the rest have no named callers to infer from -- reach them by xref")


main()
