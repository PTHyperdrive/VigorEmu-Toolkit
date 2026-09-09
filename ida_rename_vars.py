# IDAPython: rename stack locals (var_XX) from how they are used around calls to
# the functions we already named. A frame slot that receives malloc()'s return
# is a buffer; one loaded into recv()'s length arg is a length; etc. Renaming
# the frame member updates BOTH the disassembly var_XX and the Hex-Rays local.
#
#   Run AFTER the function-naming scripts (it keys off their names).
#   IDA:  File > Script file...  (Alt+F7)
#
# Heuristic (light local dataflow, small windows). It never renames a slot that
# already has a non-default name. If the summary prints 0 or errors, tell me
# your IDA version -- the frame API differs a little across 7.x/8.x/9.x.

import re
import idc, idautils, ida_funcs, ida_ua, ida_frame, ida_name

# callee name -> (arg roles by position, return role or None)
SEM = {
    "drayos_malloc":  (["size"], "buf"),
    "GetCGI":         (["conn", "input", "env"], "nfields"),
    "makeword":       (["pcursor", "stopc"], "tok"),
    "drayos_getenv":  (["envname"], "envval"),
    "drayos_atoi":    (["numstr"], "num"),
    "drayos_strchr":  (["str", "ch"], "found"),
    "drayos_strncpy": (["dst", "src", "n"], None),
    "drayos_sprintf": (["out", "fmt"], None),
    "drayos_sscanf":  (["inbuf", "fmt"], None),
    "drayos_recv":    (["fd", "rbuf", "rlen"], "nread"),
    "virtcons_out":   (["cbuf", "clen"], None),
    "FreeCtrlName":   (["cgi_input"], None),
    "drayos_free":    (["fptr", "fsize"], None),
}


def opreg(ea, n):
    t = idc.print_operand(ea, n)
    m = re.match(r"^[wx](\d+)$", t.strip())
    return int(m.group(1)) if m else -1


def is_x29_mem(ea, n):
    t = idc.print_operand(ea, n)
    return "x29" in t and "[" in t


def is_x29_add(ea, n):
    return idc.print_operand(ea, n).strip() in ("x29",)


def stkoff(pfn, ea, opn):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return idc.BADADDR
    try:
        return ida_frame.calc_stkvar_struc_offset(pfn, insn, opn)
    except Exception:
        return idc.BADADDR


def find_mem_op(ea):
    for n in (1, 2, 0):
        if is_x29_mem(ea, n):
            return n
    return -1


def main():
    total = 0
    for fea in idautils.Functions():
        pfn = ida_funcs.get_func(fea)
        if not pfn:
            continue
        fid = idc.get_frame_id(fea)
        if fid == idc.BADADDR:
            continue
        items = list(idautils.FuncItems(fea))
        assign = {}                                   # frame offset -> role

        for idx, ea in enumerate(items):
            if idc.print_insn_mnem(ea).lower() != "bl":
                continue
            callee = ida_name.get_name(idc.get_operand_value(ea, 0)) or ""
            if callee not in SEM:
                continue
            args, ret = SEM[callee]

            # return value: str w0 (maybe via mov) into a slot, just after
            if ret:
                hold = 0
                for j in range(idx + 1, min(idx + 6, len(items))):
                    ej = items[j]; m = idc.print_insn_mnem(ej).lower()
                    if m == "bl":
                        break
                    if m == "mov" and opreg(ej, 1) == hold:
                        hold = opreg(ej, 0); continue
                    if m.startswith("st") and opreg(ej, 0) == hold:
                        n = find_mem_op(ej)
                        so = stkoff(pfn, ej, n) if n >= 0 else idc.BADADDR
                        if so != idc.BADADDR:
                            assign.setdefault(so, ret)
                        break

            # arguments: last set of each arg reg, just before
            for a, role in enumerate(args):
                for j in range(idx - 1, max(idx - 12, -1), -1):
                    ej = items[j]; m = idc.print_insn_mnem(ej).lower()
                    if m == "bl":
                        break
                    if opreg(ej, 0) != a:
                        continue
                    if m.startswith("ld"):
                        n = find_mem_op(ej)
                        so = stkoff(pfn, ej, n) if n >= 0 else idc.BADADDR
                        if so != idc.BADADDR:
                            assign.setdefault(so, role)
                        break
                    if m == "add" and is_x29_add(ej, 1):
                        so = stkoff(pfn, ej, 2)
                        if so != idc.BADADDR:
                            assign.setdefault(so, "p_" + role)
                        break

        for so, role in assign.items():
            nm, k = role, 2
            while not idc.set_member_name(fid, so, nm):
                nm = "%s_%d" % (role, k); k += 1
                if k > 9:
                    nm = None; break
            if nm:
                total += 1

    print("[rename_vars] renamed %d stack locals from call-site roles" % total)
    print("              (updates both var_XX and the Hex-Rays local)")


main()
