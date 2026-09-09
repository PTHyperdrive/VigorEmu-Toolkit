# IDAPython: rename stack locals (var_XX) from how they are used around calls to
# the functions we already named. A frame slot that receives malloc()'s return
# is a buffer; one loaded into recv()'s length arg is a length; etc. Renaming
# the frame member updates BOTH the disassembly var_XX and the Hex-Rays local.
#
#   Run AFTER the function-naming scripts (it keys off their names).
#   IDA:  File > Script file...  (Alt+F7)
#
# The stack slot is resolved through the frame API (no text parsing), and
# registers are matched case-insensitively (IDA prints ARM regs uppercase). If
# the summary still shows 0 renamed, its 3 counters say which stage failed --
# paste them and your IDA version.

import re
import idc, idautils, ida_funcs, ida_ua, ida_frame, ida_name

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

diag = {"calls": 0, "slots": 0, "renamed": 0, "err": ""}


def opreg(ea, n):
    """Register number of operand n (case-insensitive; -1 if not a w/x reg)."""
    t = idc.print_operand(ea, n).strip().lower()
    m = re.match(r"^[wx](\d+)$", t)
    return int(m.group(1)) if m else -1


def stk_slot(pfn, ea):
    """Frame-struct offset of the stack operand in this insn, or BADADDR."""
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        return idc.BADADDR
    for n in range(8):
        op = insn.ops[n]
        if op.type == ida_ua.o_void:
            break
        try:
            so = ida_frame.calc_stkvar_struc_offset(pfn, insn, n)
        except Exception as e:
            diag["err"] = diag["err"] or repr(e)
            so = idc.BADADDR
        if so != idc.BADADDR:
            return so
    return idc.BADADDR


def main():
    for fea in idautils.Functions():
        pfn = ida_funcs.get_func(fea)
        if not pfn:
            continue
        fid = idc.get_frame_id(fea)
        if fid == idc.BADADDR:
            continue
        items = list(idautils.FuncItems(fea))
        assign = {}

        for idx, ea in enumerate(items):
            if idc.print_insn_mnem(ea).lower() != "bl":
                continue
            callee = ida_name.get_name(idc.get_operand_value(ea, 0)) or ""
            if callee not in SEM:
                continue
            diag["calls"] += 1
            args, ret = SEM[callee]

            if ret:                                        # return value slot
                hold = 0
                for j in range(idx + 1, min(idx + 6, len(items))):
                    ej = items[j]; m = idc.print_insn_mnem(ej).lower()
                    if m == "bl":
                        break
                    if m == "mov" and opreg(ej, 1) == hold:
                        hold = opreg(ej, 0); continue
                    if m.startswith("st") and opreg(ej, 0) == hold:
                        so = stk_slot(pfn, ej)
                        if so != idc.BADADDR:
                            assign.setdefault(so, ret)
                        break

            for a, role in enumerate(args):               # argument slots
                for j in range(idx - 1, max(idx - 12, -1), -1):
                    ej = items[j]; m = idc.print_insn_mnem(ej).lower()
                    if m == "bl":
                        break
                    if opreg(ej, 0) != a:
                        continue
                    if m.startswith("ld"):
                        so = stk_slot(pfn, ej)
                        if so != idc.BADADDR:
                            assign.setdefault(so, role)
                        break
                    if m == "add":                         # add xA, x29, #off -> &var
                        so = stk_slot(pfn, ej)
                        if so != idc.BADADDR:
                            assign.setdefault(so, "p_" + role)
                        break

        diag["slots"] += len(assign)
        for so, role in assign.items():
            nm, k = role, 2
            while not idc.set_member_name(fid, so, nm):
                nm = "%s_%d" % (role, k); k += 1
                if k > 9:
                    nm = None; break
            if nm:
                diag["renamed"] += 1

    print("[rename_vars] matched %d call sites, resolved %d stack slots, renamed %d"
          % (diag["calls"], diag["slots"], diag["renamed"]))
    if diag["renamed"] == 0:
        if diag["calls"] == 0:
            print("   -> 0 call sites: run the function-naming scripts first")
        elif diag["slots"] == 0:
            print("   -> slots 0: calc_stkvar_struc_offset didn't resolve. err=%s" % diag["err"])
        else:
            print("   -> slots found but set_member_name failed (frame API mismatch)")


main()
