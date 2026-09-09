# IDAPython: name the uC/OS-II RTOS core in DrayOS.
#
# These functions are non-exported statics with no strings, so nothing else
# names them. They were recovered structurally: OSUnMapTbl (the fixed 256-byte
# priority-resolution table, a unique fingerprint) was located by its bytes,
# and only the scheduler reads it. From OS_Sched/OS_EventTaskRdy the kernel
# globals (OSTCBPrioTbl, OSRdyGrp, OSIntNesting, OSLockNesting) were read off,
# and every function referencing them is the RTOS core (26 functions,
# 0x40000df0..0x4000c328).
#
#   IDA:  File > Script file...  (Alt+F7)   -- run after the other name scripts
#
# CONFIRMED = fingerprinted precisely.  ucos_core_ = in the core cluster but not
# yet individually fingerprinted (tag so you know it's RTOS, not app code).

import idc, ida_funcs, ida_name

def fn(ea, name, cmt=""):
    if ida_funcs.get_func(ea) is None:
        ida_funcs.add_func(ea)
    ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    if cmt:
        idc.set_func_cmt(ea, cmt, 1)

def dat(ea, name, cmt=""):
    ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    if cmt:
        idc.set_cmt(ea, cmt, 1)

CONFIRMED = {
    0x40007fd0: ("OS_Sched",        "scheduler; OSIntNesting==0 && OSLockNesting==0 -> OS_SchedNew -> ctx switch"),
    0x400080ac: ("OS_SchedNew",     "OSPrioHighRdy = (OSUnMapTbl[OSRdyGrp]<<3) + OSUnMapTbl[OSRdyTbl[y]]"),
    0x400074ec: ("OS_EventTaskRdy", "ready the highest-prio task waiting on an ECB (uses OSUnMapTbl)"),
    0x40005424: ("OS_CPU_SR_Save",  "enter critical: save + disable interrupts"),
}

# call OS_EventTaskRdy -> the post/signal family (Sem/Mbox/Q); exact split TBD
POST = [0x4000a514, 0x4000a920, 0x4000aa40]

# every function referencing OSTCBPrioTbl or OSRdyGrp -- the RTOS core
CORE = [0x40000df0, 0x4000105c, 0x40006fe4, 0x4000714c, 0x40007278, 0x400074ec,
        0x40007b90, 0x40007e24, 0x40007fd0, 0x4000838c, 0x40008444, 0x400087d4,
        0x40008cd8, 0x40008e24, 0x40008fb8, 0x40009334, 0x40009430, 0x40009594,
        0x400096c4, 0x40009864, 0x400099d8, 0x40009ba8, 0x40009c94, 0x40009e14,
        0x4000bff4, 0x4000c328]

DATA = {
    0x40e0aa50: ("OSUnMapTbl",    "uC/OS-II priority-resolution table [256] (the fingerprint)"),
    0x468f5f18: ("OSTCBPrioTbl",  "TCB* array indexed by priority (prio*4)"),
    0x468f11a0: ("OSRdyGrp",      "ready-group bitmap; OSRdyTbl[8] follows"),
    0x468efc44: ("OSIntNesting",  "interrupt nesting counter"),
    0x468f5e88: ("OSLockNesting", "scheduler-lock nesting counter"),
    0x468f5e89: ("OSPrioHighRdy", "priority of the highest-ready task"),
}

def is_default(n):
    return (not n) or n.startswith(("sub_", "nullsub_", "loc_", "unknown_",
                                    "a_", "s_", "w_", "k_"))

def main():
    for ea, (nm, cmt) in DATA.items():
        dat(ea, nm, cmt)
    for ea, (nm, cmt) in CONFIRMED.items():
        fn(ea, nm, cmt)
    for i, ea in enumerate(POST):
        if is_default(ida_name.get_name(ea)):
            fn(ea, "ucos_EventPost_%08x" % ea, "posts to a sem/mbox/q ECB (OS_EventTaskRdy caller)")
    tagged = 0
    for ea in CORE:
        if is_default(ida_name.get_name(ea)):
            fn(ea, "ucos_core_%08x" % ea, "uC/OS-II core (references OSTCBPrioTbl/OSRdyGrp)")
            tagged += 1
    print("[ucos] %d confirmed, %d post, %d core tagged, %d globals"
          % (len(CONFIRMED), len(POST), tagged, len(DATA)))

main()
