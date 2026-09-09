# IDAPython: name the functions we reverse-engineered in sohod64.bin and mark
# the CVE-chain spots, so the DB is navigable instead of a sea of sub_40xxxxxx.
#
#   IDA:  File > Script file...  > ida_names.py     (Alt+F7)
#
# Image base must be 0x40000000 (ELF32 / EM_AARCH64, ARM64 ILP32). If you loaded
# the raw .bin, set the processor to ARM (AArch64) and rebase to 0x40000000.
# For the full 1337 names, instead add the symbol table of
# out/ghidra/sohod64.symbols.elf (IDA reads ELF .symtab). This script covers the
# ~40 functions + spots that matter for CVE-2024-41592 -> 41585.

import idc, ida_funcs, ida_name, ida_bytes

def name_func(ea, name, cmt=""):
    if ida_funcs.get_func(ea) is None:
        ida_funcs.add_func(ea)
    ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    if cmt:
        idc.set_func_cmt(ea, cmt, 1)          # 1 = repeatable

def spot(ea, cmt):
    idc.set_cmt(ea, cmt, 0)

def data(ea, name, cmt=""):
    ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE)
    if cmt:
        idc.set_cmt(ea, cmt, 1)

FUNCS = {
    # --- HTTP / CGI core --------------------------------------------------
    0x40139364: ("httpd_main",         "RTOS task, prio 11 -- the web server task"),
    0x40129f5c: ("http_handler",       "per-connection HTTP handler"),
    0x4014469c: ("http_parse_request", "request line + headers; calls get_mime_headers, cgi_stub"),
    0x40143134: ("get_mime_headers",   "parses Content-length via sscanf(%ld) @0x40143174 -> conn+0x3450"),
    0x40141578: ("add_common_vars",    "builds CGI env; formats CONTENT_LENGTH @0x4014174c"),
    0x40141b3c: ("cgi_stub",           "dispatch-table lookup; blr x7 @0x40141d18 into the handler"),

    # --- CVE-2024-41592: the overflow + the free-write ---------------------
    0x40bbfa30: ("GetCGI",             "CVE-2024-41592: query->input[] w/o bound. GET loop @0x40bbfac8 UNBOUNDED; POST loop @0x40bbfd60 guarded by input_num"),
    0x40bbfff8: ("FreeCtrlName",       "chain-free input[i].name until first NULL. free() inside is the write primitive"),
    0x400bed20: ("makeword",           "malloc(len+1) + copy one token; the field bytes ARE the chunk contents"),

    # --- allocator (the heap primitive lives here) -------------------------
    0x405dbc5c: ("drayos_malloc",       "size-class alloc; slab (small addr) vs linear (large)"),
    0x405dbda8: ("drayos_free",         "outer free: ptr<threshold -> slab_free, ptr>=threshold -> linear_free_coalesce"),
    0x405db5f8: ("slab_free",           "HARDENED: boundary-tag checksum @bt+6 == ~(bt0+bt2+bt4), + descriptor/size/flags checks"),
    0x405db53c: ("slab_free_abort",     "prints the corruption/heap error and bails"),
    0x405d7fc8: ("linear_free_coalesce","linear free; coalesces adjacent; the UNLINK write @0x405d8084"),
    0x405d80d0: ("dump_free_list",      "DEBUG: walks+prints the free list (this is NOT the insert)"),
    0x405d8250: ("free_total_size",     "sums free-list chunk sizes"),
    0x405d9990: ("slab_desc_for_page",  "page addr -> slab descriptor"),

    # --- lib / compare -----------------------------------------------------
    0x400bd460: ("strcasecmp_full",     "case-insensitive full-string compare (auth gate uses it); 0 = equal"),
    0x40df5c50: ("drayos_atoi",         ""),
    0x400bfa18: ("drayos_getenv",       ""),
    0x405f6784: ("drayos_strchr",       ""),
    0x40012880: ("drayos_sprintf",      ""),
    0x40013e30: ("drayos_sscanf",       ""),
    0x40033c2c: ("drayos_strncpy",      ""),
    0x40dfb6f0: ("drayos_printf",       "console / log sink"),

    # --- auth gate ---------------------------------------------------------
    0x406d9cc4: ("is_noauth_hotspot_page", "whitelist check (wportalauth/webporshow/hsweb/hslog*.htm); returns 0 => exempt from auth. Called from ~0x400f948c"),

    # --- CVE-2024-51139 (pre-auth heap overflow, separate bug) -------------
    0x4012aa30: ("drayos_recv",          "socket read (fd, buf, len)"),
    0x40a4b9d0: ("drayos_linear_malloc", "'Linear malloc() allocated size='"),

    # --- escape (stage 2) --------------------------------------------------
    0x40422e20: ("virtcons_out",         "queue bytes to virtio-serial ch0 -> QEMU flush_buf (memsave/frmsave) / host recvCmd. THE escape channel"),
    0x40a2314c: ("frmsave_emit",         "sprintf 'frmsave %d %d %s%s' -> virtcons_out (uffs persist)"),

    # --- exception vectors (crash catch) -----------------------------------
    0x40e09000: ("exc_vector_base",      "VBAR"),
    0x40e09a14: ("sync_handler_spx",     "Current-EL/SPx synchronous fault handler (prints the crash dump, reboots)"),

    # --- CGI handlers: pre-auth reachable (GetCGI runs before the gate) ----
    0x40cd47cc: ("cgi_wlogin",      "PRE-AUTH. input[]=fp+0x1f0, saved lr @ entry 21"),
    0x40ce9d98: ("cgi_user_login",  "PRE-AUTH. saved lr @ entry 206"),
    0x40c9dcd4: ("cgi_webporshow",  "PRE-AUTH. saved lr @ entry 254"),
    0x40c9e1b0: ("cgi_wportalauth", "PRE-AUTH. saved lr @ entry 254"),
    0x40ca678c: ("cgi_Activate",    "PRE-AUTH. input[]=fp+0x20, saved lr @ entry 9 -- SMALLEST target"),
    0x40d33cc4: ("cgi_hsweb",       "PRE-AUTH. saved lr @ entry 203"),

    # --- CGI handlers: FreeCtrlName zero-local property (all POST-AUTH) -----
    0x40bc2828: ("cgi_chgbas2",  "post-auth; re-plants NULL @entry 21/23 (defeats FreeCtrlName)"),
    0x40bf194c: ("cgi_ipstrt",   "post-auth; property"),
    0x40c28814: ("cgi_func",     "post-auth; property"),
    0x40cd6584: ("cgi_authclr",  "post-auth; property"),
    0x40bd2948: ("cgi_inet16",   "post-auth; property"),
    0x40bf3530: ("cgi_acontrol", "post-auth; property"),
    0x40bfbc9c: ("cgi_ipfeds",   "post-auth; property"),
    0x40cb04b8: ("cgi_qos",      "post-auth; property"),
    0x40cb5810: ("cgi_cntrobj",  "post-auth; property"),
    0x40be9384: ("cgi_frmup",    "firmware upload"),
}

SPOTS = {
    0x40141d18: "cgi_stub: blr x7 == CGI dispatch into the handler",
    0x40bbfac8: "GetCGI: UNBOUNDED GET parse loop (the overflow)",
    0x40bbfd60: "GetCGI: POST loop (bounded by input_num)",
    0x40143174: "sscanf(Content-length, '%ld') -> conn+0x3450  (CVE-2024-51139 parse)",
    0x4014174c: "sprintf CONTENT_LENGTH env -- the ONLY reader of conn+0x3450",
    0x405d8020: "linear free: coalesce adjacency scan loop",
    0x405d8084: "linear free UNLINK WRITE: node->next = node->next->next  <== the primitive",
    0x405d8070: "linear free: global free-size counter store",
}

DATA = {
    0x41e2af78: ("cgi_dispatch_table",   "115 x { char* name; handler; u32 flags(0x2000) }"),
    0x41e30394: ("freelist_head_ptr",    "**this = linear free-list head"),
    0x41e2fd50: ("alloc_threshold_ptr",  "**this = slab/linear boundary address"),
    0x41e2e7e0: ("free_size_counter_ptr","*this -> global free-size counter"),
    0x4645a840: ("slab_region_base",     "slab region bounds live around here (+0x840/+0x844/+0xadc)"),
}

def run():
    n = 0
    for ea, (nm, cmt) in FUNCS.items():
        name_func(ea, nm, cmt); n += 1
    for ea, cmt in SPOTS.items():
        spot(ea, cmt)
    for ea, (nm, cmt) in DATA.items():
        data(ea, nm, cmt)
    print("[ida_names] named %d functions, %d spots, %d data" % (n, len(SPOTS), len(DATA)))

run()
