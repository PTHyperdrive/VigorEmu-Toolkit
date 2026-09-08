set pagination off
set confirm off
set architecture aarch64
file /home/kali/out/sohod64.symbols.elf
target remote :1234
shell sleep 1
hbreak *0x40bbfa30
continue
delete breakpoints
printf "  stopped in httpd task, pc=0x%08x\n", $pc
set $o_pc = $pc
set $o_x0 = $x0
set $o_x1 = $x1
set $o_lr = $x30
source /home/kali/pokes.gdb
printf "  command staged: %s\n", (char *)$cmdaddr
hbreak *0x40000000
set $x0 = $cmdaddr
set $x1 = $cmdlen
set $x30 = 0x40000000
set $pc = 0x40422e20
printf "  calling virtcons_out(0x%08x, %d)\n", $x0, $x1
continue
printf "  returned to landing pad, restoring task\n"
delete breakpoints
set $pc = $o_pc
set $x0 = $o_x0
set $x1 = $o_x1
set $x30 = $o_lr
detach
quit
