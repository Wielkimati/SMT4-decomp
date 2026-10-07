# Run through tools/debug_startup.py, from a fresh ignored output directory.
# Azahar must already be holding the EU base application at its entry point.
set pagination off
set confirm off
set remotetimeout 5
set architecture arm
set endian little
set remote memory-read-packet-size 8192
target remote 127.0.0.1:24689
if $pc != 0x00100000
  echo ERROR: Restart with pause-at-start enabled; expected PC 0x00100000.\n
  disconnect
  quit 1
end
if *(unsigned int *)0x00100000 != 0xeb000007 || *(unsigned int *)0x00100040 != 0x00477000 || *(unsigned int *)0x00100044 != 0x004efe34
  echo ERROR: Startup instruction or BSS bounds do not match the EU reference.\n
  disconnect
  quit 1
end
echo CHECKPOINT entry\n
info registers r0 r1 r2 sp lr pc cpsr
dump binary memory entry.bin 0x00100000 0x00101000
set arm force-mode arm
thbreak *0x00100024
continue
if $pc != 0x00100024 || ($cpsr & 0x20) != 0
  echo ERROR: ARM clear routine breakpoint mismatch.\n
  disconnect
  quit 1
end
echo CHECKPOINT clear_entry\n
info registers r0 r1 r2 pc lr cpsr
x/7i 0x00100024
dump binary memory bss-before.bin 0x00477000 0x004efe34
thbreak *0x00100030
continue
if $pc != 0x00100030 || $r0 != 0x00477000 || $r1 != 0x004efe34 || $r2 != 0
  echo ERROR: Clear-loop initial registers mismatch.\n
  disconnect
  quit 1
end
echo CHECKPOINT clear_begin\n
info registers r0 r1 r2 pc lr cpsr
thbreak *0x0010003c
continue
if $pc != 0x0010003c || $r0 != 0x004efe34 || $r1 != 0x004efe34 || $r2 != 0
  echo ERROR: Clear-loop final registers mismatch.\n
  disconnect
  quit 1
end
echo CHECKPOINT clear_end\n
info registers r0 r1 r2 pc lr cpsr
dump binary memory bss-after.bin 0x00477000 0x004efe34
dump binary memory startup-restored.bin 0x00100000 0x00100048
thbreak *0x00100010
continue
if $pc != 0x00100010 || ($cpsr & 0x20) != 0
  echo ERROR: ARM BLX checkpoint mismatch.\n
  disconnect
  quit 1
end
# With a raw target and no ELF symbols, explicitly select EACH target's mode.
set arm force-mode thumb
thbreak *0x00100cb8
continue
if $pc != 0x00100cb8 || ($cpsr & 0x20) == 0 || $lr != 0x00100014
  echo ERROR: Thumb callback dispatcher checkpoint mismatch.\n
  disconnect
  quit 1
end
echo CHECKPOINT thumb_entry\n
info registers pc lr cpsr
x/13i 0x00100cb8
dump binary memory thumb-restored.bin 0x00100cb8 0x00100cdc
# Switch back BEFORE installing the next ARM breakpoint.
set arm force-mode arm
thbreak *0x00101308
continue
if $pc != 0x00101308 || ($cpsr & 0x20) != 0
  echo ERROR: ARM game-entry checkpoint mismatch.\n
  disconnect
  quit 1
end
echo CHECKPOINT game_entry\n
info registers pc lr cpsr
x/4i 0x00101308
dump binary memory game-entry-restored.bin 0x00101308 0x00101318
info breakpoints
set arm force-mode auto
detach
echo SMT4_STARTUP_CHECK_COMPLETE\n
quit
