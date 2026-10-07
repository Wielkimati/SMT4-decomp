# Runtime reference and debugger

Date: 2026-10-06. Target: EU base `0004000000141C00`, version 0. Runtime evidence
belongs under ignored `local/runtime/`; this document contains observations and
reproduction instructions. The user now confirms supplied-save loading into
gameplay with working controls (2026-10-06); see the save-loading update below.
The earlier debugger session used the user's running profile, not an isolated
save-test profile, and did not load or alter the original save backups.

## Save-loading and gameplay update: 2026-10-06

After the instructions to copy `sdds4game1.sav` and `sdds4game2.sav` from
`Game/saves/0x0141C Shin Megami Tensei IV/20361005-064435/` into SMT IV's
**Open > Save Data Location** folder with Azahar closed, the user reported:
"I did it, my saves load in". Asked whether loading reached gameplay with
responsive movement or menus, they confirmed: "Yes, gameplay and controls work".

Record supplied-save loading, entry into gameplay, and responsive controls as
**user-confirmed successes**. This is stronger evidence than visible save slots
or a menu boot. The agent did not operate the emulator, copy files, or capture
the successful session. No save-format decoding or native-port compatibility
follows from this result.

The user did not identify individual tested slots, the loaded scene/checkpoint,
or the destination profile path. Isolation from their normal profile and the
exact base/update/DLC configuration of this run were not independently recorded;
the earlier debugger profile inventory is not a new configuration audit.
A03 now has positive gameplay/save-load outcomes. G1 remains open for a
reproducible checkpoint/configuration and isolated-profile evidence, then final
gate review. A new in-game save followed by process restart/reload is a separate,
unperformed persistence check, not a reason to discount this successful load.

## Tools and observed configuration

- Azahar log identifies **2126.1.2 | HEAD-9e6f523**, **MSYS2**. The selected executable
  remains `local/tools/azahar-windows-msys2-2126.1.2/azahar.exe`.
- ARM GDB is **16.3.90.20250906-git**, from xPack GNU Arm Embedded GCC
  **15.2.1-1.1**, Windows x64. Official ZIP SHA-256 matched; archive/executable pins
  are in `config/analysis-tools.json`. GDB is GPLv3+; the distribution's notices
  remain in its ignored installation. Bundled GCC does not establish the original
  game's compiler or adopt a matching toolchain.
- Session log: JIT enabled, CPU clock 100%, OpenGL renderer. Saved configuration
  selects New 3DS and automatic region; per-game settings use global values for
  these settings. Exact local config snapshots are retained with the capture.
- GDB stub is enabled on TCP 24689. The debugger connects to `127.0.0.1`; Azahar's
  listener itself binds all IPv4 interfaces. No firewall rules were changed.
- Log identifies the running program as `0004000000141C00`. Profile content
  inventory contains its base application/manual, with no matching update or DLC
  content found in the inspected title tree. A complete content/save audit remains
  separate work.

## Connect

Stop the game. In Azahar, choose **Emulation > Configure > General > Debug**, enable
**Enable GDB Stub**, use port **24689**, and tick **Pause next non-sysmodule process
at start**. Apply, then boot the installed base game. Leave the emulation running
from the GUI's perspective: the guest application is held by the debugger startup
pause. Do not load a save state for this startup check.

Run the pinned executable from the repository root:

```powershell
& 'local/tools/xpack-arm-none-eabi-gcc-15.2.1-1.1/bin/arm-none-eabi-gdb.exe' --nx --quiet
```

Then in GDB:

```text
set pagination off
set architecture arm
set endian little
set remote memory-read-packet-size 8192
target remote 127.0.0.1:24689
info registers pc sp lr cpsr
x/9i 0x00100000
x/7i 0x00100024
x/2wx 0x00100040
```

`target remote` selects the main launched application in this Azahar stub. The
initial observed PC was `0x00100000`, SP `0x10000000`, LR zero, CPSR `0x10` (ARM
user mode). Instructions and the two BSS literals agreed with the static import.

## Compatibility findings

The stub advertises `PacketSize=9800`, which GDB interprets as hexadecimal, while
the source declares a 10,000-byte buffer. Default large memory dumps failed and
Azahar logged `command_buffer overflow in SendReply`. A 1024-byte packet limit
successfully read a 4096-byte probe and then the complete initialized image.
An 8192-byte limit also passed and is used by the reproducible checker. Use a bounded packet size before bulk reads;
an oversized-packet error does not mean the target address is unmapped.

GDB reports an unknown `3DS` OS ABI and no executable file. These warnings did not
prevent the observed connection/register/disassembly checks. We intentionally did
not use GDB's `load` command or supply the raw `.code` file as an ELF executable.

The stub's `s` packet explicitly reports single stepping unsupported. Use temporary
address breakpoints and continue instead of `stepi`/`nexti`. Its execute breakpoints
patch guest instruction bytes even when requested as hardware breakpoints; remove
them before comparing those bytes. Capture baseline memory before installing them.

Sources: [selected Azahar GDB stub](https://github.com/azahar-emu/azahar/blob/2126.1.2/src/core/gdbstub/gdbstub.cpp),
[debug controls](https://github.com/azahar-emu/azahar/blob/2126.1.2/src/citra_qt/configuration/configure_debug.ui),
[xPack release](https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack/releases/tag/v15.2.1-1.1).

## Evidence files

The initial session is retained in `local/runtime/startup-20261006/`, with GDB
transcript, baseline probe, emulator log snapshot, and saved configuration copies.
The initial full initialized-memory capture is 3,633,152 bytes and has SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`: an exact
match to the expanded reference before breakpoint insertion. This verifies the
running executable identity, not just the startup instructions.

## Completed startup checks

The successful scripted repeat is under
`local/runtime/startup-20261006-repeat/check/`. Its `COMPLETE.json` records capture
lengths/hashes, comparisons, and detach success; `gdb-session.txt` records registers
and all six temporary breakpoint stops.

| Stop | Mode / CPSR | Relevant observation |
| --- | --- | --- |
| `0x00100000` | ARM / `0x00000010` | Entry, SP `0x10000000`, instruction bytes match |
| `0x00100024` | ARM / `0x00000010` | Clear routine; LR `0x00100004` |
| `0x00100030` | ARM / `0x00000010` | Before first compare: r0 `0x00477000`, r1 `0x004EFE34`, r2 zero |
| `0x0010003C` | ARM / `0x60000010` | After loop: r0 and r1 `0x004EFE34`, r2 zero |
| `0x00100010` | ARM | Reached BLX after earlier startup calls |
| `0x00100CB8` | Thumb / `0x60000030` | BLX target; LR `0x00100014`; disassembly matches |
| `0x00101308` | ARM / `0x60000010` | Final startup call reached after callbacks; LR `0x00100020` |

The two full BSS captures cover 495,156 bytes (`0x78E34`). Both before and after
are entirely zero, SHA-256
`5174fe6e1b29c2fdea63fb53d3572d01204c46b4701f2c8ce465e30f5a684ef2`.
Because the emulator supplied zero memory already, this is not a nonzero-sentinel
test proving each store's effect. The observed loop registers, boundaries, code,
and final zero state agree with the static interpretation. No sentinel writes
were performed. Reads just beyond the logical end succeeded, as expected from
page allocation; they do not extend the game's logical BSS.

All six temporary breakpoints were removed. Captures of the clear routine, Thumb
dispatcher, and final startup target match their original bytes after removal.
GDB detached successfully and the emulator process remained responsive with the
SMT IV window title. This proves stop/read/continue/detach operation; a full
menu-to-gameplay and save-copy test still belongs to A03.

The agent closed its background test process. On 2026-10-06 the user then
reported that a fresh normal launch reached the main menu; they closed it after
checking. Gameplay and supplied-save
loading were unverified at that point; the later user confirmation is recorded above.

For future visual/gameplay checks, have the user launch Azahar and attach the
debugger as needed.

### Failed attempt and recovery

The first interactive run passed the BSS and Thumb checks, then Azahar exited while
continuing toward the ARM target `0x00101308`. That breakpoint was created while
stopped in Thumb mode with GDB's mode selection set to `auto` and no ELF symbols.
Wrong breakpoint width is the leading explanation, not a proven emulator diagnosis.
The repeat explicitly forced the target mode before every transition and passed.
Retain the first transcript/failure; do not describe every debugger feature as tested.

The pinned Windows binary rejected the long CLI option `--gdbport`. Its short
equivalent **`-g 24689`** successfully enabled the stub and paused the application
at entry. It was used to restart the same installed base `.app`; the exact launch
arguments are in `local/runtime/startup-20261006-repeat/azahar-command-short.json`.
Do not mistake the prior
profile log for a new repeat-session log.

## Repeat the checked sequence

With the game freshly paused at entry and no other debugger attached, from the
repository root run:

```powershell
python tools/debug_startup.py --output local/runtime/startup-next
```

The output directory must be new and inside `local/`. The wrapper checks the
pinned debugger and reference hashes, connects only to loopback port 24689, runs
`tools/gdb/check-startup.gdb`, compares captured bytes and BSS, and writes
`COMPLETE.json` only on success. It leaves the emulator resumed after detaching.
The script explicitly chooses ARM or Thumb for each target; it does not use
single stepping. No source recovery, menu/gameplay, save compatibility, or hardware
accuracy claim follows from this startup check alone.
