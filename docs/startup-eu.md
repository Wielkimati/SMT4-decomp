# EU executable: initial startup analysis

Date: 2026-10-06. Reference: base `0004000000141C00`, version 0. Expanded-code
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All addresses below are original virtual addresses, not file offsets or PC pointers.
Names are descriptive annotations. Startup runtime agreement was verified on
2026-10-06; see [runtime-reference.md](runtime-reference.md) for captures and limits.

## Entry and instruction modes

The first instruction at `0x00100000` is an ARM `BL 0x00100024`. The entry sequence
contains the following directly encoded transfers. Immediate targets were also
decoded from the raw instruction words independently of Ghidra, using the ARM
PC+8 rule and BLX H bit.

| Call/branch address | Target | Target mode | Current interpretation |
| --- | --- | --- | --- |
| `0x00100000` | `0x00100024` | ARM | Zero-fill startup range |
| `0x00100004` | `0x0010236C` | ARM | Unclassified startup routine |
| `0x00100008` | `0x00106D58` | ARM | Unclassified startup routine |
| `0x0010000C` | `0x00104EF4` | ARM | Unclassified startup routine |
| `0x00100010` | `0x00100CB8` | Thumb | `BLX` demonstrates mixed ARM/Thumb code |
| `0x00100014` | `0x00102338` | ARM | Unclassified startup routine |
| `0x00100018` | `0x001023C0` | ARM | Unclassified startup routine |
| `0x0010001C` | `0x00101308` | ARM | Unclassified startup routine |
| `0x00100020` | `0x00101300` | ARM | Tail branch, not a call |

The import seeds ARM mode only for `0x00100000–0x0010003F` and follows control
flow. It does not force the entire executable into ARM mode. Compiler family,
SDK version, `main`, and engine identity remain unclassified.

Two useful static leads now have instruction-level support:

- The Thumb routine at `0x00100CB8` walks `[0x0042A188,0x0042AB78)` in four-byte
  steps, adds each stored offset to its own entry address, and calls the result
  using `BLX r0`. There are 636 entries; all computed targets are inside `.text`
  and have bit 0 clear (ARM). A static-initializer dispatcher is a probable role.
- The ARM routine at `0x00102338` walks an absolute callback table. Its two endpoint
  literals both equal `0x0042AB78`, describing an empty range in this image.

The final startup call, `0x00101308`, is a candidate game entry/main loop: generated
pseudocode shows extensive setup, rendering callback names, resource paths, and
recurring control flow. Its detailed behavior has not been verified. The tail target
`0x00101300` is `SWI 0x03; BX LR`, consistent with the 3DS ExitProcess wrapper in
[libctru's SVC definitions](https://github.com/devkitPro/libctru/blob/master/libctru/source/svc.s).
This establishes a platform interpretation, not that the retail game uses libctru.
The initial auto-analysis merged this tail stub into the entry function; its
indirect-jump warning remains a known function-boundary/termination-model issue.

## BSS evidence

At `0x00100024`, two PC-relative loads read the literals at `0x00100040` and
`0x00100044`: `0x00477000` and `0x004EFE34`. The routine sets `r2=0`, compares
`r0` against `r1`, conditionally stores a word and advances `r0` by four while
unsigned-lower, then returns with `BX LR`. The static effect is 123,789 zero stores
over the half-open range `[0x00477000, 0x004EFE34)`, length `0x78E34`.

ExHeader arithmetic independently gives:

```text
initialized data end = 0x0042B000 + 0x0004B644 = 0x00476644
declared BSS end      = 0x00476644 + 0x000797F0 = 0x004EFE34
file-backed data end  = 0x0042B000 + 0x0004C000 = 0x00477000
file-backed padding  = [0x00476644, 0x00477000), length 0x9BC
```

All `0x9BC` bytes of this data padding are zero in the expanded file. The startup
clear begins at its end and stops at the ExHeader-derived logical end. Keep the
file-backed padding separate from the non-file-backed startup-cleared range.
The exact semantic ownership of every padding byte is not established.

The [selected Azahar loader source](https://github.com/azahar-emu/azahar/blob/2126.1.2/src/core/loader/ncch.cpp#L128-L153)
rounds the ExHeader BSS size to pages and appends it to the allocated data pages;
it also contains an explicit uncertainty comment about the BSS arithmetic. That
allocation can extend through `0x004F1000` exclusive. It is not evidence that the
game's logical BSS extends that far. Live register and memory observations now
agree with the clear-loop bounds; reads beyond the logical end also succeeded.

## Imported memory blocks

End addresses in this table are exclusive. File offsets refer to expanded `.code`.

| Block | Start | End | File offset | Analysis permissions |
| --- | --- | --- | --- | --- |
| `.text` | `0x00100000` | `0x003FE69C` | `0x000000` | R-X |
| `.text_padding` | `0x003FE69C` | `0x003FF000` | `0x2FE69C` | R-- |
| `.rodata` | `0x003FF000` | `0x0042AB78` | `0x2FF000` | R-- |
| `.rodata_padding` | `0x0042AB78` | `0x0042B000` | `0x32AB78` | R-- |
| `.data` | `0x0042B000` | `0x00476644` | `0x32B000` | RW- |
| `.data_padding` | `0x00476644` | `0x00477000` | `0x376644` | RW- |
| `.bss_startup_zeroed` | `0x00477000` | `0x004EFE34` | None; uninitialized block | RW- |

Text and rodata padding were also checked and are entirely zero. Disabling execution
on text padding is an analysis choice; actual kernel permissions operate at page
granularity. BSS is represented as uninitialized storage, not file bytes and not a
claim that memory remains unknown after startup. Extra emulator allocation beyond
the observed logical end is deliberately not included in this static map.

## Runtime checkpoint results

All planned startup stops were reached. At `0x00100030`, r0/r1 held
`0x00477000`/`0x004EFE34`; at `0x0010003C`, both held `0x004EFE34`. The full cleared
range was zero before and after; no nonzero sentinel was injected. The full live
initialized image matched the reference SHA-256 before breakpoint insertion.
The BLX target `0x00100CB8` was reached with CPSR T=1 and LR `0x00100014`, and
`0x00101308` was subsequently reached in ARM mode. Breakpoint removal restored
the checked bytes; detach/resume succeeded. See the runtime report for the failed
first follow-up, packet-size workaround, explicit breakpoint modes, and commands.
