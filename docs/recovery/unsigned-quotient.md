# Consumed unsigned quotient recovery

2026-10-06, A07/A08 continuation. The nonzero-divisor r0 contract at EU ARM
`0x002C6C64` is reconstructed in
[`src/unsigned_quotient.c`](../../src/unsigned_quotient.c). Together with the
lookup and four table helpers, six entry-point contracts now build and pass
controlled instruction-level comparisons. The fully rebuilt lookup executes no
original code; the original-layout registry is still supplied by the harness.

Reference expanded-code SHA-256:
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Addresses here are original ARM virtual addresses. Names are project descriptions.
The implementation was derived from local instructions; no external implementation
was copied. Original compiler/runtime-library identity and project license remain
undecided.

## Instruction evidence and contract

| Original range/target | Observed behavior |
| --- | --- |
| `0x002C6C64..0x002C6C94` (exclusive end) | Initialize quotient accumulator r2; compare divisor r1 with dividend r0 shifted right by 2, 5, 8, 12 and 16 |
| `0x002C62B8`, `0x002C6294`, `0x002C6270`, `0x002C623C`, `0x002C620C` | Dispatch to subtraction starting at quotient bits 1, 4, 7, 11 and 15, respectively |
| `0x002C61E4..0x002C620C` | Scale divisor by 8 bits, optionally another 8; seed accumulator with carry markers that drive later repeated blocks |
| `0x002C620C..0x002C62C4` | Unsigned shifted comparisons, conditional subtraction and carry accumulation; carry at `0x002C626C` repeats through `0x002C6208` with divisor shifted down by 8 |
| `0x002C62C4..0x002C62D4` | Final subtraction/selection into r1; final quotient bit into r0; return through LR |

The caller `tbl1_entry_count` checks divisor zero before tail-calling this entry.
For this consumed contract, inputs are uint32 dividend/divisor, divisor must be
nonzero, and output r0 is floor(dividend / divisor). The final instructions also
suggest an r1 remainder result, but this C interface and comparison do not claim
that ABI. Zero division branches to `0x002C63CC` through the normalization path;
that handler's behavior remains unrecovered and is not replaced by a claimed
zero-divisor result. Other result registers, flags, timing and stack scratch bytes
are outside this contract.

The C reconstruction iterates quotient bits 31 down to 0 instead of reproducing
the dispatch/unrolling and carry markers. At each bit it compares
`dividend >> bit` with divisor before subtracting `divisor << bit`; a successful
comparison ensures the shifted divisor fits in uint32. The residual dividend
only decreases, and the accumulated bits yield the same quotient. All shifts
are in 0..31. No C division operator, compiler division helper or original binary
is used by this implementation. This is behavioral recovery, not binary matching.

GNU objdump and the saved Ghidra listing agree on the dispatch and subtraction
instructions. The private run exports `division-listing.txt` and
`division-coverage.txt`; all 72 instruction addresses in the two nonzero-divisor
ranges were visited. Address coverage includes predicated instructions and is
not a claim that every conditional outcome or uint32 input pair was exhausted.

## Build and comparison

From the repository, with the saved Ghidra project closed in the GUI:

```powershell
python tools/check_nkm_lookup.py --recover-quotient --output local/validation/quotient-next
python -m unittest discover -s tests -v
```

`--recover-quotient` implies `--recover-helpers`. The earlier original-helper and
recovered-table/original-quotient modes remain available. All modes now use the
expanded synthetic division corpus from `tools/unsigned_quotient_cases.py`.

Successful full run: `local/validation/quotient-20261006/COMPLETE.json`.

Both earlier modes also pass with the expanded corpus:
`local/validation/quotient-20261006-helpers-regression/COMPLETE.json` (296 bytes)
and `local/validation/quotient-20261006-original-helpers-regression/COMPLETE.json`
(80 bytes). Their rebuilt paths deliberately retain their documented original
dependencies.

| Check | Result |
| --- | --- |
| Original/rebuilt/Python integer quotient | 2,615 cases passed |
| Original/rebuilt/expected table helpers | 1,154 cases passed |
| Original/rebuilt/expected integrated lookup | 1,770 cases passed |
| Public synthetic tests | 28 passed |
| Combined ARM binary | 352 bytes; quotient entry `0x00600128`, 56 bytes |
| Maximum instructions per call | 327, within the existing 512 budget |

The quotient corpus covers unsigned extremes, every power-of-two divisor,
dispatch and normalization thresholds on both sides, exact/inexact quotients,
and deterministic random full-width and small divisors including odd/even values.
Python integer division constructs expectations; the Java checker independently
checks those expectations before executing separate original and rebuilt states.

The harness rejects every original-code address on the rebuilt path in this mode.
Direct original division is also confined to its reviewed nonzero-divisor ranges.
It checks preserved r4-r11/SP, stack-only stores, initialized/bounded reads and
instruction budget. The ELF has no unresolved symbols; its sole external binding
is registry data at `0x0049382C`. Original code remains necessary as the comparison
oracle, not as an execution dependency of the rebuilt side.

The local negative control omits quotient bit 31. For `0xFFFFFFFF / 1`, the harness
rejects rebuilt `0x7FFFFFFF` against original/expected `0xFFFFFFFF`, emitting no
success report. The repository source stays unchanged. See
`local/validation/quotient-20261006-negative-top-bit/NEGATIVE.json` and its local
driver `local/validation/check-quotient-negative.py`.

## Remaining work

The subsequent [section-3 recovery](nkm-section3.md) now passes 236 comparisons
using the same rebuilt helpers and quotient. Next: registry loaded-pointer writes
and a bounded loader/lifecycle routine. Registry loader/lifetimes, the explicit host address boundary,
compiler/ABI research and revision-pinned port handoff remain open. The recovered
quotient source does not itself assume pointer width, but no native-host comparison
or port import is claimed. The table helpers still require 32-bit addresses.

Live gameplay checks remain deferred at the user's request. G1/G2 are open; no
emulator, save or profile was changed. There is no reconstructed 3DS application,
complete division ABI, matching build or native PC runtime.
