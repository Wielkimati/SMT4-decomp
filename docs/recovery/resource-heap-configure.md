# Resource heap configuration entries

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
The three ARM leaf entries are reconstructed in
[`src/resource_heap_configure.c`](../../src/resource_heap_configure.c).
Names retain the enclosing wrapper's argument positions, without assigning
unproved meanings to the configuration fields.

## Instruction-derived contracts

All three accept `(subobject, value)` as full-width u32 argument words.
Addresses below are relative to that subobject, which the recovered wrapper
passes as `heap+0x18`. Address additions wrap modulo 2^32. Backing must be
valid for the original access width; no null-pointer check is present.

| Entry / exclusive end | Field | Store | r0 return |
| --- | --- | --- | --- |
| `0x00146CE0` / `0x00146CF0` | u16 at +0x34 (heap+0x4C) | Low 16 bits of value | Previous u16, zero extended |
| `0x00146CF0` / `0x00146D10` | u16 at +0x36 (heap+0x4E) | Replace bit 0 with value bit 0; preserve bits 1-15 | Previous bit 0 |
| `0x00146D10` / `0x00146D20` | byte at +0x38 (heap+0x50) | Low 8 bits of value | Previous byte, sign extended to 32 bits |

Each entry performs exactly one field load followed by exactly one field store,
including when the value does not change. They make no calls and use no stack.
The second setter uses the input's low bit, not its nonzero truth value.
The source returns the third setter's sign-extended register pattern as u32,
using explicit arithmetic instead of implementation-defined signed narrowing.
The wrapper ignores all three returns; the old void declarations were therefore
sufficient for its modeled boundary but have now been corrected for direct use.
No complete object layout, option meaning, or allocator algorithm is inferred.

Read-only saved-project inspection is
`local/validation/heap-config-20261007-inspect/exports/listing.txt` and
`pseudocode.c`; the exact three function boundaries and all **16 ARM instructions**
agree with pinned GNU objdump. Byte and normalized instruction agreement is
recorded in `local/validation/heap-config-20261007-static-audit.json`.
The saved project has one call reference to each setter, at `0x002C3AB8`,
`0x002C3AC4`, and `0x002C3AD0` respectively. This is a saved-reference observation,
not proof of complete caller discovery. No saved Ghidra analysis was modified.

## Direct comparison design

The checker builds a freestanding C11 ARMv6K/ARM soft-float unit with pinned GCC,
warnings as errors, no SDK, no startup, and no external symbols. Neither side
intercepts calls; rebuilt execution is confined to the relocated rebuilt image.
Each path is checked against an independent byte-oriented memory/return oracle
and then against the other path's final bytes and ordered access trace.

The fixture is 40 guarded bytes beginning at subobject+0x24: the target fields
are at offsets 16, 18 and 20. Neighboring bytes, including the other configuration
fields, contain seeded random values and must be preserved. This is a bounded
subobject fixture, not a complete heap. Three address patterns cover ordinary,
high-bit, and wrapping base arithmetic: `0x00910000`, `0x89100000`, `0xFFFFFFF0`.
Halfwords are aligned; invalid backing and misaligned accesses are outside this
contract. Read/write callbacks reject wrong addresses, widths, multiplicity,
ordering and any unexpected memory access. The entire initialized 4 KiB stack
and 32 caller bytes must remain unchanged; SP, r4-r11 and d8-d15 are preserved.
Incidental r2/r3 inputs are poisoned. Flags and other volatile-register results
are not part of the recovered callable contract.

The deterministic corpus contains **200,976 comparisons**, **66,992 per entry**:

- 1,296 boundary combinations: three entries, three addresses, twelve old-value
  patterns and twelve option words. Values include zero, one, two, byte/halfword
  sign and width boundaries, the high u32 bit, and all ones.
- 131,072 cases exhaust every old u16 for each halfword setter, using seeded
  full-width option values. This does not exhaust the u16-by-u32 Cartesian product.
- 65,536 cases exhaust all old/new byte pairs for the third setter, with seeded
  upper option bits that must not affect the stored byte.
- 3,072 additional seeded full-width cases across all three entries.

## Validated direct result

Final marker: `local/validation/heap-config-20261007-direct-final/COMPLETE.json`.
GCC produces **72 text bytes**, SHA-256
`d8c1d36238e70e9899f35f9f7890ca4d57f50b87b4a21e84e3f926cf52bf3e0e`.
All 200,976 cases pass, visiting all 16 original instruction addresses, with
maximum eight instructions per invocation. There are **33,463 negative byte
returns**, **66,990 wrapping-address cases**, and **34,060 unchanged-value stores**.
No lower dependency is modeled or executed within these direct leaves.

The first positive run, `local/validation/heap-config-20261007-direct/COMPLETE.json`,
also passed. A follow-up corrected the driver's provenance list to hash its own
Python file instead of the copied wrapper driver's name; the final run validates
that corrected driver. The binary and complete comparison result are identical.
No recovered-source or comparison-harness correction followed a failed positive
run. These three analyzed, understood, implemented, buildable and bounded
behavior-verified entries bring the boundary to **43 entry-point contracts plus
two adapted worker regions**. This is behavior recovery, not binary matching.

## Negative checks

All ten separately compiled mutants are rejected by corpus assertions after
successful builds. `local/validation/heap-config-20261007-negative-runs.json`
indexes the individual `NEGATIVE.json` markers, binary hashes and actual failures.
Compilation failures are not counted as rejection.

| Mutant | Rejected deviation |
| --- | --- |
| `fourth-offset` | Access at +0x32 instead of +0x34 |
| `fourth-byte` | Byte store instead of halfword store |
| `fourth-return-new` | Return input instead of previous field |
| `fifth-clobber` | Lose unrelated bits 1-15 |
| `fifth-boolean` | Set bit 0 for every nonzero input |
| `fifth-return-word` | Return whole old halfword instead of its low bit |
| `sixth-offset` | Access at +0x39 instead of +0x38 |
| `sixth-unsigned` | Zero extension instead of sign extension |
| `sixth-wide-store` | Halfword store overwrites adjacent byte |
| `sixth-skip-same` | Omit the original's unconditional store for equal bytes |

The wrong fourth-return mutant retains its volatile load and explicitly marks
the local previous value used, so it remains buildable with warnings as errors.

## Regressions, provenance and closeout

The corrected return declarations leave both existing caller builds and their
complete comparison objects identical to the previous package:

- `local/validation/heap-config-20261007-wrapper-regression/COMPLETE.json`:
  16,144 wrapper cases, 96 text bytes, all 25 original addresses; all four
  lower dependencies remain modeled.
- `local/validation/heap-config-20261007-retained-regression/COMPLETE.json`:
  324 scenarios, 5,184 wrapper executions, 3,856-byte image and 853 original
  addresses; configuration and allocator remain modeled in this mode.

Exact result comparisons are in
`local/validation/heap-config-20261007-regression-audit.json`.
All **50 public tests** pass; command, exit code and full output are recorded in
`local/validation/heap-config-20261007-public-tests.json` and its `.log`.
The thirteen sequential positive/negative/regression commands are indexed in
`local/validation/heap-config-20261007-checks.json`. The complete package index
is `local/validation/heap-config-20261007-package.json`.

Before editing, the prior package's six positive markers/binaries, ten negative
markers/binaries and five changed-file hashes were verified against its index;
see `local/validation/heap-config-20261007-handoff-audit.json`. Existing source
and checker files are preserved apart from the configuration declarations in
the shared header. New files contain project-authored recovery/harness code;
no external source was imported. All started commands finished, and
no detached Ghidra/build job remains. No live gameplay session was requested.
This package is complete; no subsequent recovery target was started.

## Reproduce

Run from `SMT4-decomp`, with fresh ignored output directories. Ghidra jobs on
one saved project must be sequential.

```powershell
python tools/check_resource_heap_configure.py --output local/validation/NEW-CONFIG-DIRECT
python tools/check_resource_heap_configure.py --mutant fifth-boolean --output local/validation/NEW-CONFIG-NEGATIVE
python tools/check_resource_heap_allocate.py --output local/validation/NEW-WRAPPER-REGRESSION
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --recover-raw-allocation --recover-heap-allocation --output local/validation/NEW-RETAINED-REGRESSION
python -m unittest discover -s tests -v
```

## Evidence limits and next bounded package

These are direct leaf contracts. Existing wrapper and retained modes still model
all three configuration entries and `0x00146AD8`; new source does not silently
broaden their older evidence. Live gameplay, concurrency, full compiler/ABI,
binary matching and a reconstructed application remain unverified. G1/G2 live
gates remain deferred and unpassed. Lower allocation/free, complete heap layout,
capacity and option semantics remain open. No PC-port implementation is included.

Next add **optional configuration integration to the direct heap-wrapper checker**
(`tools/check_resource_heap_allocate.py`, `CompareResourceHeapAllocate.java`),
for example `--recover-configuration`. Link `resource_heap_configure.c` and
execute original/rebuilt `0x00146CE0`, `0x00146CF0`, `0x00146D10` within the
six-word wrapper. Keep `0x00146AD8` as the only inner model in that new mode.
Preserve the default mode's four models and existing corpus/results. Replace its
36-byte counter-only fixture with coherent guarded backing for heap+0x4C,
+0x4E, +0x50 and +0x54: configuration fields currently sit within counter guards.
Use varied initial fields/full-width options, observe intermediate stores/order,
and verify all fields at the allocator boundary. Do not keep artificial model
counter effects on now-recovered configuration calls; allocator-model counter
effects can still test the wrapper's post-call load. Check null returns, address
wrapping, return preservation and saved registers; reject integrated mutants,
then rerun the direct leaves, older wrapper mode and retained integration.
Retained configuration integration can follow as a separate package after that
broader direct domain is validated. It adds no new entry-point contracts.
