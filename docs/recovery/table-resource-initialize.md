# Table-resource registry initialization

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored recovery from ARM instructions; descriptive source names,
no external implementation reused, no private resource strings copied.

## Strategy review and acceptance

The previous dispatch marker's source/tool
hashes all matched before edits (`table-registry-20261013-static/prior-handoff-check.json`
under `local/validation`). Its completed milestone was retained, not repeated.
The recorded next target directly replaces one modeled startup callback and
registry construction fixtures. Optional extraction/compiler research and live
verification do not block this source package. No reprioritization was needed.

Acceptance, declared before implementation: recover ARM `0x003F05F0`, its
ancillary writes and all 67 records; preserve exact path addresses, policy
bytes, loaded/size clearing and opaque bytes; build warning-clean; compare
ordered effects and guarded memory against original execution; replace callback
190 in the dispatcher corpus; exercise existing registry/bulk consumers from
constructed state; reject meaningful compiled faults and retain regressions.
Full process startup, other constructors, file service behavior and live G1/G2
are outside this milestone.

## Recovered source and original contract

`src/table_resource_initialize.c` and `.h` add **one complete entry contract**,
`smt4_table_resource_initialize(void)`, corresponding to ARM `0x003F05F0`.
Executable intervals are `[0x003F05F0,0x003F090C)` and
`[0x003F0CB8,0x003F0F50)`, joined by the branch at `0x003F0908`; the last
instruction is `BX LR`. There are **365 original instruction sites**.
The intervening region is literals and strings. Read-only saved-project inspection
finds **no saved function/instruction objects** there, with ARM context zero;
it does not claim saved membership was already established. Hash-bound raw
bytes, independent GNU disassembly, and instruction-level execution agree.
The saved project and original image are unchanged.

The initializer has no input and no consumed return value. It writes, in order:

1. Two `0xFFFFFFFF` words at `0x00446518` and `0x0044651C`.
2. Zero words at `0x00446520` and `0x00446524`.
3. For each record in ascending order at `0x0049382C + 16*i`, its original path
   address at +0, policy byte at +12, zero loaded word at +4, zero size at +8.

All 67 path addresses are explicit reviewed bindings in source. There are
**46 policy-one and 21 policy-zero records**. Slot 1 keeps path `0x003F0930`
and policy one. The three bytes at +13..+15 remain unchanged. Paths are original
32-bit values into the pinned image, not embedded host strings or native pointers.
No loaded resource is freed, no I/O is performed, and no other callee is invoked.
The initial scalar stores model the original STRD/STM effects as ordered words;
atomicity or observation between those writes is not claimed.

The C loop replaces unrolled instruction stores while volatile scalar accesses
preserve their observed order and widths. The static path/policy array is a
source representation of instruction constants, not a new original data table.
The supported domain is writable, ordinary, correctly aligned original-address
storage with no concurrency, reentrancy or MMIO. Direct poisoned-state cases
check overwriting nonzero words; they do not establish safe reinitialization of
live resources. Scratch registers and an unused r0 result are not C outputs.

## Integration and modeled boundaries

`--recover-table-registry` in `tools/check_resource_pool_initialize.py` builds
the new source with existing startup/global constructor, lifecycle and bulk
source. `CompareTableResourceInitialize.java` extends the existing comparison;
two small dispatch hooks select a machine and handle an additional callback.
These build/harness changes are support, not additional recovered contracts.
Shared lifecycle, bulk, global-constructor and dispatcher source is unchanged.

Pinned relative-table entry 190 at `0x0042A480`, offset `0xFFFC6170`, invokes
the actual initializer in the original path and its rebuilt source in the
rebuilt path. The new corpus retains concrete resource constructor entry 331.
**634 other constructor bodies per pinned traversal remain modeled**, down
from 635 in the older dispatcher-only mode. Old modes retain their documented
scope; they are not retrospectively claimed to execute this initializer.

The initializer oracle derives path/policy constants from the reviewed ARM
instruction forms and compares every original/rebuilt ordered store, including
byte widths. The separate static decoder used for source transcription is saved
locally. The original P-code execution independently checks those decoded effects.
All 272 normalized stores (268 registry stores plus four ancillary words) must
match; stack and surrounding bytes, callee-saved registers, SP and return mode
are checked. Original execution is confined to the two code intervals.

Three direct pairs use 0x00, 0xFF and 0xA5 initial registry/guard bytes. Each
machine then retains its constructed state across 13 consumer calls, without
reseeding registry fields: dynamic policy rejection, null-result load/retry,
loaded skip, release preserving stale size, unsigned invalid IDs 67 and
0xFFFFFFFF, bulk passes with null/nonzero/mixed returns and size preserved/written,
and a repeated bulk pass. Lower/upper index schedules exercise different orders.
The resulting **39 consumer pairs** execute recovered ARM `0x00297714`,
`0x002A49E0` and `0x0033C8A0` and their rebuilds. Whole state is checked at each
modeled dependency and at return. The direct construction/consumer sequences
are distinct from the pinned dispatcher executions; this does not claim a
single end-to-end startup-to-file-I/O run.

Index helper `0x0029706C`, load `0x002C3344` and release `0x002C43B4` are explicit
models in this new connected mode. Their arguments/order, caller-saved clobbers
and selected outputs are checked; their bodies do not execute. The previously
recovered index/remainder chain and its separate comparison remain unchanged.
Request/callback consumers, real file bytes, allocation and synchronization
are not newly covered. Inherited pool backing/singleton fixtures and scheduled
exclusive outcomes retain the startup report's boundaries. Arbitrary callbacks,
full process startup, concurrency, native services and live G1/G2 remain open.

## Validation

Primary: `local/validation/table-registry-20261013-dev1/COMPLETE.json`.
The first build/comparison passed; the development directory name is retained.

- Warning-clean freestanding ARMv6K build: **4,484 bytes**, including existing
  dispatch/global/lifecycle/bulk source and the new initializer/data. This is not
  a matching or whole-game build. The 1,132-byte increase over dispatch-only
  includes supporting consumer linkage and is not all newly recovered code.
- **15 dispatcher pairs** retain all 24 dispatcher sites and include four table
  initializer invocations across the two pinned relative pairs and both paths.
- **Three direct initializer pairs**, giving ten initializer calls across both
  paths in total; all **365** original sites and **272 ordered stores per call**.
- **39 persistent consumer pairs**, with **426 modeled file loads across both
  paths**; original/rebuilt/expected guarded state and model arguments agree.
- Three compiled faults rejected by runtime store assertions: slot-one policy,
  an extra reserved-byte write, and the second ancillary sentinel.
- Retained dispatcher-only comparison: same 3,352-byte binary and entire
  comparison object as `startup-dispatch-20261013-dev1`; default models retained.
- **134 public tests pass**. Final audit checks source/tool hashes, original and
  rebuilt image hashes, Python syntax, JSON and package whitespace.

Audit: `local/validation/table-registry-20261013-audit/COMPLETE.json` with
`negative-checks.json`, `regressions.json` and `public-tests.log`.
Static evidence: `local/validation/table-registry-20261013-static/`, including
`membership.txt`, `decoded-stores.json`, `initializer.log`, `continuation.log`
and `prior-handoff-check.json`. All Ghidra jobs are sequential and read-only.
No commit or live session.

```powershell
python tools/check_resource_pool_initialize.py --recover-table-registry --output local/validation/NEW-TABLE-REGISTRY
python tools/check_resource_pool_initialize.py --recover-table-registry --mutant table-policy --output local/validation/NEW-TABLE-NEGATIVE
python tools/check_resource_pool_initialize.py --recover-startup-dispatch --output local/validation/NEW-DISPATCH-REGRESSION
python -m unittest discover -s tests
```

## Next independent source milestone

Recover loaded table-resource reload ARM **`0x0025C848..0x0025C8F4`**. Its
static lifecycle lead is still unrecovered: no corresponding source exists.
Fresh GNU disassembly is saved at
`local/validation/table-registry-20261013-static/next-reload.log`.
The registry literal is `0x0025C8F4`; the next function begins `0x0025C8F8`.
Confirm saved function membership before implementation.

The entry first calls gate `0x002C5890(2)`, then checks unsigned ID <67 and
nonnull loaded data. It queries `0x0025B9E8`, enables a state with
`0x0025B9D8(1)`, loads replacement bytes through `0x002C3344`, and compares sizes.
Equal sizes copy via `0x002C6048` into the old allocation then release the new
one; unequal sizes release the old allocation and publish the new pointer/size.
It restores the state with `0x0025B9D8(0)` only when initially clear. Do not infer
null-load error handling: no null test is visible before copy/publication.

Read `docs/recovery/resource-lifecycle.md` and this report. Recover the reload
contract with explicit gate/state/copy/service boundaries, grouping the two
state accessors only if their instruction evidence makes that bounded. Use
constructed registry state and controlled loaded allocations, preserving
release/copy/publication order, equal/unequal/zero sizes, policy independence,
invalid IDs, gate short-circuit and initial-state restoration. Reuse the current
build/comparison interfaces.
