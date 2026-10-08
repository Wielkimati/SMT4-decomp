# Resource inner heap block selection

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry **`0x00146AD8`**, exclusive end **`0x00146C20`**, is recovered in
[`src/resource_heap_allocate_inner.c`](../../src/resource_heap_allocate_inner.c).
This adds one bounded entry-point contract: **44 plus two adapted worker regions**.

## Selection and acceptance

Its completion markers and extracted table length/hash
were checked (`local/validation/heap-inner-20261008-audit/handoff-check.json`).
This package advances A07 source recovery under G2's bounded source/comparison
criteria; it does not close G2's deferred live evidence or G3.

The selected milestone is the complete callable **block-selection** behavior of
`0x00146AD8`, including its single required dependency boundary, integrated with
the already recovered wrapper `0x002C3A98` and setters `0x00146CE0`, `0x00146CF0`,
`0x00146D10`. Acceptance requires instruction-backed arguments/layout/arithmetic,
a warning-clean ARM build, original/rebuilt/oracle agreement on both traversal
directions, no-fit and null returns, selection/ties/early exits, overflow and field
accesses, plus caller integration, deliberate fault rejection and affected
regressions. Storage mutation at **`0x0014F608`** is an explicit remaining model.
Its splitting, used/free lists, metadata and clearing form a separate dependency
boundary with a materially different arena fixture; it is the next source target.

## Instruction-derived source contract

Inputs are `(subobject, size, alignment)` as u32 words. The wrapper passes
`heap+0x18` as the subobject. All arithmetic below wraps modulo 2^32; source uses
unsigned arithmetic and explicit original addresses, not native object pointers.

1. Replace input size zero with one, then compute `(size+3)&~3`. This can wrap
   large nonzero sizes to zero; there is no overflow rejection.
2. Read u16 at subobject+`0x36`. Bit 0 clear selects the first eligible node;
   bit 0 set selects the strictly smallest eligible capacity. Other bits have
   no effect on this routine.
3. For alignment bit 31 clear, read the forward head at subobject+`0x24`, then
   follow node+`0x0C`. For each node, start is node+`0x10`, capacity is u32 at
   node+4, and candidate is `(start+alignment-1)&~(alignment-1)`. Eligibility is
   unsigned `capacity >= candidate-start+rounded` **and** `capacity < best`.
4. For alignment bit 31 set, read the reverse head at subobject+`0x28`, then
   follow node+8. Candidate is `(capacity+start-rounded)&~(-alignment-1)`.
   Eligibility is **bit 31 clear in `candidate-start`**, and unsigned
   `capacity < best`. The original `SUBS`/`BMI` tests N alone. Replacing this
   with unsigned `candidate >= start` changes wrapping cases.
5. Best capacity initially equals `0xFFFFFFFF`; even a fitting node with that
   capacity is never selected. Equal-capacity ties preserve the first selected
   node in traversal order. After selection, stop for first-fit mode or when
   capacity equals rounded size; otherwise keep walking. Empty/no-fit lists
   return null and make no lower call.
6. A selected node causes exactly one five-word call to `0x0014F608` with
   `(subobject+0x24, node, candidate, rounded, reverse)`, where reverse is 0 or 1
   on the stack. Return its r0 unchanged. The selection routine makes no external
   stores and performs no external reads after this call returns.

Alignment zero, non-power-of-two words and the signed-minimum pattern are not
rejected. Their bitwise results are covered as arithmetic observations, without
claiming valid allocations. Neither requested capacity nor returned payload is
dereferenced by this routine. Cyclic or invalid lists have no new source guard.

Read-only saved-project export is
`local/validation/heap-inner-20261008-inspect/exports/listing.txt` and
`pseudocode.c`. The saved function begins at the requested entry and ends at
`0x00146C1C`; one saved call reference is `0x002C3AE0`. This is not a complete
caller-discovery claim. The source was checked against original instructions,
including the predicated forward comparison and reverse N-bit condition, rather
than relying on the decompiler's complicated loop reconstruction.
`local/validation/heap-inner-20261008-audit/static-audit.json` records exact byte
agreement among GNU ARM disassembly, Ghidra and the pinned image for all 123
instructions in the inner routine, wrapper and setters (82+25+16). The driver
also preserves independent GNU disassembly of `[0x0014F608,0x0014F7EC)`, including
two trailing literal words, as a static lead for the remaining dependency.

## Build and controlled evidence

Primary marker:
`local/validation/heap-inner-20261008-direct-integrated/COMPLETE.json`.
Pinned GCC builds **532 text bytes**: 364 for selection, 96 for the wrapper,
72 for the setters. Only `smt4_resource_heap_commit_block=0x0014F608` is bound
externally. C11, ARMv6K ARM mode, freestanding soft-float, optimization and
warnings-as-errors match the existing comparison setup. No SDK or original
binary helper executes on the rebuilt path. This is behavioral agreement,
not binary matching or a reconstructed game executable.

The checker is
[`tools/check_resource_heap_allocate_inner.py`](../../tools/check_resource_heap_allocate_inner.py)
with
[`CompareResourceHeapAllocateInner.java`](../../tools/ghidra/CompareResourceHeapAllocateInner.java).
It reuses the existing P-code machine and pinned tool wrappers. The new source
contract is distinct from this necessary harness/integration work. The existing
wrapper and setters were linked unchanged; they add no new entry contracts.

| Observation | Result |
| --- | ---: |
| Original/rebuilt/oracle comparisons | 23,616 |
| Direct inner / integrated wrapper cases | 11,808 / 11,808 |
| No selection (no lower call) | 13,502 |
| Reverse-direction cases | 11,130 |
| Rounded size wraps to zero | 3,264 |
| Selected node, modeled return null | 2,509 |
| Integrated counter wraps to zero | 2,090 |
| Selection beyond initial traversal node | 3,740 |
| Equal-capacity observations | 3,298 |
| Original instruction addresses visited | 123 |
| Dependency calls across both paths | 20,228 |
| Maximum instructions per invocation | 183 |

The deterministic grid has 22,848 cases: three subobject address patterns,
14 sizes, 17 alignments, eight list/capacity profiles, two policy bits and
direct/integrated entry modes. Another 768 seeded cases use full-width random
sizes, alignments, options and capacities, with up to six nodes. Profiles include
empty lists, zero/maximum capacity, exact fits, undersized nodes, equal sizes,
later smaller fits and capacities at sign boundaries. Nodes have consistent
forward/backward links. Ordinary, high-bit and wrapping subobject arithmetic
is exercised; one node starts at `0xFFFFFFE0` to stress candidate overflow.

Every original/rebuilt invocation is separately checked against a byte-oriented
oracle, then the same expected ordered trace. The oracle enumerates the known
fixture traversal order, independently of the emulator's pointers. It checks
exact read/store widths, addresses and ordering, the five consumed lower-call
arguments, returned word, all guarded header/node bytes, stack alignment at
the lower call, caller stack preservation, bounded 128-byte stack scratch,
restored SP, r4-r11 and d8-d15. Unexpected/uninitialized reads or code execution
are rejected. VFP volatile registers, integer volatile registers and flags are
clobbered by the lower model.

Integrated calls execute all three setters before selection. Initial policy bit
differs from the passed option bit in the grid, so the selected traversal policy
must reflect the actual setter write. Full-width options are narrowed only by
the recovered setters; unrelated bits and bytes remain checked. The dependency
can preserve state or synthetically change list heads, policy, node capacities
and counter. Those changes are model probes, not assertions about `0x0014F608`.
They prove there are no post-commit selection reads and that the wrapper reloads
the counter after a nonnull return, while a null result leaves it untouched.

## Scope, remaining model and next package

This fixture provides list headers and a bounded subobject field region, not
complete storage for their declared capacities. Large capacities, overflow,
zero/non-power-of-two alignments and opaque model returns probe original
selection arithmetic; they do not establish allocatable memory or success of
the real commit routine. Backing is aligned, finite and nonoverlapping. Invalid
backing, cycles, concurrent mutation and a complete heap lifetime remain outside
the claim. Visited instruction addresses do not establish all predication outcomes.

The new combined checker replaces four wrapper-level models with actual recovered
configuration/selection execution and has just **`0x0014F608`** modeled. Older
direct-wrapper and retained-worker modes retain all their existing interception
boundaries and evidence. Retained-worker configuration/selection integration is
not claimed. Lower free/conversion services, fixed-object allocation, recursive
locks and other previously recorded resource models remain open. No PC-port work,
original input changes or live gameplay checks are included. G1/G2 live evidence,
full ABI/compiler provenance, matching and G3 review remain open.

Next recover **`0x0014F608`** in a source file such as
`src/resource_heap_commit_block.c`. Verify its saved-project entry/end and compare
its listing with `original-commit.log` in the primary evidence directory. It
consumes the five observed arguments and has no BL in the inspected GNU range.
Build a valid guarded arena fixture covering removal at list endpoints/interior,
prefix/suffix remainders around the 20-byte threshold, direction and configuration
byte effects, metadata widths and optional clearing from the word at lists-4.
Link it into the new selection checker only over valid arena-backed cases;
retain this package's broader model-based arithmetic domain explicitly. Recover
storage writes/return and compare original/rebuilt memory, then run affected
regressions. Do not treat synthetic huge capacities as real arenas.

## Reproduce

Run from `SMT4-decomp`, with fresh output directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_heap_allocate_inner.py --output local/validation/NEW-INNER
python tools/check_resource_heap_allocate_inner.py --mutant reverse-sign --output local/validation/NEW-INNER-NEGATIVE
python tools/check_resource_heap_allocate.py --output local/validation/NEW-WRAPPER
python tools/check_resource_heap_configure.py --output local/validation/NEW-CONFIG
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --recover-raw-allocation --recover-heap-allocation --output local/validation/NEW-RETAINED
python -m unittest discover -s tests -v
```

## Negative checks and closeout

All eight independently compiled source mutants were rejected by actual corpus
assertions after successful builds: `zero-size`, `rounding`, `fit-equality`,
`last-tie`, `reverse-sign`, `first-fit`, `direction`, and `return`. They remove
zero-size normalization, change rounding/fit strictness, replace the first tie,
use the wrong reverse condition, invert selection policy, corrupt the fifth
argument, or lose the lower result. Markers are
`local/validation/heap-inner-20261008-negative-<name>/NEGATIVE.json`; each records
the compiled binary hash and actual exception. No compilation failure was
counted as rejection. The positive source/comparison passed on its first run.

Three affected regressions pass, with binary hash and complete comparison object
identical to their prior configuration-package evidence:

- `local/validation/heap-inner-20261008-wrapper-regression/COMPLETE.json`:
  16,144 cases, 96 bytes; all four lower calls still modeled.
- `local/validation/heap-inner-20261008-config-regression/COMPLETE.json`:
  200,976 direct setter cases, 72 bytes; no lower calls.
- `local/validation/heap-inner-20261008-retained-regression/COMPLETE.json`:
  324 retained scenarios, 5,184 wrapper executions, 3,856 bytes; the older
  retained mode still models configuration and inner selection.

Exact comparisons are in
`local/validation/heap-inner-20261008-audit/regression-audit.json`; the sequential
command/exit/log index is `checks.json` in that directory. All **134 public tests**
pass (`public-tests.json` and `public-tests.log`). No new public test was needed
for the unchanged public interfaces; the private differential harness provides
the new source evidence.

The package audit marker is
`local/validation/heap-inner-20261008-audit/COMPLETE.json`. It records source/tool
identity checks against completed builds, static byte agreement, fault markers,
regressions, public tests and whitespace checks. Source and harness code are
project-authored from the pinned reference and existing project infrastructure;
no external implementation was imported. Symbol metadata binds the new source
to its address/hash/evidence. No project gates or reference identities changed.
All started commands completed; no detached Ghidra/build job remains.
