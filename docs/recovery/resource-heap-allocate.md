# Resource six-word heap allocation wrapper

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x002C3A98` is reconstructed in
[`src/resource_heap_allocate.c`](../../src/resource_heap_allocate.c).
This adds one analyzed, understood, implemented, buildable and bounded
behavior-verified entry-point contract: **40 plus two adapted worker regions**.
The direct raw-router checker and older retained-worker modes still model this
wrapper. The optional retained integration described below executes it without
broadening those older evidence boundaries or adding another entry-point contract.

## Contract and instruction evidence

The six u32 inputs are `(heap, size, alignment, fourth, fifth, sixth)`.
The fifth and sixth arrive at entry SP and SP+4. The wrapper occupies exactly
`[0x002C3A98,0x002C3AFC)`: 25 ARM instructions, no embedded literal data.
It saves the original heap, size, alignment and both stack arguments, then calls:

| Order | Original dependency | Arguments marshaled by wrapper |
| --- | --- | --- |
| 1 | `0x00146CE0` | `(heap+0x18, fourth)` |
| 2 | `0x00146CF0` | `(heap+0x18, fifth)` |
| 3 | `0x00146D10` | `(heap+0x18, sixth)` |
| 4 | `0x00146AD8` | `(heap+0x18, size, alignment)`; allocation result in r0 |

All four calls remain explicit models. Their names in the header describe
argument positions, without assigning meanings to the option words or recovering
the lower implementation. Incidental extra volatile-register values at the first
three calls are outside the interface. Their return values are ignored.

The fourth call's r0 is returned unchanged. For nonzero r0 only, instructions
`0x002C3AEC` through `0x002C3AF4` read the current u32 at `heap+0x54`, add one
modulo 2^32 and store it back. This read occurs after all four dependencies;
null results perform neither a counter read nor a counter write. Size zero
does not bypass any dependency. Full-width argument words are forwarded,
including signed-alignment bit patterns, without validation or narrowing.
Object-address arithmetic also wraps as u32. No locking occurs in this wrapper.

The earlier raw-router inspection is
`local/validation/allocate-raw-20261007-inspect/exports/listing.txt`.
The new check exports the wrapper and bounded windows around nine saved call
references, then independently decodes their original bytes with pinned GNU
objdump. `local/validation/heap-allocate-20261007-static-audit.json` records
agreement for 172 instruction occurrences (25 wrapper and 147 caller-window
occurrences), as well as agreement with the previous wrapper listing.
This is a check of known saved references, not proof that every caller has
been discovered or recovered.

Call sites `0x00103814`, `0x002B27C4`, `0x002B2814` and `0x003F7378` save r0
before calling the enclosing lock release. Four small wrappers at call sites
`0x001A0E94`, `0x001C2A38`, `0x001FFAE8`, `0x00203BA4` return with r0 intact.
The call at `0x003F72D4` likewise returns r0 and marshals option bytes from an
outer object; its sixth option is sign-extended before the call. These windows
reinforce the instruction-derived return contract despite the earlier
decompiler's void-return guess. They are static evidence, not new recovered
entry points. No original call-site function was modified.

## Build and controlled comparison

Run from `SMT4-decomp` with fresh ignored output directories; Ghidra jobs on
the authoritative project must remain sequential:

```powershell
python tools/check_resource_heap_allocate.py --output local/validation/NEW-HEAP-DIRECT
python tools/check_resource_heap_allocate.py --mutant early-count --output local/validation/NEW-HEAP-NEGATIVE
python tools/check_resource_allocate_raw.py --output local/validation/NEW-RAW-REGRESSION
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --recover-raw-allocation --output local/validation/NEW-RETAINED-REGRESSION
python -m unittest discover -s tests -v
```

Final positive marker:
`local/validation/heap-allocate-20261007-direct-final/COMPLETE.json`.
Pinned GCC builds **96 text bytes**, SHA-256
`d710c76ba646e49e5d92f8e35db706f14724ed2122110ea37876f17625a139c8`.
The source uses C11, ARMv6K, ARM mode and the existing freestanding soft-float
comparison flags. Only the four named lower dependencies are linker bindings.
The rebuilt path executes no original code. The original is 100 bytes; GCC
uses conditional counter instructions and different register allocation.
This is behavioral recovery, not a binary match or reconstructed application.

| Check | Recorded result |
| --- | ---: |
| Original/rebuilt/independent-oracle comparisons | 16,144 |
| Null allocation results | 4,036 |
| Counter increments wrapping to zero | 4,666 |
| Cases with modeled counter effects | 10,762 |
| Zero-size calls, still invoking all dependencies | 3,024 |
| Cases with wrapping heap-address arithmetic | 5,381 |
| Original instruction addresses visited | All 25 |
| Dependency calls checked across both paths | 129,152 |
| Maximum instructions per invocation | 25 |

The deterministic grid has 15,120 cases: three heap-address patterns; five
sizes including zero, one, high-bit and max; 14 alignment words including all
ten signed values produced by the router; six counter boundaries; four return
patterns (null, one, high-bit and max); and three dependency-effect profiles.
Three distinct option triples rotate through the grid. Another 1,024 seeded
cases supply random full-width sizes, alignment, options, counts and returns.
The three heap patterns are ordinary, high-bit and `0xFFFFFFF0` (subobject
wraps to 8 and counter to `0x44`). All counter fixtures are word aligned.

Each path is checked independently against the contract oracle, then against
the other path's dependency/store trace and final counter/guard bytes. Models
either preserve the counter or change it after every call; final allocation
effects use an XOR pattern or force `0xFFFFFFFF`. These effects test the
post-call reload and overflow, without pretending to implement lower calls.
Models clobber volatile integer/VFP registers and flags, and give unrelated
return words to the first three calls. The checks enforce exact call order,
consumed arguments, 8-byte stack alignment at calls, preserved allocation
result, conditional read/write counts, saved r4-r11 and d8-d15, restored SP,
unchanged caller stack, a bounded 64-byte stack region and guarded counter
storage. Unexpected reads, writes and instruction execution are rejected.
The caller stack argument slots remain stable across the modeled calls.

The first positive run at `local/validation/heap-allocate-20261007-direct/`
also passed. The driver then gained warning-safe mutation generation and
richer negative markers; the final run revalidates those final tool hashes.
Both runs have the same source binary and comparison results. No failed
positive comparison or recovered-source correction occurred in this package.

## Negative checks and regressions

All twelve independently compiled mutants fail a corpus assertion:

| Mutant | Rejected behavior |
| --- | --- |
| `subobject` | Wrong subobject offset |
| `fourth-word`, `fifth-word`, `sixth-word` | Wrong full-width forwarded option |
| `call-order` | Reversed first two dependencies |
| `size-alignment` | Swapped allocator size/alignment |
| `null-count` | Counter access on null instead of nonzero |
| `counter-offset` | Wrong counter field |
| `increment` | Increment by two |
| `early-count` | Read before the allocation call returns |
| `return` | Lost nonzero allocation result |
| `zero-size` | Added early return absent from original |

Markers are under `local/validation/heap-allocate-20261007-negative-*/NEGATIVE.json`;
each records the compiled binary hash and actual exception. Command results
are in `local/validation/heap-allocate-20261007-negative-runs.json`.
Unused-argument casts occur only in local mutant copies so wrong-forwarding
variants remain buildable under warnings-as-errors. Compilation failures
are not accepted as mutant rejection.

The direct raw-router regression is
`local/validation/heap-allocate-20261007-raw-regression/COMPLETE.json`:
8,824 comparisons, 292 bytes and all 85 original addresses, with the same
binary hash and complete comparison object as the previous package.
The retained raw-router regression is
`local/validation/heap-allocate-20261007-retained-regression/COMPLETE.json`:
324 scenarios, 5,184 router executions, 3,760 bytes and 828 original addresses,
also unchanged in binary and complete comparison result. Both retain the
modeled `0x002C3A98` boundary. These runs check compatibility of the shared
header additions; they do not integrate the newly recovered wrapper.

All **50 public tests** pass. Commands and outputs are indexed by
`local/validation/heap-allocate-20261007-checks.json` and
`local/validation/heap-allocate-20261007-public-tests.json`.
The package index is `local/validation/heap-allocate-20261007-package.json`.
The preceding handoff was checked against eight saved positive marker/binary
hashes, five negative marker hashes and its saved public-test log; see
`local/validation/heap-allocate-20261007-handoff-audit.json`.

## Direct package limits and historical follow-up

This contract establishes only the wrapper's forwarding and conditional
counter update. The heap algorithm, option meanings, complete object layout,
valid heap capacities, actual allocation/failure policy, synchronization and
counter lifetime remain unknown. Returned words and wrapping addresses are
opaque arithmetic probes, not usable allocated storage. Tests provide only
guarded counter storage and dependency models, not complete heap objects.
There is no concurrent-memory or live gameplay claim. G1/G2 live gates remain
deferred and unpassed; full ABI/compiler identity, matching and native runtime
remain open.

Next, add an **optional retained-wrapper integration** to
`tools/check_resource_registry_worker.py` and
`tools/ghidra/CompareResourceRegistryWorker.java`, requiring the existing
`--recover-raw-allocation` dependency chain. Link `src/resource_heap_allocate.c`
and execute original/rebuilt `[0x002C3A98,0x002C3AFC)` inside
`executeRawAllocation` instead of intercepting `LOWER_ALLOC` there. Move the
raw fixture/return boundary to `0x00146AD8`; keep it and the three configuration
calls modeled. Supply guarded counter backing for each captured heap address:
the current router fixture changes raw base after calls and uses wrapping
addresses, so this must be designed before enabling wrapper loads/stores.
Check wrapper counter updates against modeled lower effects and retain outer
lock reloads, captured router locks, caller state and address-reuse checks.
Do not infer counter decrement/free behavior from this allocation-only source.
Keep older modes unchanged, reject integration mutants, rerun the direct
wrapper and caller regressions, and leave locks/fixed-object allocation/live
gates explicit. That integration adds no new entry-point contract.

## Retained wrapper integration (2026-10-07)

`--recover-heap-allocation` requires `--recover-raw-allocation` and its complete
allocation/conversion/selector/registration chain. It links the existing faithful
`resource_heap_allocate.c`, without modifying recovered source. Original/rebuilt
wrapper instructions execute inside `executeRawAllocation`. The raw-address,
registration-category and lifetime/reuse fixtures now take effect at modeled
`0x00146AD8`, after the three modeled configuration calls. There is no synthetic
return or dependency effect at the recovered `0x002C3A98` boundary.

Each captured heap gets a disjoint 36-byte guarded region containing just its
`heap+0x54` counter and 16 guard bytes on each side. These regions remain in
the retained memory oracle through registration, submission, worker cleanup and
the second batch; the harness does not decrement them on free. Wrapping raw bases
produce a captured heap of `0xC` and counter at `0x60`. This is bounded arithmetic
backing, not a complete heap object. Overlapping counter fixtures are rejected.

The inner models change the counter after every dependency. The final model
forces `0xFFFFFFFF` for half the retained invocations and supplies an XOR-derived
value otherwise. The independent oracle expects one modulo-u32 increment after
the allocator returns. Reads before that return, extra reads/stores, wrong-width
accesses and accesses to counter guards are rejected. Final bytes and the complete
external-store multiset must match the oracle. Dependencies also change the raw base and outer
lock handle: the router must retain its captured heap/object lock while the outer
allocation layers must reload their lock handle. Models clobber volatile integer
registers and flags using the existing retained harness; no new VFP-clobber claim
is made for this integration.

Checks retain six incoming arguments, four inner calls in order, inner arguments,
8-byte stack alignment at calls, caller argument slots, bounded stack access,
callee-saved integer registers and allocation return preservation. The original
wrapper disassembly exactly matches the prior direct recovery's GNU listing.
The rebuilt path executes no original instructions. GCC produces **3,856 bytes**:
**3,832 text bytes plus 24 read-only data bytes**, SHA-256
`7e3016b0e1c049e88a01c4b45a3607de069657bb381d48be1c45f53838ba5f28`.
This is controlled behavioral agreement, not binary matching.

Primary marker:
`local/validation/heap-retained-20261007-integrated/COMPLETE.json`.

| Check | Across both paths unless noted |
| --- | ---: |
| Retained scenarios | 324 |
| Heap wrappers / raw routers / allocation / registration / conversion | 5,184 each |
| Modeled inner calls | 20,736 |
| Counter reads / writes | 5,184 each |
| Counter increments wrapping to zero | 2,592 |
| Invocations with wrapping raw-base-to-heap arithmetic | 324 |
| Router object-lock calls | 10,368 |
| Reused payload allocations | 2,592 |
| Submissions / completions | 2,592 each |
| Selector executions | 13,824 |
| Original addresses visited | 853, including all 25 wrapper addresses |

The constructor domain remains selectors `0x100`, nonzero rounded sizes,
three zero option words and nonnull allocation results. Null returns, arbitrary
options/alignments and other routing selectors remain direct-corpus evidence.
Instruction visitation does not demonstrate every predication outcome. The new
counter backing does not establish capacity, lower option semantics, concurrent
behavior or decrement/free semantics. The inner allocator, three configuration
calls, fixed-object allocation, recursive locks and other documented lower models
remain unrecovered in this mode. Live G1/G2 evidence remains deferred and unpassed.
The result field `raw_lower_dependencies_modeled=false` describes the exercised
raw-router-to-heap-wrapper boundary; it does not recover the unexercised
fixed-object allocator or the four modeled inner dependencies.

Run from `SMT4-decomp` with fresh ignored output directories and sequential
Ghidra jobs:

```powershell
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --recover-raw-allocation --recover-heap-allocation --output local/validation/NEW-HEAP-INTEGRATED
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --recover-raw-allocation --recover-heap-allocation --mutant heap-early-count --output local/validation/NEW-HEAP-INTEGRATED-NEGATIVE
python tools/check_resource_heap_allocate.py --output local/validation/NEW-HEAP-REGRESSION
python tools/check_resource_allocate_raw.py --output local/validation/NEW-RAW-REGRESSION
python -m unittest discover -s tests -v
```

### Integrated negative checks

All ten local compiled mutants are rejected by corpus assertions, after successful
builds: `heap-subobject`, `heap-call-order`, `heap-size-alignment`,
`heap-null-count`, `heap-counter-offset`, `heap-increment`, `heap-return`,
`heap-early-count`, `raw-reload-lock`, and `cached-outer-lock`. The last two
exercise the distinct captured-router and reloaded-outer lock contracts while
the recovered wrapper's inner models change those states. Negative markers
include binary hashes and actual assertion text; their index is
`local/validation/heap-retained-20261007-negative-runs.json`.

Three CLI misuse cases reject missing mode dependencies before creating an output
directory; see `local/validation/heap-retained-20261007-cli-guards.json`.
All **50 public tests** pass, recorded in
`local/validation/heap-retained-20261007-public-tests.json` and its log.
The prior handoff's three positive markers/binaries, twelve negative markers and
eight changed-file hashes were checked against the files before implementation.
`local/validation/heap-retained-20261007-baseline.json` retains pre-edit hashes;
`local/validation/heap-retained-20261007-source-audit.json` records preservation
of recovered source and the unchanged original wrapper disassembly.

### Regressions and evidence index

The single-batch mode also passes at
`local/validation/heap-retained-20261007-single-batch/COMPLETE.json`: 324 scenarios,
2,592 wrappers and 10,368 inner calls, with the same 3,856-byte image and 853
original instruction addresses. The retained and single-batch runs both passed
on their first attempts; no source or harness correction followed a failed
positive comparison.

The following regressions have identical binaries and complete comparison
objects to their prior positive markers:

- `local/validation/heap-retained-20261007-direct-regression/COMPLETE.json`:
  16,144 direct wrapper cases, including 4,036 null returns; 96 bytes.
- `local/validation/heap-retained-20261007-raw-regression/COMPLETE.json`:
  8,824 direct raw-router cases; 292 bytes.
- `local/validation/heap-retained-20261007-retained-regression/COMPLETE.json`:
  324 scenarios, 5,184 routers, 3,760 bytes and 828 original addresses.
- `local/validation/heap-retained-20261007-default-regression/COMPLETE.json`:
  the older default checker, 324 scenarios and 578 original addresses.

The command/result index is `local/validation/heap-retained-20261007-checks.json`;
exact comparisons are in `local/validation/heap-retained-20261007-regression-audit.json`.
The complete package index is `local/validation/heap-retained-20261007-package.json`.
All started commands finished; no detached Ghidra/build job remains.

### Subsequent direct configuration recovery (2026-10-07)

The three configuration entries `0x00146CE0`, `0x00146CF0` and `0x00146D10`
now have direct source/build/comparison contracts in
[the configuration report](resource-heap-configure.md). They are leaf setters
with previous-value returns; this wrapper ignores those returns. Its direct and
retained modes still retain all four documented inner models. The next bounded
package is optional configuration integration into the direct wrapper checker,
with coherent backing for the configuration fields and counter; the configuration
report owns the detailed next task. Existing integration evidence is unchanged.
