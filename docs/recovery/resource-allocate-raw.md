# Resource raw allocation routing

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x002B26F0` is reconstructed in
[`src/resource_allocate_raw.c`](../../src/resource_allocate_raw.c).
This package adds one analyzed, understood, implemented, buildable and bounded
behavior-verified entry-point contract: **39 plus two adapted worker regions**.
The optional retained-worker integration below reuses this contract; it adds no
entry point. Earlier checker modes still intercept this router at their previous
boundaries.

## Contract and static evidence

The five-word interface is `(first, second, third, size, fifth)`. The original
overwrites the third argument before using it. Size zero returns null without
reading global state or invoking dependencies. The fifth stack word is readable
even on the zero-size route in the original instructions.

For nonzero size, the second word selects alignment magnitude:

| Exact second word | Magnitude |
| --- | ---: |
| `0x100` | 4 |
| `0x101` | 128 |
| `0x102` or any unlisted value | 8 |
| `0x103` | 64 |
| `0x104`, `0x105` | 16 |

Exactly zero in the full-width fifth word negates the alignment modulo 2^32.
Every other value leaves it positive. All nonzero-size calls read the heap
base word at **`0x00465170+4`**, including unsupported and fixed-object routes.
This is a different global from registration/outer allocation state
`0x00465120`. The volatile source declaration preserves that read; it does not
establish concurrent behavior or a complete state layout.

| Exact first word | Behavior |
| --- | --- |
| `0x100` | Acquire `base+0x74`; call `0x002C3A98(base+0x1C, size, signed_alignment, 0, 0, 0)`; release the same lock; return allocation result |
| `0x10000` | Acquire `base+0xE0`; call `0x002C3A98(base+0x88, size, signed_alignment, 0, 0, 0)`; release the same lock; return allocation result |
| `0x20000` | Call `0x00144978(0x004E4100, size, first, 0x00465170)`; return result |
| `0x30000` | Call `0x00144978(0x004E411C, size, first, 0x00465170)`; return result |
| Other | Return null, with no dependency calls |

The locked routes capture object/lock addresses before acquiring. They do not
reload them after any dependency. Null allocation results still release the lock
and return null. Object-address arithmetic wraps as original u32 addition. The
fixed-object source preserves observed r2/r3 marshalling without asserting that
those arguments are consumed by the lower implementation.

The original occupies `[0x002B26F0,0x002B285C)`, containing 85 ARM instructions
and six jump-table words at `[0x002B2724,0x002B273C)`. The table targets are
`0x002B273C`, `0x002B2744`, `0x002B2758`, `0x002B274C`, `0x002B2754`, and
`0x002B2754`. The following three literals are `0x00465170`, `0x004E4100`, and
`0x004E411C`. The checker verifies these words against the hash-bound image.

Read-only Ghidra inspection is retained in
`local/validation/allocate-raw-20261007-inspect/exports/`. It includes the router,
both lower allocators, aligned caller `0x002C5544`, and callers `0x002BF7EC` and
`0x002C34F8`. Independent GNU disassembly in the direct run agrees with the saved
Ghidra instructions, call targets and raw literal words. The latter two callers
remain unrecovered. Inspection of `0x002C3A98` shows a six-word interface and
does not recover its implementation; decompiler return-type guesses are not used
as evidence over the original register dataflow.

## Direct build and comparison

From `SMT4-decomp`, use fresh ignored output directories and sequential Ghidra
jobs on the authoritative saved project:

```powershell
python tools/check_resource_allocate_raw.py --output local/validation/NEW-DIRECT
python tools/check_resource_allocate_raw.py --mutant reload-lock --output local/validation/NEW-NEGATIVE
python tools/check_resource_allocate_lower.py --output local/validation/NEW-LOWER-REGRESSION
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --output local/validation/NEW-RETAINED-REGRESSION
python -m unittest discover -s tests -v
```

Successful direct marker:
`local/validation/allocate-raw-20261007-direct-final/COMPLETE.json`.
The pinned GCC build yields **292 bytes: 268 bytes of `.text` (including
literals) and 24 bytes of `.rodata`**. The driver includes both sections in the
comparison image; instruction execution is restricted to `.text`. The rebuilt
path executes no original code. The linker resolves explicit lower boundaries,
not an implicit original helper implementation.

| Check | Result |
| --- | ---: |
| Original/rebuilt/independent-oracle cases | 8,824 |
| Zero-size cases | 1,950 |
| Locked-route cases | 1,189 |
| Fixed-object-route cases | 1,190 |
| Nonzero unsupported-selector cases | 4,495 |
| Null results on allocation routes | 390 |
| Signed alignment values | All 10 |
| Original instruction addresses visited | All 85 |
| Dependency calls checked across both paths | 9,514 |
| Maximum instructions per invocation | 46 |

The deterministic grid has 7,800 cases spanning selector neighbors/high-bit
lookalikes, all six table entries/defaults, full-width direction words, size
zero/one/high-bit/max, two dependency-effect profiles, and varied base/result
words. Another 1,024 seeded random cases probe full-width arguments. The oracle
uses an exact-key alignment table and separately computes lock as heap plus 88.
Each path is checked against the oracle as well as against the other's call trace.

Dependencies clobber volatile integer/VFP registers and flags. An adversarial
profile changes the global base after every dependency; saved heap/lock addresses
must still be used. Checks cover argument registers, both zero stack words,
8-byte dependency stack alignment, global-read counts, return preservation,
callee-saved registers, d8, stack restoration, caller stack, state/stack guards,
and unexpected reads/writes. All router writes must be inside its stack frame.
Visited instruction addresses do not prove every possible predication outcome.

The first run, `local/validation/allocate-raw-20261007-direct/`, failed at a
rebuilt lookup-table read: the copied driver extracted only `.text`, while GCC
emitted the table in `.rodata`. It has no COMPLETE marker. The final driver
includes that data and records both image and text extents. No recovered-source
behavior was changed to accommodate this harness packaging issue.

## Negative checks and regressions

Nine independently built mutants are rejected: `zero-size`, `alignment-101`,
`alignment-default`, `direction-byte`, `heap-offset`, `sixth-word`, `reload-lock`,
`fixed-object`, and `selector-mask`. They test early return, exact table/default
mapping, full-width direction comparison, heap addressing, sixth-argument zero,
captured-lock behavior, fixed-object choice, and exact route selectors. Each
build succeeds and fails a corpus assertion; compilation errors are not counted.
Mutated sources remain local and production source stays unchanged. Markers:
`local/validation/allocate-raw-20261007-negative-*/NEGATIVE.json`.

The direct aligned-allocation regression is
`local/validation/allocate-raw-20261007-lower-regression/COMPLETE.json`;
the retained registration/selector/conversion/allocation regression is
`local/validation/allocate-raw-20261007-retained-regression/COMPLETE.json`.
Both retain their modeled raw-router boundary and match the previous binary
hashes and complete comparison objects. All **50 public tests** pass; command
and result are in `local/validation/allocate-raw-20261007-public-tests.json`.
The local `allocate-raw-20261007-package.json` under `local/validation/` indexes
the positive and negative markers and records hash/regression checks.

## Limits and next package

`0x002C3A98`, `0x00144978`, and recursive locks `0x002C3AFC` / `0x002C3A78`
remain explicit models. Opaque bases and return values include null, unaligned,
high-bit and wrapping probes; these establish argument arithmetic, not usable
heap storage. No raw heap layout, capacity, allocation algorithm, concurrency,
OS behavior, full ABI/compiler identity, binary matching or native gameplay is
established. Live G1/G2 checks remain deferred and unpassed.

## Retained-worker integration (2026-10-07)

`--recover-raw-allocation` requires recovered allocation, conversion, selector
and registration. It links the existing faithful router source and executes its
original/rebuilt instructions inside `executeAllocation`; there is no synthetic
return at the router boundary. The six-word lower allocator `0x002C3A98`
returns the retained raw fixture. The separate raw-state region begins at
`0x00465170`, adjacent to the outer-state guard ending at that address.

The retained constructors supply first/second selectors `0x100`, nonzero rounded
sizes, and their original fifth argument. This mode checks the resulting heap
`base+0x1C`, signed alignment, three zero words, and acquire/allocation/release
order. The router's object lock `base+0x74` is checked separately from the two
enclosing allocator locks. Lower models alter the raw base after each call,
requiring captured heap/lock addresses, and alter the outer lock handle,
requiring its later reloads. Bases include a high wrapping value. These deliberate
effects test dataflow; they do not establish concurrent heap behavior.

Category/tracked-node setup and raw-address selection remain lower-call fixtures.
Registration performs the actual tag/account/list stores, followed by constructor
payload initialization, submission, worker completion, conversion, cleanup and
freed-address reuse. Checks retain all 32 raw residues, three list-removal
topologies, empty final accounting, memory guards and lifetime checks. The nested
router checks its single state read, stack-only writes, caller stack, callee-saved
registers and raw return value. Dependency models clobber volatile integer
registers and flags through the existing retained-harness boundary.

Marker: `local/validation/allocate-raw-integrated-20261007-final/COMPLETE.json`.
The linked image is **3,760 bytes**, including **3,736 text bytes and 24 read-only
data bytes**, SHA-256
`db28f2ade2a83722c13e9df9e1dc7248493b9e6c98f4ce6a1c6819a66f70cf17`.
The driver extracts both sections and confines instruction execution to text.
The rebuilt path executes no original instructions.

| Check | Result across both paths unless noted |
| --- | ---: |
| Retained scenarios | 324 |
| Raw routing / lower allocation executions | 5,184 each |
| Router object-lock calls | 10,368 |
| Allocation / registration / conversion executions | 5,184 each |
| Selector executions | 13,824 |
| Reused payload allocations | 2,592 |
| Submissions / completions | 2,592 each |
| Traversals / node visits | 3,888 / 9,072 |
| Original instruction addresses | 828 |
| Original router addresses on the constructor route | 44 |
| Maximum instructions per worker invocation | 10,185 |

All 44 router addresses expected for this route are checked as an exact set.
Other routes, null results and alignment selectors remain covered by the direct
corpus; this integration does not broaden its constructor input domain.
Instruction visitation does not establish every predication outcome. The ten
release-routing addresses omitted by the selector fixture remain outside this
mode and are covered by older modes.

The first integration run failed before allocation because the new raw-state
fixture's leading guard overlapped the existing outer-state guard. It remains
at `local/validation/allocate-raw-integrated-20261007-first/` without COMPLETE.
The corrected region is disjoint; no recovered source was changed for this fix.

From `SMT4-decomp`, use fresh output directories:

```powershell
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --recover-raw-allocation --output local/validation/NEW-RAW-INTEGRATED
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --recover-raw-allocation --mutant raw-reload-lock --output local/validation/NEW-RAW-NEGATIVE
python tools/check_resource_allocate_raw.py --output local/validation/NEW-RAW-DIRECT
python -m unittest discover -s tests -v
```

### Integration mutation checks and regression records

All four integrated mutants compile and fail a corpus assertion:
`raw-heap-route`, `raw-alignment` and `raw-sixth-word` fail the six-argument
check; `raw-reload-lock` fails the captured object-lock check. Their local
markers are `local/validation/allocate-raw-integrated-20261007-negative-*/NEGATIVE.json`.
The source mutations remain confined to each ignored output directory.

The single-batch corpus also passes at
`local/validation/allocate-raw-integrated-20261007-single-batch/COMPLETE.json`:
324 scenarios, 2,592 router/lower calls, 5,184 router lock calls, 6,912 selectors,
the same binary and 828 original addresses. This mode makes no address-reuse
claim. Four CLI combinations missing required recovered modes are rejected
before output creation; see `local/validation/allocate-raw-integrated-20261007-options.json`.

All five earlier retained modes and the direct router pass with identical
binary hashes and complete comparison objects to their previous records:

| Regression | Marker below `local/validation/allocate-raw-integrated-20261007-` | Previous directory below `local/validation/` |
| --- | --- | --- |
| Base retained reuse | `reuse-regression/COMPLETE.json` | `registry-reuse-20261007-final` |
| Recovered allocation | `allocation-regression/COMPLETE.json` | `allocate-register-20261007-allocation-regression` |
| Recovered conversion | `conversion-regression/COMPLETE.json` | `heap-index-20261007-conversion-regression` |
| Recovered selector | `selector-regression/COMPLETE.json` | `allocate-register-20261007-selector-regression` |
| Recovered registration | `registration-regression/COMPLETE.json` | `allocate-raw-20261007-retained-regression` |
| Direct router | `direct-regression/COMPLETE.json` | `allocate-raw-20261007-direct-final` |

The direct `sixth-word` mutant is also rejected again at
`local/validation/allocate-raw-integrated-20261007-direct-negative-sixth-word/NEGATIVE.json`.
This rerun complements the nine direct mutants retained from the preceding
package; it does not claim those other eight were rerun here.
All **50 public tests** pass. Commands/results are recorded in
`local/validation/allocate-raw-integrated-20261007-checks.json` and
`local/validation/allocate-raw-integrated-20261007-public-tests.json`.
The local `allocate-raw-integrated-20261007-package.json` indexes eight positive
manifests, five negative markers, source/tool/binary hash checks, regression
equality and documentation-link checks. All Ghidra jobs ran sequentially and
finished.

## Next bounded recovery

Recover the six-word heap-allocation wrapper **`0x002C3A98`** directly before
another retained integration. Existing read-only inspection is in
`local/validation/allocate-raw-20261007-inspect/exports/`; independently verify
instructions `[0x002C3A98,0x002C3AFC)` and callers. The observed wrapper calls
`0x00146CE0`, `0x00146CF0`, `0x00146D10` with heap subobject `+0x18` and its
last three arguments, then `0x00146AD8` with size/alignment. It conditionally
increments the word at `heap+0x54` for a nonzero allocation and preserves r0 as
the return. The decompiler's void-return guess is not the instruction contract.
Keep all four dependencies explicit models initially; test argument order,
null/nonzero returns, post-call counter reload, wrapping increment, stack and
guards. Do not infer a complete heap algorithm from this wrapper. Optional
retained integration is a later package; `0x00144978`, recursive locks and live
gates remain deferred.
