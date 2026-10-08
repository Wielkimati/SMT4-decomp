# Worker prefix lookup and file open

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored recovery in
[`resource_worker_file_open.c`](../../src/resource_worker_file_open.c) adds
**three bounded entry contracts**, reaching **63 entries plus two adapted worker
regions**. No external implementation was reused. The header, optional comparison
mode and fixture hooks are supporting integration, not additional recovered code.

## Strategic review and acceptance

Before edits, all 22 manifest input files and the preceding
compiled binary were verified in
`local/validation/worker-open-20261008-audit/handoff-check.json`.
This package
follows A07 by removing another game-code dependency actually reached by the
worker. Optional extraction and compiler research do not block it. G1/G2 live
and G3 ABI/provenance/transfer gates remain open; no port implementation is added.

Acceptance declared before implementation: instruction-backed prefix packing,
bounded first-match lookup and UTF-16 suffix length; exact type-4 descriptor,
status and conditional handle publication; a warning-clean ARM build; direct
boundary and negative comparisons plus connected worker execution; fault rejection
and preserved older regressions. Backend virtual open remains explicitly modeled.

## Original contracts

| Entry | Mode and exclusive end | Recovered behavior |
| --- | --- | --- |
| `0x002B5CA0` | ARM, `0x002B5D68` | Prefix key packing and registry lookup |
| `0x002B5C8C` | Thumb, `0x002B5C9E` | Zero-terminated UTF-16 code-unit count |
| `0x002BB944` | ARM, `0x002BB9D4` | Resolve backend, construct suffix descriptor and dispatch open |

The prefix table literal at `0x002B5D68` is `0x004D43E0`. It names 32 records
with 16-byte stride: key low/high at +0/+4, returned backend address at +8,
and an unused word at +12. This package does not recover registry initialization.

The resolver examines at most eight UTF-16 units. Only the complete unit `0x003A`
terminates prefix packing; **NUL does not terminate this scan**. Consequently a
valid prefix has at most seven units before its colon. For each preceding unit,
the original sign-extends its low byte and ORs that signed value into the shifted
64-bit key. This is not unsigned byte concatenation. High unit bytes otherwise
do not affect the key, but `0x013A` is not a delimiter. Source uses explicit
unsigned word shifts and masks to preserve this behavior without signed overflow.

No colon among the eight units, or a zero packed key, returns zero without
lookup. Otherwise all 32 records are eligible, in order; the first matching
key supplies its +8 value, even when that value is null and a later duplicate
is nonnull. The original searches in pairs; the source's ordered loop has the
same result within stable, readable table storage. Concurrent updates, volatile
read ordering and faulting records are outside the compared domain.

The Thumb length routine counts 16-bit units until a zero unit. It does not
decode Unicode scalars or combine surrogate pairs. Original open calls it with
`BLX`, and it returns to ARM through `BX LR`. The standalone rebuilt routine
uses ARM instructions; this is behavioral reconstruction, not binary matching.

Open takes `(handle_out, path, mode)`. If lookup returns zero, it returns exactly
`0xC8804465` and leaves the caller's handle unchanged. Otherwise it scans again
to the first literal colon and builds three words on the stack: **type 4,
suffix pointer, `(suffix_units + 1) * 2` bytes**. The terminator is included.
It invokes backend vtable slot +0 with receiver in r0, local handle output in r1,
descriptor pointer in r2 and the unchanged mode in r3. The service call is
eight-byte stack aligned; descriptor and local output are distinct word-aligned
storage. Nonnegative statuses, including positive nonzero values, publish the
service's local handle. Negative statuses preserve the caller output, even when
the backend wrote its local output. The exact service status is returned.
The saved decompiler labels open's return `void`; the error literal, unchanged
r0 on return and controlled comparisons establish the recovered status contract.

The 95 original instructions are checked against saved Ghidra extents and
independent GNU disassembly. **94 execute** in the corpus. The unvisited
`0x002B5D4C` branch requires the address of a matching record to be zero;
the pinned nonzero table and indices 0..31 cannot produce that address. It is
not a missed supported input branch. Predicated-instruction visitation is not
an exhaustive path proof.

## Build and controlled comparison

Primary evidence: `local/validation/worker-open-20261008-final/COMPLETE.json`.
The freestanding C11 ARMv6K build is warning-clean and **2,152 bytes**, adding
**388 compiled source bytes**: length 48, resolver 156 and open 184. GCC inlines
length into open while retaining the separately tested exported length entry.
No original application helper runs on the rebuilt path. This is not a rebuilt
3DS application or a matching binary.

| Comparison | Result |
| --- | ---: |
| Connected original/rebuilt/oracle worker cases | 2,304 |
| Direct open cases | 362 |
| Direct prefix cases | 442 |
| Standalone original Thumb / rebuilt ARM length cases | 7 |
| Retained direct read / position cases | 724 / 3,312 |
| Retained read / position persistent sequences | 2 / 4 |
| Retained isolated adapter / object-allocation cases | 210 / 48 |
| New original instruction addresses visited | 94 / 95 |
| Total original addresses visited | 525 |
| Connected open calls, both paths | 4,608 |
| Modeled backend open calls, both paths | 2,624 |
| Maximum new routine instructions per direct invocation | 2,562 |

The `--recover-file-open` mode implies read, position, methods and allocation
recovery. Its new machine executes original/rebuilt open, resolver and length;
only backend vtable +0 is intercepted. The conversion model now emits `r:` when
at least two units convert successfully, with the retained synthetic suffix
thereafter. Empty/one-unit/early-failed conversions exercise lookup failure.
The table fixture rotates through all slots. A backend failure or lookup miss
preserves the worker's reset zero handle; the connected oracle therefore uses
zero for later read/close arguments. Supplied backend statuses remain in the
input rows; effective lookup failures are `0xC8804465`. The worker still proceeds
through size, seek, allocation and read after failed open. Success returns all
six retained handle patterns. Conversion, service and ownership models remain
explicit; older modes retain their exact fixtures.

Direct probes include empty, seven- and eight-unit, absent-colon, zero-key,
embedded-NUL, signed-low-byte and non-ASCII-delimiter prefixes. They cover every
table position, adjacent duplicates, null-first duplicates, misses and an
otherwise matching eight-unit key that must still be rejected. Suffix lengths
are 0, 1, 7 and 260; standalone length probes cover 0, 1, 2, 7, 127, 260 and 511
units, including nonzero units with zero low bytes and surrogate code units.
Modes and successful handles include zero, sign-bit and all-ones words; statuses
include zero, one, signed maximum, signed minimum and all ones. Negative services
alternate untouched local output and written poison.

The Java oracle uses a single signed-byte/64-bit shift expression, independently
of the C word-pair implementation. Each call compares exact return/output,
backend arguments/order, full guarded table/backend/path bytes, output guards,
stack restoration and callee-saved registers. Models clobber volatile registers
and flags. The direct source domain requires up to eight readable prefix units,
a terminated suffix on successful lookup, valid initialized backend/vtable
storage and successful backend output initialization. Aliasing, invalid memory,
concurrency, backend reentrancy, unbounded suffixes and real filesystem side
effects are not established. Backend targets in this corpus are modeled ARM
entries; original ARM/Thumb length interworking executes directly.

## Validation audit

Audit index: `local/validation/worker-open-20261008-audit/COMPLETE.json`.
All six compiled faults are rejected at semantic assertions, with source/binary
identities and exact rejection messages in `negative-checks.json`:

| Fault | Rejection |
| --- | --- |
| `prefix-sign` | Exact resolver result |
| `prefix-limit` | Unexpected backend invocation for an eight-unit prefix |
| `prefix-last` | Missing backend call for final-slot match |
| `open-length` | Type-4 suffix pointer/byte length |
| `open-status` | Conditional handle write on positive success |
| `open-preserve` | Conditional handle write on negative failure |

The read, position, method, allocation and legacy regressions retain **identical
complete comparison objects and binaries** (1,764 / 1,628 / 1,088 / 956 / 548
bytes), verified in `regressions.json`. All **134 public tests pass**, with the
actual output in `public-tests.log`. The first test invocation's PowerShell
stderr redirection produced an ambiguous shell exit despite unittest reporting
OK; a subprocess capture rerun confirmed exit zero. Commands, actual exit codes
and durations are recorded in `validation-jobs.json`. Ghidra jobs ran sequentially
on the saved project read-only. No source/build validation job remains detached.

The initial development run exposed a fixture return bug: open had already
returned, but the inherited external-call completion reused its clobbered LR.
The new hook now saves/restores the caller return address for that completion.
No recovered source changed for this fix. The next run passed; the final run
additionally compares the standalone Thumb entry and a matching overlong key.
All source assertions and old-mode checks are retained.

## Models removed and remaining limits

This new mode removes open `0x002BB944` from the connected worker model and
executes its recovered prefix and length dependencies. Direct probes execute
all three contracts. Earlier modes still intercept open, and earlier isolated
adapter probes retain their lower-call models. Inherited manifest flags describe
those historical scopes; new `open_prefix_length_recovered` and
`backend_virtual_open_modeled` fields describe the new chain.

Backend virtual open, OS read/size, diagnostic delivery, prefix-table construction,
raw storage/registration, clearing, recursive locks, path conversion, close and
destruction remain modeled or unrecovered in this mode. The new registry table
and backend objects are synthetic. No complete file/backend lifetime, native
service implementation, original compiler/full ABI or live gameplay is claimed.

## Reproduce and next independent milestone

Continuation: the subsequent [cleanup package](resource-worker-file-cleanup.md)
has validated the cleanup/destruction group below. Its new mode retains backend
close/resource-release models and separates diagnostic stops from conditional
returning continuations. The historical next-task findings below
remain the evidence that selected cleanup.

Run from `SMT4-decomp`, with fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-file-open --output local/validation/NEW-OPEN
python tools/check_resource_worker_io.py --recover-file-open --mutant prefix-limit --output local/validation/NEW-OPEN-NEGATIVE
python tools/check_resource_worker_io.py --recover-file-read --output local/validation/NEW-READ-REGRESSION
python -m unittest discover -s tests
```

Next recover the **file-object cleanup/destruction chain**: base cleanup
`0x002BB81C` / shared body `0x002BB824`, deleting destructor `0x00354FA4`, null-safe
object release wrapper `0x002B2580`, and backend close dispatcher `0x002B9450`.
The pinned worker vtable `0x004208B0` slot +4 points at `0x00354FA4`. That routine
calls `0x002BB824` then tails to `0x002B2580`, which conditionally tails to the
already recovered release router `0x002C43B4`. Close `0x002B9450` dispatches a
nonnull backend's vtable slot +0x2C. These directly remove existing worker
destructor/close boundaries; do not repeat completed allocation or open work.

Starting static evidence is the audit's `next-*-disassembly.log`,
`next-cleanup-ghidra.txt` and `next-function-*.c`. The read-only inspection verifies
saved bodies `[0x002BB824,0x002BB85C)`, `[0x00354FA4,0x00354FB8)`,
`[0x002B9450,0x002B9468)` and `[0x002B2580,0x002B2590)`. There is **no saved
function at `0x002BB81C`**: GNU decoding shows a two-instruction prefix falling
into `0x002BB824`; validate that entry explicitly during recovery. The first
inspection stopped on this missing function object; the second records the
absence and exports the other saved functions without changing the database.
These are static next-task findings, not additional recovered source.
Use valid
synthetic backend handles and retain explicit backend close, allocator release
and diagnostic boundaries as needed. Compare null/tag-only/untagged/tagged
handles, reload after diagnostic effects, clearing only after close, object return,
destructor order and null release. `0x002BCE9C` zeros r0 and tails to `0x002AD90C`;
the latter clears an optional callback then tails to `0x001526B4`. Thus the old
"preclose" name/model is not evidence of a real flush or returning cleanup
operation. Determine its termination boundary before extending tagged-path
claims; keep any returning diagnostic model explicit. Live gates remain deferred.
