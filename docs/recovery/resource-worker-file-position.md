# Worker lower size/cache, seek and position

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored recovery in
[`resource_worker_file_position.c`](../../src/resource_worker_file_position.c)
adds **three bounded entry contracts**, reaching **59 entries plus two adapted
worker regions**. No external implementation was reused. Header declarations,
the new comparison mode and two optional harness hooks are integration/support,
not additional recovered game contracts.

The subsequent [read-loop package](resource-worker-file-read.md) executes
`0x002BB864` through `--recover-file-read`, retaining an explicit OS read model.
The later [size-service package](resource-worker-file-size-service.md) executes
size dispatch/method/accessor/IPC through these cache/seek callers in a separate
checker, retaining TLS/SVC and diagnostic models. This report's original mode
and fixture domain are unchanged.

## Strategic review and acceptance

Its binary and unchanged manifest
inputs were verified in
`local/validation/worker-position-20261008-audit/handoff-check.json`; the two
files already edited for this package are explicitly excluded from that check.
The original inner allocation target is complete. G1/G2 live gates and G3 ABI/provenance/transfer gates retain their open status.

Acceptance declared before implementation: verify the independent position tail
entry and shared five-word layout; recover size success/failure cache/output
effects, 64-bit relative addition, signed bounds, equality refresh and exact
errors; build warning-clean ARM source; compare direct and connected state
effects; reject relevant compiled faults and preserve older modes. OS size and
diagnostics remain explicit models. The package meets this bounded acceptance.

## Original contracts

All addresses below are original ARM virtual addresses. Independent GNU
disassembly is saved with the final comparison; `original-position-ghidra.txt`
cross-checks all **104 instructions** and both error literals. The saved Ghidra
function at `0x002ACA78` includes `[0x00146458,0x001464F4)` as a noncontiguous
body range. The dispatcher's restored-frame tail branch at `0x002ACB18`, helper
prologue, epilogues and separate literal establish the independently callable
position boundary without changing the saved database.

At the lower receiver (worker object+4), the five words are:

| Offset | Meaning |
| --- | --- |
| +0 | Handle with low-bit tag; OS size receives `handle & ~1` |
| +4 / +8 | Cursor low / high words |
| +12 / +16 | Cached size low / high words |

The original fields require word alignment, not an eight-byte-aligned C struct
member. Source reads/writes the pairs as words. The comparison domain uses valid
mapped five-word storage and a separate aligned eight-byte size output; null,
faulting, overlapping or concurrently observed objects are not established.

| Entry / exclusive end | Contract |
| --- | --- |
| `0x002BB8EC` / `0x002BB944` (22 instructions) | Queries OS size `0x002A8914` into local output. Nonnegative status copies both words to cache and caller output. Negative status clears both cache words and leaves caller output untouched. Cursor/handle are unchanged; returns exact service status, including positive nonzero statuses. |
| `0x002ACA78` / `0x002ACB24` (43 instructions) | Origin 0 validates absolute offset; 1 adds current cursor; 2 always queries size, updates/clears cache, then adds size if successful. Addition wraps modulo 2^64. Unknown origin returns `0xE0E046BD` without state changes or OS calls. Successful dispatch tails to position validation; an end-query failure returns its exact status. The r1 forwarding/alignment word is not consumed. |
| `0x00146458` / `0x001464F4` (39 instructions) | Rejects negative signed 64-bit position with `0xE0E046C1`. A position strictly below signed cached size is accepted without a query. Equality or greater triggers refresh; failure clears cache, preserves cursor and returns service status. Successful refreshed size must be signed-greater-or-equal to position, otherwise returns `0xE0E046C1`. Acceptance stores both cursor words and returns zero. |

Signed comparisons follow original `SUBS/SBCS` with signed branches; source uses
a sign-bit bias in unsigned comparisons to avoid C signed overflow. Relative
addition also uses unsigned arithmetic. A successful query that supplies a
high-bit-set size is still cached as supplied; signed bounds can subsequently
reject it. Those are controlled interface/state probes, not observed huge files.

End-relative seek can make **two queries**: the first computes its target and
sets cache, then equality or growth triggers the helper's second query. The
second size/status can differ. A stale positive cache can accept a position
without observing a newer OS size. A failed bounds check after successful query
retains the newly refreshed cache while preserving cursor. Negative absolute
positions and invalid origins do not clear cache.

## Build and controlled comparison

Primary evidence:
`local/validation/worker-position-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K build is **1,628 bytes**, with **540
new source bytes** (68 size/cache, 180 position, 292 seek including inlined cache
refresh). No original code executes on the rebuilt path. This is GCC behavior
evidence; binary matching and a complete original-target build remain unclaimed.

| Check | Result |
| --- | ---: |
| Connected original/rebuilt/oracle allocation/I/O cases | 2,304 |
| New direct lower/adapter state cases, including sequence steps | 3,312 |
| Persistent cache/cursor sequences | 4 |
| Retained isolated adapter probes / object-allocation probes | 210 / 48 |
| New original instruction addresses visited | 104 / 104 |
| Total original instruction addresses visited | 397 |
| Executed connected size/seek chains, both paths | 9,216 |
| Modeled OS size calls, both paths | 9,508 |
| Maximum instructions in a lower/adapter invocation | 76 |

`--recover-file-position` implies `--recover-file-methods` and allocation
recovery. The connected corpus retains the existing path, flag, allocation,
metadata, read-count, close, descriptor and destructor checks. Size/cache now
mutates the object and real seek validates it; a new optional final-object oracle
supplies the independently predicted cursor/cache words. The default hook does
nothing, preserving all earlier modes. Synthetic vtables select real original
or rebuilt adapters, and original construction/vtable identities remain checked.

Connected size outputs retain bounded low words (0, 1, 68, 69, 127, 128, 129,
801); high words alternate zero, one and differing high-bit patterns. The worker
consumes the low word. Seeks to zero exercise cache hits and refreshes with both
signs of OS status. Only successful initial size calls proceed through the worker;
negative initial size is checked directly up to diagnostic entry.

The direct corpus crosses zero, one, low-word carry, `2^32`, signed maximum,
signed minimum and all-ones offsets/cursors; contrasting cache pairs; absolute,
current, end and invalid origins; positive zero/nonzero/max statuses and two
negative statuses. Size queries start with nonzero low/high cache patterns.
Service failure alternates leaving its local output untouched and writing poison;
neither permits failure output to escape to the caller. Second end-relative
responses differ from the first and cover shrinkage and failure. Handle fixtures
include zero, low-bit-only, high-bit and all-ones patterns.

The four persistent sequences retain object memory across calls: size refresh,
cache hit, equality refresh, failed refresh, recovery, end-relative one/two-query
paths and invalid-origin preservation, starting from contrasting cursors. Each
call checks complete guarded object/output bytes, OS call count/order and
pre-call object snapshots, handle untagging, exact status, adapter diagnostics,
stack guards/restoration and callee-saved registers. OS models poison volatile
registers/flags. A separate signed Java-long oracle predicts arithmetic/state;
original/rebuilt traces must also agree. Coverage is bounded and instruction
visitation does not establish every possible predication or concurrent behavior.

The retained 210 isolated adapter probes deliberately still intercept lower
calls, using an optional relocation hook for the compiled lower entries. Their
existing counters (`method_returns`, `terminal_size_failures`, `diagnostic_calls`)
retain that narrower scope plus the connected read adapter; new chain diagnostic
checks are asserted in the position runner. They must not be read as all new
diagnostic totals. New direct size-adapter failures stop at diagnostic entry;
new seek diagnostics are modeled returning, preserving the previous boundary.

## Validation, models removed and limits

The audit index is
`local/validation/worker-position-20261008-audit/COMPLETE.json`.
Six compiled faults are rejected: failure cache corruption, skipping equality
refresh, unsigned bounds comparison, lost relative carry/high word, wrong origin
error and failure output overwrite. Detailed markers and rejection causes are
under `local/validation/worker-position-20261008-negative-*/`.
The file-method, allocation and legacy regressions preserve their entire previous
comparison objects and 1,088/956/548-byte binaries. All **134 public tests pass**;
the audit records their actual output and exact artifact comparisons.

The first development run stopped at a Java static-context compile error. The
second exposed an uninitialized harness output-guard region before behavioral
comparison. Both harness issues were fixed. The third passed; the final run
added nonzero size-query cache seeds and retained the same compiled binary. No
failed development run is acceptance evidence. All Ghidra jobs were sequential,
read-only on the saved project; all launched validation jobs finished.

Only the new mode replaces the lower **size/cache and seek/position** models.
OS size `0x002A8914`, read loop `0x002BB864`, diagnostic `0x002BBD70` and its
delivery tail `0x002AD7E8` remain modeled. Old optional modes retain their stated
boundaries. Raw allocation/storage, registration, zeroing, recursive locks,
path conversion, file open/preclose/close, destruction and ownership also remain
explicit models here. This does not establish asynchronous cursor/cache access,
OS result validity, post-diagnostic size return after unwritten output, complete
file lifetimes or live gameplay. No native service replacement is implemented.

## Reproduce and next independent milestone

From `SMT4-decomp`, use fresh output directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-file-position --output local/validation/NEW-POSITION
python tools/check_resource_worker_io.py --recover-file-position --mutant position-equality --output local/validation/NEW-POSITION-NEGATIVE
python tools/check_resource_worker_io.py --recover-file-methods --output local/validation/NEW-METHODS-REGRESSION
python tools/check_resource_worker_io.py --recover-allocation --output local/validation/NEW-ALLOCATION-REGRESSION
python tools/check_resource_worker_io.py --output local/validation/NEW-IO-REGRESSION
python -m unittest discover -s tests
```

Next recover **read loop `0x002BB864`**, extent `[0x002BB864,0x002BB8EC)`, and
integrate through the recovered read adapter `0x00354F9C` and position mode,
keeping OS read `0x002A4E54` modeled. Static starting evidence is the audit's
`next-read-disassembly.log` and `next-read.c`. Instructions confirm zero-byte
success, partial/zero/full-read termination, status failure without caller count
write, cursor advancement retained from earlier successful iterations, buffer
advance and remaining-count subtraction. At `0x002BB8BC`, `ADC` uses the returned
count **arithmetic-shifted by 31**: cursor advancement sign-extends the 32-bit
count rather than blindly zero-extending it. Verify this in bounded synthetic
direct cases alongside ordinary payload/partial-read scenarios. Query actual
service signatures from the stack arguments; do not infer real OS behavior from
the current read model. Do not reopen completed adapters/allocators or optional
extraction work. Live gates remain deferred.
