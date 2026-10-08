# Worker file cleanup and destruction

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored reconstruction in
[`resource_worker_file_cleanup.c`](../../src/resource_worker_file_cleanup.c).
No external implementation was reused. Four routines and an alternate shared
entry are represented by five exported C contracts. Headers, comparison hooks
and fixture changes support this recovery; they are not additional game code.

## Strategic review and acceptance

The completed open/path milestone was verified against all 25 manifest input
identities and its compiled binary before edits, recorded in
`local/validation/worker-cleanup-20261008-audit/handoff-check.json`.
This follows
A07's source/comparison criterion and removes actual worker call boundaries.
G1/G2 live and G3
ABI/provenance/transfer gates remain open, with no port implementation.

Acceptance declared before implementation: recover conditional close, handle
reload/clearing, object return, null dispatch and destructor/release ordering;
build warning-clean ARM source; compare guarded direct and connected cases;
reject semantic faults and preserve prior-mode regressions. Determine the tagged
diagnostic boundary before claiming continuation. Backend virtual close and
resource release remain explicit external models.

## Original contracts

| Entry | ARM exclusive end | Contract |
| --- | --- | --- |
| `0x002BB81C` | prefix ends `0x002BB824` | Clear scratch r1, fall into shared cleanup; return original object |
| `0x002BB824` | `0x002BB85C` | Conditional cleanup of object handle at +4; incoming r1 is dead |
| `0x00354FA4` | `0x00354FB8` | Shared cleanup, then tail to null-safe object release |
| `0x002B2580` | `0x002B2590` | Forward nonnull object to `0x002C43B4`; null is a no-op |
| `0x002B9450` | `0x002B9468` | Dispatch nonnull backend receiver through vtable +0x2C; null is a no-op |

Cleanup requires a valid object. It leaves handle words 0 and 1 unchanged.
If any bits except bit zero are set, an odd handle first calls `0x002BCE9C`.
After that call, it **reloads** object +4, clears bit zero from the reloaded
value, calls close, and only after close returns stores zero at object +4.
It returns the original object pointer, regardless of dependency scratch r0.
The destructor passes that returned pointer to `0x002B2580`. There is no
vtable rewrite or access to other object words in these original routines.
The worker's real vtable `0x004208B0` slot +4 names `0x00354FA4`.

Close does not strip a tag itself: its caller must provide a valid backend
address, or zero. The backend object's first word is its vtable, and the target
is at +0x2C. Close and object release use void source contracts because the
recovered callers do not consume their scratch return registers. No status
normalization or allocator result contract is inferred.

The saved Ghidra project has no function object at `0x002BB81C`. Its prefix
encodings (`e3a01000`, `e1a00000`) are independently checked, decoded by GNU,
and executed directly in original/rebuilt probes. Other saved extents agree.
This does not modify the database or count an absent function object as proof.

## Tagged diagnostic boundary

The historical name `smt4_worker_file_preclose` remains for compatibility.
It denotes a diagnostic boundary, not an established flush service.
`0x002BCE9C` zeros r0 and tails into `0x002AD90C`, which reads callback
`0x0044E450`. If present, it clears the callback before invoking it, with zero
r0/r1/r2/r3 and first stack word; the second stack word forwards incoming r2.
It then tails to `0x001526B4` with r0/r1/r2 zero. That address contains
**`SVC 0x3C`**, followed by `BX LR`.

Two original-only controlled probes execute this chain with callback absent and
present, stopping **before the SVC**. The optional callback is modeled and
clobbers volatile registers. The SVC encoding and arguments are checked. This
establishes the service boundary, not its real termination/return behavior.
Six direct original/rebuilt cleanup pairs stop at diagnostic entry and verify
that no close, clear or release has occurred. Separate returning-model probes
deliberately exercise the continuation encoded after that call. Their results
are conditional on that model and do not establish real tagged-handle cleanup.
Older worker modes retain their historical returning diagnostic assumptions.

## Build and comparison

Primary evidence: `local/validation/worker-cleanup-20261008-final/COMPLETE.json`.
The comparison mode `--recover-file-cleanup` implies open/read/position/method/
allocation recovery. It replaces connected close and destructor interception
with executed source, while intercepting only backend vtable close and allocator
release `0x002C43B4` within the new chain. Earlier isolated direct adapter probes
and older modes retain their documented boundaries.

The connected corpus substitutes three valid synthetic backend objects for the
old opaque nonzero handle patterns. Both paths receive the same objects;
tag-only and null cases remain. Diagnostic replacement handles also name valid
objects. Conversion/open/read/allocation fixtures and existing state assertions
remain active. The outer worker closes and clears a nonzero handle before the
executed destructor, so this exercises no duplicate backend close and release
after cleanup. An existing backend-effect fixture clears the descriptor object,
causing the worker to skip destruction, as in the original region.

Direct probes separately exercise both cleanup entries, deleting destructor,
close dispatcher and null-safe release. They cover null/tag-only/untagged/tagged
handles; diagnostics replacing the handle by null, tag-only, another untagged
or tagged object; and backend close writing poison into the handle before
cleanup clears it. Release receives null, valid object, sign-bit and all-ones
words at its modeled boundary. Exact object bytes, guards, call predicates,
order, receiver/slot, returned object, stack alignment/restoration and saved
registers are checked. Service models clobber volatile registers and flags;
new access checks reject object reads/writes after release.

Bounded domain: valid readable 32-bit object/vtable storage, normal returning
backend/release models, and explicit diagnostic stop/return variants. Real
filesystem effects, resource release internals, concurrent mutation, invalid
memory, backend freeing the caller object, full ownership and live behavior
are not established. Direct backend targets are modeled ARM entries; this
package does not add a backend Thumb-interworking claim.

## Validation results

The warning-clean freestanding C11 ARMv6K build is **2,524 bytes**, adding
**372 compiled source bytes**: close 20, cleanup/shared entry 112 each, null
release 12, destructor 116. GCC inlines the shared body into both callers;
all five exported contracts are compared directly. This is behavioral recovery,
not a matching binary or reconstructed 3DS application.

| Comparison | Result |
| --- | ---: |
| Connected original/rebuilt/oracle worker cases | 2,304 |
| Direct cleanup/close/release cases | 68 |
| Direct terminal diagnostic paths, both implementations | 12 |
| Connected close dispatches, both implementations | 768 |
| Connected destructors, both implementations | 4,480 |
| Modeled backend close / resource release calls, both implementations | 846 / 4,522 |
| New original instructions visited | 31 / 31 |
| Total original addresses visited in recovered chain | 556 |
| Maximum instructions per direct new invocation | 27 |
| Original-only diagnostic-to-SVC probes | 2 |

Retained direct checks include 362 open, 442 prefix, seven UTF-16 length,
724 read, 3,312 position, 210 adapter and 48 object-allocation cases, plus
the two read and four position persistent sequences. The diagnostic-only
probes do not count as recovered source or as executed SVC behavior.

All six compiled semantic faults are rejected: `cleanup-reload` at the backend
call predicate, `cleanup-tag-only` at the diagnostic predicate,
`cleanup-clear` at exact object bytes, `cleanup-return` at the release receiver,
`close-slot` at the unexpected dispatch target, and `release-null` at the
release predicate. The first development run passed. The final run additionally
enforces no object instruction accesses after release and passed unchanged
source/binary behavior.

Audit index: `local/validation/worker-cleanup-20261008-audit/COMPLETE.json`.
`negative-checks.json` records exact fault source/binary hashes and rejection
messages. `regressions.json` verifies **identical complete comparison objects and
binaries** for open/read/position/method/allocation/legacy modes (2,152 / 1,764 /
1,628 / 1,088 / 956 / 548 bytes). **All 134 public tests pass**, with actual output
in `public-tests.log`; `validation-jobs.json` records commands, zero exit codes
and durations. `static-audit.json` verifies source sizes, primary manifest input
hashes and entry/SVC evidence. All Ghidra jobs ran sequentially, read-only on the
saved project; all started jobs finished.

## Reproduce and next independent milestone

Continuation: [path recovery](resource-worker-path.md) has now validated the
conversion/accessor package described below. Its connected mode uses bounded
byte-table paths; locale callbacks and initialization remain open. The historical
selection below records how the wrapper package was chosen.

Run from `SMT4-decomp`, using fresh directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-file-cleanup --output local/validation/NEW-CLEANUP
python tools/check_resource_worker_io.py --recover-file-cleanup --mutant cleanup-reload --output local/validation/NEW-CLEANUP-NEGATIVE
python tools/check_resource_worker_io.py --recover-file-open --output local/validation/NEW-OPEN-REGRESSION
python -m unittest discover -s tests
```

Next recover the worker's path-conversion dependencies: Thumb initial-state predicate
`0x002B9486`, measurement wrapper `0x002B9468`, conversion loop `0x002C63DC`,
and its evidenced byte decoder `0x001008C8`. Inspect the locale/state/error
accessors actually reached by that chain before selecting the bounded domain.
Keep locale callbacks, context and error storage explicit where not recovered. Recover
state and byte-count behavior with valid synthetic locale tables, then connect
real conversion to the worker's UTF-16 open path. This removes an existing
worker model; it does not require optional extraction or live gameplay.

Static continuation evidence is the audit's `next-path-ghidra.txt`,
`next-function-*.c` and `next-*-disassembly.log`. Saved Thumb extents are
`[0x002B9486,0x002B9498)`, `[0x002B9468,0x002B9486)`,
`[0x002C63DC,0x002C644C)` and `[0x001008C8,0x00100908)`.
The first routine tests null/state word zero and returns 1/0; it does not reset
state despite the historical fixture name. The conversion loop calls the byte
decoder and uses accessor `0x002C6936` for absent explicit state and `0x002C6894`
for error storage. The byte decoder obtains a locale-table pointer via
`0x002C6C94`, which calls `0x002C6C48` then adds four. The table selects a direct
byte path or a relative callback. These are static next-task findings only;
none of these conversion/locale routines is claimed recovered by this package.
