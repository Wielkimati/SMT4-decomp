# Concrete archive-backend ownership lifetime

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored behavioral source; descriptive names are not original symbols.
No external implementation was reused.

## Strategic review and acceptance

The prefix milestone is complete;
the old inner-allocation objective is also complete. The handoff's backend
lifetime task follows the actual vtable dependency at prefix removal's modeled
disposal call. It is the next useful independent milestone. Prior prefix
source/tool identities all matched before edits; see the audit's
`handoff-check.json`. No extraction, compiler investigation, live session or
port work is required for this target.

Acceptance declared before implementation: instruction-backed pool take,
factory, checked accessor, teardown, disposal and singleton registration;
guarded exact head/count and output effects; service failure versus exhaustion;
captured/reloaded service and handle values; close-before-clear-before-pool-return;
registration rollback/publication; persistent create/register/open/remove/reuse;
warning-clean ARM build, original/rebuilt comparisons, fault rejection and
retained regressions. OS services, locks, clear, diagnostics and startup storage
remain explicit boundaries. The completed package meets that bounded acceptance.

## Recovered source

`src/resource_worker_backend.c` and `.h` implement six original contracts:

| Original ARM body, end exclusive | Source contract |
| --- | --- |
| `[0x002B5D6C,0x002B5DD0)` | `smt4_worker_backend_pool_take` |
| `[0x003568C8,0x00356974)` | `smt4_worker_backend_create` |
| `[0x0023A004,0x0023A028)` | `smt4_worker_backend_service` |
| `[0x0035674C,0x003567A0)` | `smt4_worker_backend_teardown` |
| `[0x003562D0,0x0035631C)` | `smt4_worker_backend_dispose` |
| `[0x00354DEC,0x00354E60)` | `smt4_worker_backend_register` |

The first, second, third, fourth and sixth match saved Ghidra function extents.
Disposal has **no saved function object**. The original factory literal and
vtable `0x004209F8` slots +0x30/+0x34 bind disposal and teardown. GNU decoding
and a transient ARM decode in the read-only Ghidra job establish disposal's
tested body. `function-boundaries.txt`, `original-ghidra.txt` and the six
`original-smt4_worker_backend_*.log` files retain that distinction. The project
database was not modified.

Pool take locks the inline object at pool+0x30. A null +0x24 free head returns
null after unlocking, without count or clear changes. Otherwise it pops the
first node using node+0 as its next pointer and increments +0x2C modulo 32 bits.
If option bit 0 at +0x14 is set, it calls `0x00139F54` with the popped pointer,
pointer plus +0x18 element size modulo 32 bits, and zero. It unlocks and returns
the captured node, ignoring clear and lock return registers. Higher option bits
do not select clearing.

The factory calls archive-open `0x002ADBE8` with a local copy of global
`0x0044E650+0x10`, the supplied archive identifier and a type-1, one-byte path
descriptor. The descriptor's local data block contains its own 32-bit address
followed by word 1. Source preserves that construction; actual stack addresses
are relocated, not claimed identical. On a sign-bit service failure it returns
the exact status without writing the caller output. The negative service may
write its local handle output; those words are not consumed by the factory.

On nonnegative service return it captures the 64-bit handle and reloads the
global service word **before** pool take. A node from pool `0x004D431C` receives
vtable `0x004209F8`, captured service at +4 and handle low/high at +8/+12. The
caller receives the node and status zero, even if the service returned a positive
status. On exhaustion it publishes null, then reloads the global service word
again and calls archive-close `0x002ADBB8` with the acquired handle. Close's
result is ignored; the factory returns `0xD8604659`. Thus service-open failure
and allocation failure have different caller-output effects.

The checked accessor reads object+4. Zero enters diagnostic `0x002BBD70` with
status `0xE0A046DA` and original site `0x0023A020`; any returning continuation
reloads object+4. Normal diagnostic return is not established. Terminal probes
stop at entry; separate returning models may change the service and handle.

Teardown first installs the concrete vtable and captures both handle words.
It closes only when their OR is nonzero, using the checked accessor's result
and the captured handle even if a returning diagnostic changes object storage.
After close returns it clears both handle words. It always clears service +4
and returns the original receiver. Close failures do not suppress clearing.
Zero handle skips the accessor and service close entirely.

Disposal dispatches the receiver's **current** vtable +0x34 before locking the
concrete pool. It then stores the current pool head in receiver+0, publishes the
receiver as the free head, decrements +0x2C modulo 32 bits, and tail-unlocks.
It does not hardcode the teardown target or use its return value. An alternate
scripted +0x34 callback separately verifies this dispatch; normal connected
sequences execute recovered teardown.

Singleton registration checks global +8 first. A nonzero value returns
`0xC92044E7` without calling the factory. Otherwise it creates archive 4,
registers the caller's prefix with both flag bytes zero, and publishes the
object at global +8 only on nonnegative registration return. Registration
failure invokes the new object's vtable +0x30 and preserves the registration
status. Factory failure does not invoke registration/disposal. The original
r1/r2 and incoming r3 are not consumed as semantic parameters.

## Integration and models removed

The new dedicated `tools/check_resource_worker_backend.py` links backend,
existing prefix and existing open/resolver/UTF-16 source into one ARM image.
Persistent calls use the same emulator memory without reseeding objects, pool,
registry or global state between calls. Singleton creation constructs the real
backend, registration publishes it, open resolves it, removal executes concrete
disposal/teardown, and later creation reuses the returned node. Two sequences
each perform three full lifetimes, with and without optional clearing. A third
sequence checks that a close callback's replacement singleton survives removal's
post-disposal comparison.

This adds **six original contracts** and replaces the **backend-disposal model
on these connected prefix-removal paths**. The inherited backend file-open
virtual call remains modeled: lifetime recovery alone does not open a real file.
There were no existing intercepted factory/pool/accessor/singleton calls in the
older prefix mode to replace. Older `--recover-prefix` and worker checker modes
retain their published models and corpora. The larger extern state declaration,
new builder and comparison oracle are supporting interface/tooling changes,
not additional recovered routines.

The private reference supplies original instructions; no original binary helper
executes on the rebuilt path. Vtable function words are relocated in controlled
fixtures to rebuilt disposal/teardown. Registry/pool initialization remains
synthetic. This is not startup recovery, a full allocator, a filesystem, binary
matching, a rebuilt 3DS application or a native runtime.

## Comparison domain and validation

Primary evidence: `local/validation/worker-backend-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K build is **1,592 bytes**, comprising
**700 compiled bytes of new backend source** plus 892 bytes of existing prefix
and open source. GCC is the behavioral toolchain, not an identified original
compiler. All **146** instructions in the six new bodies were visited.
Visitation does not prove every predication outcome or live behavior.

**607 original/rebuilt pairs** include 96 pool calls, 160 factory calls,
96 accessor calls, 96 teardown calls, 98 disposal calls, 42 singleton calls,
7 connected removals and 12 connected opens. The **three persistent sequences**
each execute both implementations. Counts include their constituent pairs.
There are 382 archive-open and 382 archive-close model invocations, 102 clear
invocations and four alternate-teardown invocations, counting both paths.
**80 terminal** and **80 explicitly returning diagnostic** probes distinguish
those boundaries. Tests do not assume diagnostics normally return.

The independent state oracle checks complete guarded pool, global, node, output,
name/path and registry regions at every modeled call and at return. It checks
service arguments and descriptor shape, output preservation/publication,
callback ordering, exact statuses, pool wraparound and node reuse. Cases include
empty/nonempty pools, option values 0/1/2/all bits, zero/4/16-byte clearing,
counts 0/1/0x7FFFFFFF/0xFFFFFFFF, signed status boundaries, zero/low-only/high-only/
all-bit handles, null/nonzero service words, duplicate/empty/full registration,
already-published singleton, and four callback effect profiles. Close results
include zero, positive, sign-bit-only and all-bit values.

Callbacks deliberately clobber volatile registers/flags. Scripted mutations
separate the global service before open, after open, after acquire/release, and
at failure cleanup; change object fields during diagnostics/close; and replace
the singleton during removal. Boundary stack alignment, callee-saved registers,
stack restoration and lower stack guards are checked. The domain uses mapped,
word-aligned, nonaliasing storage; two synthetic nodes; valid vtables and readable
bounded names. Large counters are arithmetic probes, not physical pool sizes.
The checker does not establish arbitrary reentrancy, concurrency, invalid-pointer
behavior, cyclic/double-return pools, all clearing lengths or real OS behavior.

Audit evidence: `local/validation/worker-backend-20261008-audit/COMPLETE.json`.
Three compiled faults were rejected: reading the global service after pool take
instead of using its captured value, writing one to the cleared handle high
word, and returning zero instead of reloading the checked service word.
`negative-checks.json` records exact failing cases and assertions. The retained
prefix/worker regression reproduces its accepted **5,052-byte binary and complete
comparison object exactly**, including 692 direct prefix pairs, six persistent
sequences and 2,304 connected worker pairs; see `regressions.json`. All **134
public tests pass**, with actual exit zero and both streams captured in
`public-tests-console.log`. `validation-jobs.json` records all five sequential
audit jobs and their exits/durations. All launched jobs finished.

The first two development attempts stopped at the saved-function assertion for
disposal, before the corpus ran. The checker was corrected to record its absent
function object and use the independently supported ARM extent. The third run
passed. Final validation adds the concrete removal/global-replacement sequence
and varying ignored close statuses. No recovered C correction was required.

Run from `SMT4-decomp`, using fresh output directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_backend.py --output local/validation/NEW-BACKEND
python tools/check_resource_worker_backend.py --mutant factory-capture --output local/validation/NEW-BACKEND-NEGATIVE
python tools/check_resource_worker_io.py --recover-prefix --output local/validation/NEW-PREFIX-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

The file-ownership task below is now validated by
[the file ownership package](resource-worker-file-owner.md). Its dedicated
checker replaces modeled backend file open and executes concrete file disposal
through the existing close dispatcher. This report's original backend checker
retains its published model and unchanged corpus.

Recover **concrete file-object creation and close ownership** behind this
archive backend: vtable +0 entry `0x003565A0`, file disposal `0x00356438`,
file teardown `0x00356578`, and checked file-handle accessor `0x00239CD0`.
The next open body uses the newly recovered archive accessor and generic pool
take with pool `0x004D4358`; it installs file vtable `0x00420998`, whose +0x2C
and +0x30 entries identify file disposal and teardown. Follow audit
`next-file-link.json` and `next-file-*-disassembly.log`; these are static leads,
not recovered or validated new contracts.

Next acceptance: descriptor length at/beyond 512, service-failure output
preservation, successful object/handle construction, pool-exhaustion null output
and SVC handle cleanup, file close-service before virtual teardown before pool
return, then persistent archive-create/register/file-open/file-close/remove/reuse.
Reuse this package's source and harness plus the existing recovered file-close
dispatcher at `0x002B9450`. Keep lower file-open service `0x00356C28`, close
service `0x00356D5C`, SVC `0x23`, locks, clearing and diagnostic delivery explicit
until separately recovered. Verify the exact saved function extents before
implementation; GNU body leads are open `[0x003565A0,0x00356660)`, disposal
`[0x00356438,0x003564A4)` and teardown `[0x00356578,0x003565A0)`.

Archive service wrappers, raw allocator ownership/storage, registry/pool startup,
private locale/mapping/callback relocation, and deferred G1/G2 live evidence
remain open. Full ABI, matching, provenance/transfer and downstream port gates
are unchanged. Do not repeat this completed archive-backend lifetime milestone.
