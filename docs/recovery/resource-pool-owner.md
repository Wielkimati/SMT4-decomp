# Pooled resource construction and caller ownership

2026-10-08. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed roles, not original symbols. No external code reused.

## Strategic review and acceptance

All checked identities agree. The working tree was initially clean.
See `local/validation/pool-owner-20261008-static/handoff-check.json` and
`previous-evidence-check.json`.

The completed lazy allocator is a dependency, not this package's objective.
The selected next milestone is ARM caller `0x002ADCD8..0x002ADE84`, batching its
constructor `0x0014636C..0x00146448` and aligned-zero entry `0x002C4B84` because
both directly precede the caller's service request. Inspection established the
boundary before source implementation: recover allocation/construction,
request argument assembly, success-only output publication and error cleanup
dispatch; execute the recovered lazy allocator and both pool takes; compare
first-call/repeated/exhausted allocation, service/initializer status boundaries,
ordered writes, full guarded state and cleanup order. Keep request, initializer,
virtual cleanup and kernel close as named models. These bounded criteria pass.

`0x001270C4` was inspected but not batched: it adds a distinct virtual method at
vtable+0x3C and different request assembly. Optional extraction, compiler research,
live gameplay and port work do not unblock the selected contract and remain
outside this package. No project gate or reference fact changed.

## Recovered source and consumed interface

| Original, ARM | Source contract | Compiled bytes |
| --- | --- | --- |
| `0x002ADCD8..0x002ADE84` | `smt4_resource_pool_owner_create` | 424 |
| `0x0014636C..0x00146448` | `smt4_resource_pool_object_construct` | 164 |
| `0x002C4B84`, then existing shared body through `0x002C4BD8` | `smt4_resource_aligned_zero` | 8 |

The first two contracts are in `src/resource_pool_owner.c`/`.h`; the additional
zero entry is in `src/resource_clear.c`/`.h` and delegates to recovered word fill.
Thus two new routines and one entry extension add 596 bytes to the linked image;
the checker, interface declarations and symbol metadata are supporting changes.
The image totals 3,536 bytes. GCC instruction layout is not a matching claim.
No older checker loses a model in this package. The new caller comparison executes
allocation, clearing and construction directly instead of supplying their results;
its remaining service/initializer/cleanup models are listed separately below.

Static evidence is `local/validation/pool-owner-20261008-static/static.txt`
(saved caller extents, instructions, references) and the primary comparison's
`original-owner.log`, `original-construct.log`, `original-aligned-zero.log`.
`dependencies.txt` in the static directory confirms the constructor/zero/request
saved extents and request callers. The object cleanup address `0x003567F0` has
no saved function object; its recovery still requires a boundary investigation.
These independently decoded original instructions agree on the calls, literals,
field stores and returns. `visited.txt` records all 107 caller and 55 constructor
instruction addresses; this is not a claim that every branch outcome is feasible.

The constructor returns its input pointer. It writes zero to +4/+8,
+0x20..+0x6C, +0xBC..+0xCC, +0xDC/+0xE8/+0xEC, +0xF8,
+0xFC..+0x108, +0x118/+0x124/+0x128 and +0x0C..+0x1C;
stores all-ones at +0xF0/+0x12C, pool vtable `0x00420B9C` at +0xB8/+0xF4,
and object vtable `0x00420A3C` at zero. The source preserves the original store
order. Other bytes are untouched. The constructor does not initialize the embedded
locks, link pools, allocate backing storage or fail conditionally.

The caller obtains a 0x130-byte node through `0x00146284`, returns `0xD8604659`
on exhaustion, clears the node, then executes the constructor. Its subsequent
null check is retained in source, although the concrete constructor cannot return
null for a nonnull input. The descriptor's four words and five scalar parameters
are consumed only after acquisition and construction.

Request `0x002B5DD0` receives a captured service word from `0x0044E660`, an
initially zero handle output, zero, command `0x2345678A`, and stack arguments
`2, data1, 16, 2, data2, 20, 1, 0`. The first buffer contains descriptor words
zero/one, its third word's low byte, and scalar `a`. The three bytes above that
byte are **FF**, because the concrete original constructor leaves r12 all-ones
and the caller preserves those bits. The source makes this consumed behavior
explicit rather than relying on GCC's incidental r12 value. The second buffer
contains `0, descriptor[3], 0, 0, 0`. All 36 buffer bytes are checked, including
the three FF bytes. Other incidental registers and stack padding are not contracts.

Nonnegative request status leads to recovered pool take from `0x004D4358`.
Exhaustion calls SVC 0x23 with the returned handle, ignores its result, then
cleans up the main object and returns `0xD8604659`. Otherwise the new node gets
vtable `0x00420998` and the handle, then `0x00145E9C` receives the main object,
wrapper node and all five scalars. A negative initializer status dispatches the
wrapper's current vtable+0x2C, then the main object's current vtable+0x30.
A negative request status dispatches only the latter. Cleanup results do not
replace the saved failure. Nonnegative initialization publishes the main object
to the output and returns zero, including when the service/initializer returned
positive values. Failure leaves the output untouched.

## Behavioral evidence

Primary: `local/validation/pool-owner-20261008-final/COMPLETE.json`.
The warning-clean freestanding ARMv6K build passes **84 caller pairs** and
**12 isolated constructor pairs**. Both original and rebuilt must match an
independent state oracle; no constructed object or allocated result is copied
from that oracle into either machine.

- Twelve isolated caller cases cross request values 0, 1, `0x7FFFFFFF`,
  `0x80000000`, `0xD8604659`, `0xFFFFFFFF` with modeled handle publication or
  preservation. Ten cross initializer values 0, 1, `0x7FFFFFFF`, `0x80000000`,
  `0xFFFFFFFF` with original or changed virtual dispatch tables.
- Two second-pool exhaustion cases check close with zero/published handles,
  ignored close results, object cleanup and unchanged output.
- Eight persistent sequences cross guards 0, 1, 2, `0x80000000` with unowned
  or same-TLS depth-three outer locks. The two zero-guard sequences allocate
  all 16 real constructed nodes, then fail twice. Six preinitialized sequences
  allocate both available nodes and then fail twice. Storage is not reseeded
  between calls. Existing used counts and outer ownership/depth are preserved
  according to the executed operations.
- Constructor probes use four poison fills and three aligned addresses,
  including `0xF0000000`. Every untouched byte and surrounding guard is checked.
  The aligned-zero entry's new connected evidence is the consumed length 0x130;
  other lengths retain the separate shared-body clearing evidence.

Checks include exact nonstack word writes in order, full object/pool/storage/
input/output bytes at every modeled boundary and return, both request buffers,
all consumed call arguments, input-stack preservation, stack guards and
callee-saved registers, guard reads, exclusive reservation discipline, allowed
instruction intervals and budgets. The original/rebuilt paths execute lazy
construction, quotient, pool initialization, recursive/base locks, both pool
takes, aligned clearing and object construction.

The first development run stopped at the alternate cleanup address because the
harness inspected its opcode before recognizing the modeled call. No fabricated
instruction was added there: the checker now recognizes dependency addresses
before opcode inspection. The corrected primary run completes all cases. The
failed development log remains in `local/validation/pool-owner-20261008/`.

Audit: `local/validation/pool-owner-20261008-audit/COMPLETE.json`.
Three compiled faults are rejected: replacing a constructor all-ones field with
zero (direct constructor case zero), publishing null (caller case zero), and
using wrapper vtable+0x30 instead of +0x2C (caller case 18, wrong target
`0x00356578`). Exact failures are in `negative-checks.json`. Both affected
regressions preserve their complete accepted comparison objects: 76 lazy-pool
calls and 874 clearing pairs. Their linked images increase by the new eight-byte
zero entry to 2,948 and 392 bytes; binary identity is not claimed. All **134 public
tests** pass; see `public-tests.log`. Ghidra jobs ran sequentially and all launched
commands finished before handoff.

## Models and limits

Request `0x002B5DD0`, initializer `0x00145E9C`, virtual cleanup entries
`0x00356438`/`0x003567F0` and synthetic alternates, and SVC 0x23 are intercepted.
Models validate inputs and boundary state, apply only their explicitly scheduled
effects, clobber caller-saved registers/flags and return configured results.
Initializer effects exercise state changes and vtable reloads; cleanup effects
mark completion but **do not return nodes to either pool**. Therefore cleanup
dispatch/order is recovered, whereas teardown, pool return/reuse and complete
ownership lifetimes remain open. These models do not establish valid real
resource contents, request semantics or successful OS behavior.

TLS and successful exclusive-store outcomes remain scheduled; backing storage,
second-pool setup, initial locks and descriptor bytes are synthetic. The corpus
does not cover contention, arbitrary concurrency/aliasing, corrupt lists, recursion
overflow, embedded-pool initialization or real kernel state. Constructor-null
after successful allocation is unreachable on the concrete recovered path.
Old checker modes keep their original model boundaries. Live G1/G2, matching,
full ABI/compiler identity, original-target application and transfer/provenance
gates remain open.

## Reproduction and next task

```powershell
python tools/check_resource_pool_owner.py --output local/validation/NEW-POOL-OWNER
python tools/check_resource_pool_owner.py --mutant constructor --output local/validation/NEW-OWNER-CONSTRUCTOR-NEGATIVE
python tools/check_resource_pool_owner.py --mutant publish --output local/validation/NEW-OWNER-PUBLISH-NEGATIVE
python tools/check_resource_pool_owner.py --mutant cleanup --output local/validation/NEW-OWNER-CLEANUP-NEGATIVE
python tools/check_resource_lazy_pool.py --output local/validation/NEW-OWNER-LAZY-REGRESSION
python tools/check_resource_clear.py --output local/validation/NEW-OWNER-CLEAR-REGRESSION
python -m unittest discover -s tests
```

Next independent milestone: replace the **request model at `0x002B5DD0..0x002B5E6C`**
with recovered source, integrating it through this caller. Its original code builds
TLS command `0x08030204`, two buffer descriptors and the SVC 0x32 request, then
publishes a handle on nonnegative kernel return and returns the service status.
Validate exact TLS words, consumed buffers, kernel-versus-service failures and
handle publication through the ownership cleanup paths. Reuse this checker and
the existing file/archive IPC harnesses. Keep initializer `0x00145E9C` and virtual
teardown/pool-return dependencies explicit; do not repeat this completed caller.
