# Alternate resource creation and handle wrapping

2026-10-08. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategic review and acceptance

All 40 source/tool identities and the previous
teardown binary match its manifest; see
`local/validation/pool-alternate-20261008-static/handoff-check.json`.
Existing uncommitted recovery work was preserved. Teardown is complete and was
not selected again. The recorded alternate caller and its virtual factory form
a connected new source package using the completed request/initializer/lifetime
chain. Optional extraction, compiler research and native-port work do not unblock
this target and remain deferred.

Acceptance declared before implementation: recover ARM `0x001270C4` and
`0x003567A4`, build source, and compare request argument/layout transport,
factory publication/exhaustion, failure-output preservation, initializer argument
transport and cleanup, and persistent pool return/reuse. The first buffer's
self-reference required explicit inspection and an additional actual-byte check;
it was not treated as a literal byte `1`. Remaining kernel/read/diagnostic and
initial storage models are named below. No project gate or reference fact changed.

## New recovered source contracts

`src/resource_pool_alternate.c` adds two contracts, totaling 448 compiled bytes:

| Original ARM entry and exclusive end | Contract | GCC bytes |
| --- | --- | ---: |
| `0x001270C4..0x00127218` | `smt4_resource_pool_alternate_create` | 352 |
| `0x003567A4..0x003567E4` | `smt4_resource_pool_wrap_handle` | 96 |

The saved Ghidra project contains both function objects with these exact extents.
`static-ghidra.txt` and the raw original disassembly agree; literal words after
the ends are excluded. The reference vtable `0x00420A3C` +0x3C contains
`0x003567A4`, checked before relocation of the rebuilt virtual entry. No Ghidra
database annotations were changed.

The alternate caller takes output, two pool counts, backing address, capacity,
loading flag and a descriptor pointer. Its original ABI places output/counts/
backing address in r0-r3, and capacity/flag/descriptor at entry SP+0/+4/+8.
It takes a main object through `0x00146284`, clears 0x130 bytes, and constructs
it through `0x0014636C`. A null result returns `0xD8604659` without publishing
output. The concrete constructor always returns its receiver; its redundant
null branch is preserved, not forced with an artificial constructor model.

The request reuses `0x002B5DD0`, capturing service global `0x0044E660` and
initializing handle output to zero. Scalars are word1=0, word2=3, type1=1,
size1=1, type2=2, size2=12, word7=1 and word8=0. Buffer two is exactly the
incoming descriptor address, not a copied or reformatted descriptor. Buffer one
points to a local word **containing its own address**. Original instructions at
`0x00127114`/`0x0012711C` establish this self-reference at caller SP+0x30;
the adjacent store of `1` at SP+0x34 is not the exposed byte. The request declares
one byte, not four, from the self-referential word. No format or service meaning
is assigned to that byte here.

The source preserves the pointer relationship. The pinned GCC build additionally
places that word at the same stack offset as the original. At the compared
entry SP `0x00A01000`, both expose byte `0xD0` from address `0x00A00FD0`.
The harness checks the relationship, complete local-word preservation across
request execution, **and equality of the actual declared byte** between machines.
`request-layouts.tsv` records each observation; the static directory's
`request-layout-audit.json` independently checks all 77 request pairs and the
three descriptor words. The byte check must remain if a compiler or frame change
alters placement. This is evidence for the pinned build/stack fixture, not a
claim that the service ignores that byte or that arbitrary rebuilds preserve it.

After a nonnegative request result the caller zeros its local file output and
invokes object vtable +0x3C with receiver, output address and returned handle.
A nonnegative factory result invokes the existing initializer with the original
five arguments. Negative initialization disposes the file through its current
vtable +0x2C; any negative request/factory/initializer result disposes the main
object through +0x30 and returns that result, preserving caller output. A
negative request does not separately close a published response handle. Success
normalizes to zero and publishes the main object only at the end.

The wrapper never reads its receiver. It takes a node from file pool
`0x004D4358`. On success it writes vtable `0x00420998`, then handle at +4,
publishes the node and returns zero. The recovered stores explicitly retain
that order. On exhaustion it executes SVC 0x23 on the handle, including zero,
ignores the kernel result, returns `0xD8604659` and does **not** write output.
No validation of handle bits, output aliasing or receiver validity is added.

## Integration and models

`--recover-alternate` implies `--recover-teardown`, initialization and request
recovery. The two new source contracts execute alongside existing lazy/main/file
pool allocation, clearing, construction, request IPC, initialization/query IPC,
file disposal/close IPC, object teardown, pool return and recursive locks.
No new game-call interception stands in for the factory. Read-method and
diagnostic models remain. Earlier modes retain their documented models and
coverage; this package does not newly recover those dependencies or remove a
model from the earlier corpora.

Header declarations, build selection/mutations, generalized invocation/request
hooks in the shared checker and the new subclass are supporting integration.
They are not additional recovered game contracts. The default request checks
retain their original argument values, buffer extents and preservation checks;
the new hooks let the alternate caller use its distinct ABI and buffer shape.

## Primary comparison evidence

`local/validation/pool-alternate-20261008-final-checked/COMPLETE.json` records a
warning-clean **6,364-byte** ARMv6K C11 build. There are **78 alternate-owner
pairs, 16 direct-factory pairs, 22 cleanup pairs and four persistent sequences**.
All **101 new instruction sites** execute, excluding literals. This is site
visitation, not proof of every conditional outcome. Both machines independently
match the ordered-write/full-fixture oracle, result and ABI checks.

The corpus covers:

- Loaded/unloaded creation, signed kernel/service status boundaries, positive
  success statuses and absent response writes. With no response, the request's
  own type1 word supplies handle 1; that value is concretely wrapped.
- Empty main/file pools, zero/nonzero handles, short header, insufficient
  capacity, negative read results at every read position, and preservation of
  caller output after failure. The inherited sizing-read error can proceed when
  its computed sentinel is within capacity; this package does not change it.
- Actual disposal and reuse without reseeding between operations, all five
  ownership buckets, nested outer locks and wrapping/nested file-pool metadata.
  Successful sequences restore main count 0 and initial file count 5.
- Direct factory receivers 0, 1, `0x80000000` and `UINT32_MAX`, proving no
  receiver dereference; handle/count edge bits, output sentinels, and close
  return values that must not replace the exhaustion result.
- High mapped main objects, descriptor edge words, unequal pool counts,
  unsigned size wrapping, and callback-time changes to the service global.

There are 154 request IPC calls, 138 factory calls and 44 file-close IPC calls
across both machines. Full guarded fixtures, stack/input preservation,
callee-saved registers, lock reservations, code extents and instruction budgets
remain checked. Kernel/TLS response scheduling is explicit. The original
reference hash is checked before and after each successful checker run.

Development found a Java field-type error, then correctly rejected GCC's
reversed file-field store order, then rejected the initial incorrect assumption
that the first request buffer held literal 1. The source now uses ordered
volatile field stores and the instruction-backed self-reference. Failed runs
remain in `pool-alternate-20261008-dev*`; they are not accepted evidence.

## Fault checks and regressions

`local/validation/pool-alternate-20261008-audit/COMPLETE.json` records five
rejected compiled faults: changing the first buffer size to four, replacing the
self-reference with literal 1, swapping initializer counts, publishing null on
factory exhaustion, and losing the supplied handle. Each fails its corresponding
layout, forwarding, preservation or node-layout assertion; exact reasons and
binary identities are in `negative-checks.json`.

All four affected checker modes retain their complete comparison objects and
exact binary hashes: teardown 5,916 bytes, initializer 4,740, request 3,696 and
default owner 3,536. This retains their larger direct initializer/request/cleanup
corpora instead of treating the new alternate corpus as a replacement. See
`regressions.json`. All **134 public tests** pass (`public-tests.log`). Shared
file/lock/request/initializer/teardown source was unchanged, so their unrelated
independent checkers were not repeated. All Ghidra jobs ran sequentially, and
all launched validation processes finished before handoff.

## Remaining boundaries and next milestone

Reads at `0x003564A8` and returning diagnostics at `0x002BBD70`/`0x002BCE9C`
remain modeled. TLS/SVC replies, successful exclusives and callback effects are
scheduled. Initial locks, pools, service globals and backing storage are
synthetic. Invalid/aliased buffers, duplicate ownership, cyclic lists, real
concurrency and service interpretation of request payloads are outside this
domain. The concrete factory returns only zero or its exhaustion error; arbitrary
alternate factory implementations are not covered. This is bounded source/build
and comparison evidence, not binary matching, live play or a full application.

The next independent source target is the **descriptor-based archive factory
`0x00127220..0x001272C4`**. Static evidence is
`local/validation/pool-alternate-20261008-static/next-caller.log`. It sends
archive ID 7, type 2, length 12 and the caller's descriptor to recovered archive
open `0x002ADBE8`; then it takes pool `0x004D431C`, constructs the existing
backend layout, publishes null on exhaustion, reloads service state and closes
the acquired 64-bit archive through `0x002ADBB8`. This is distinct from the
completed generic factory `0x003568C8` and the handle wrapper recovered here.
Recover its new source contract and compare it through the existing archive
IPC/lifetime harness (`tools/check_resource_worker_file_owner.py
--recover-archive-services --recover-clear`), including descriptor transport,
service capture/reload, output preservation versus null publication, both handle
halves and return/reuse. Start from `resource-worker-archive-service.md` and
`resource-worker-backend.md`. Do not recover their existing callees again.

Full read-service integration, startup/storage ownership, initial outer-lock
construction, diagnostic delivery, deferred live G1/G2, compiler/full ABI,
matching and source-transfer gates remain open.

```powershell
python tools/check_resource_pool_owner.py --recover-alternate --output local/validation/NEW-ALTERNATE
python tools/check_resource_pool_owner.py --recover-alternate --mutant alternate-self-reference --output local/validation/NEW-ALTERNATE-NEGATIVE
python tools/check_resource_pool_owner.py --recover-teardown --output local/validation/NEW-TEARDOWN-REGRESSION
python -m unittest discover -s tests
```
