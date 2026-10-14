# Pooled resource initialization and query chain

2026-10-08. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategic review and acceptance

All 32 recorded source/tool
identities and the previous request binary match (`handoff-check.json` in the
static directory). Existing uncommitted owner/request/clear work was preserved.
The completed request milestone is a dependency, not a repeated objective.

Selected initializer ARM `0x00145E9C..0x0014627C` and its direct query helper
`0x00145E7C..0x00145E9C`. Before implementation, acceptance required an ARM build,
controlled original/rebuilt agreement for header/short/error reads, unsigned
capacity boundaries, both loading modes, exact embedded layouts, concrete
pool/lock initialization and caller failure cleanup, with remaining services
explicit. These bounded criteria pass. The helper's two small callees were
batched after instruction inspection because they directly supply the value
that selects the initializer's ownership slot. Their query IPC shares the
existing TLS/SVC comparison machinery. Optional preparation, compiler research,
live gameplay and port implementation do not unblock this target.

Static inspection resolves vtable `0x00420998` slot zero to `0x003564A8`, the
already recovered file-read method. This mode schedules reads at that method;
it does not silently inherit the separate read-service checker's IPC evidence.
The next dependency boundary is teardown and actual pool return/reuse.
No project acceptance gate or reference fact changed.

## Source contracts and behavior

| Original ARM entry and exclusive end | Recovered contract | GCC bytes |
| --- | --- | ---: |
| `0x00145E9C..0x0014627C` | `smt4_resource_pool_owner_initialize` | 880 |
| `0x00145E7C..0x00145E9C` | `smt4_resource_pool_object_query` | 40 |
| `0x002BBD3C..0x002BBD64` | `smt4_resource_pool_query_service` | 68 |
| `0x0014F42C..0x0014F460` | `smt4_resource_pool_query_value` | 56 |

The first two are in `src/resource_pool_object_initialize.c`; the last two are
in `src/resource_pool_query.c`. They add four recovered entry contracts and
1,044 compiled bytes to the 4,740-byte linked image. Header/checker/symbol changes
support those contracts and are not additional recovered game routines.
The previous aggregate initializer interception is removed only in the new
`--recover-initialize` mode, which implies `--recover-request`. The query helper,
service accessor and IPC execute without game-call interception. Older modes
retain their documented initializer model.

The initializer consumes an object, a file wrapper, two pool counts, a backing
address, capacity and a loading flag. Its first virtual read requests 40 bytes
at offset zero. A negative status returns unchanged; a nonnegative status with
count other than 40 returns `0xC8A04554`. The first and last header words do not
constitute a checked signature/version: word zero is ignored, word nine is later
copied to object+0xB0. Words 1/2, 3/4, 5/6, 7/8 describe four views; these are
raw observed fields, not inferred resource-format semantics.

Required pool bytes are `(a << 5) + 24*b`, with 32-bit wrapping arithmetic.
With any nonzero loading flag, a second 40-byte read at offset zero supplies a
separate sizing header. Negative status, count other than 40, or a negative
signed sum of sizing words 2/4/6/8 makes required bytes `UINT32_MAX`.
Otherwise the wrapping sum is added to required pool bytes. Capacity comparison
is unsigned and rejects only `required > capacity`, returning `0xD8604659`.
Thus a failed sizing read can pass when capacity is `UINT32_MAX`. The sizing
header need not equal the first header; no consistency check is added.

In loaded mode, four reads use lengths from the **first** header. Destinations
advance by requested length; file offsets advance by returned count, wrapping
at 32 bits and then sign-extending to the read method's 64-bit argument.
Nonnegative short payload reads are accepted. Each negative payload status
returns immediately, preserving earlier payload effects. The first payload
offset is 40. Zero-length payload reads still occur. Embedded views at
+0x70/+0x80/+0x90/+0xA0 receive backing address, length, zero and owner address.
In unloaded mode they instead receive zero, length, owner address and the
corresponding odd header word. Source preserves the original store order.

Four consumed descriptor layouts at +0x20/+0x30/+0x48/+0x58 receive zeros,
embedded-view pointers and lengths; the first and third lengths shift right two.
Fields not written by the original remain untouched. The two embedded pools at
+0xB8/+0xF4 use 32- and 24-byte elements, alignment four, zero options, and the
remaining backing address. Recovered `0x002A4EB4`, `0x002C3B54`, `0x00138F44`
and quotient source execute to create their lists and locks. No new capacity,
alignment or overflow validation is imposed on those existing contracts.

Query helper `0x00145E7C` captures a service handle and passes its address plus
object+4 to the query IPC. Accessor `0x002BBD3C` checks word `0x0044E644`; zero
calls diagnostic `0x002BBD70` with status `0xE0A046DB` and site `0x002BBD58`.
It reloads the service word after that diagnostic, including when it stays zero.
The query IPC obtains TLS and writes only command word zero, `0x08630000`, then
issues SVC 0x32 with the captured handle. A negative kernel return preserves the
output; every nonnegative kernel return publishes command word two and returns
command word one, including negative service status.

A negative query result calls the same diagnostic with site `0x0014622C`.
Under the explicitly returning diagnostic model, its return value is ignored.
The initializer reloads object+4 and treats it as signed: values below -8 select
slot zero, -8 through -1 slot one, zero slot two, 1 through 8 slot three, and
values above 8 slot four. It stores the file wrapper at object+0x0C+4*slot and
object+8, then returns zero. Those diagnostic-site constants represent original
instruction provenance, not GCC program counters.

## Comparison evidence

Primary: `local/validation/pool-object-init-20261008-final/COMPLETE.json`.
The warning-clean ARMv6K C11 build passes **106 owner pairs and 106 direct
initializer pairs**. Both machines must match an independent ordered-write and
full-state oracle; predicted initialized objects/pools are never copied into the
machines. All **248 initializer, eight helper and 23 query-chain instruction
sites** execute. This does not claim every possible predication outcome.
There are 1,544 scheduled read calls and 304 actual query IPC executions across
both machines, with 60 returning diagnostic calls.

The corpus covers:

- Both loading modes; flags 1, `0x80000000`, and `UINT32_MAX`; all five signed
  ownership slots and -8/0/8 boundaries; preserved versus published query output.
- Capacity one below/equal/one above required, failed sizing with maximum
  capacity, negative/wrapping sizing sums, and wrapping pool-count products.
- First-header counts 0/39/40/41/all-ones, positive and negative statuses;
  failures at every later read; zero/short/full and high/wrapping returned counts.
  All four payload destinations and signed 64-bit offsets are checked.
- Zero pool counts, unaligned backing addresses, empty payloads, nonmultiple-of-
  four lengths, and full-width unloaded lengths. Some zero-size unaligned pool
  extents wrap to large metadata sizes while their unsigned list loop is empty;
  this reproduces the original bounded path, not a usable allocation guarantee.
- Query kernel sign boundaries and positive returns, negative service status
  with output publication, service lookup diagnostics with zero/nonzero/high
  replacement handles, and returning query diagnostics that change object+4
  before the final slot selection.
- Direct objects begin poisoned, alternate between original low storage and
  `0xF0000000`, and retain untouched bytes/guards. Caller objects use the concrete
  constructor and exercise ordered wrapper/object cleanup on initializer failure.

Checks retain input/stack preservation, callee-saved registers, stack guards,
allowed instruction extents and budgets, request command/buffers, full TLS
bytes, query command write count/order, kernel handle and output publication,
exclusive reservation discipline, exact pool links, and all guarded object,
storage, input, output and global fixture bytes. Query outputs are checked at
query return and in the initializer's final ordered writes. The main object's
query service global is synthetic; its loads and diagnostic-driven reload execute.

Static evidence: `local/validation/pool-object-init-20261008-static/static.txt`
and `helpers.txt`; GNU independent decoding is in the primary
`original-object-init.log`, `original-query-service.log` and
`original-query-ipc.log`. Function extents, instructions, literals and virtual
slot agree. `visited.txt` binds the executed original instruction addresses.

The initial initializer-only development run passed with the query's two lower
calls modeled. When those calls were recovered in one translation unit, GCC
inlined the query IPC into its helper, bypassing the checker's entry observation;
the development run correctly stopped at an unrecognized TLS write. Keeping the
service/IPC functions in `resource_pool_query.c` preserves the observable call
boundary without changing optimization flags or adding an original-behavior
claim about inlining. The corrected query development and final runs pass.
The failed development log remains local; it is not accepted evidence.

## Fault checks and regressions

Audit: `local/validation/pool-object-init-20261008-audit/COMPLETE.json`.
Four compiled faults are rejected: rejecting capacity equality (owner case 0),
advancing file offsets by requested length instead of returned count (case 78),
moving the -8 boundary to the wrong slot (case 2), and suppressing query output
publication on negative service status (case 24). Exact assertions and mutant
binary hashes are in `negative-checks.json`.

Both affected regressions preserve their **entire comparison objects and exact
binary hashes**: request mode remains 3,696 bytes with 132 owner / 70 direct
request / 12 constructor pairs, and default owner remains 3,536 bytes with
84 owner / 12 constructor pairs. Their existing persistent allocation sequences
remain checked. All **134 public tests** pass; see `regressions.json` and
`public-tests.log`. Shared pool/lock/clear source was unchanged, so its independent
regressions were not repeated. Ghidra jobs ran sequentially; all launched jobs
finished before handoff.

## Models and limits

The remaining game-call models are virtual read `0x003564A8`, diagnostics
`0x002BBD70`, and cleanup `0x003567F0`/`0x00356438`. The read model checks actual
arguments, then independently supplies a requested-size payload and a scheduled
count/status, including deliberately inconsistent counts and effects on failure.
It always writes the count. It does not execute read IPC or establish real file
contents. The separate read-service recovery remains valid within its own corpus.

TLS locations, SVC 0x32 responses and successful exclusive outcomes are scheduled.
Query responses overwrite command words one/two independently of kernel status;
untouched query responses and arbitrary TLS/output aliasing are not this domain.
Volatile caller registers and flags are clobbered at modeled calls/SVCs. Request
IPC executes through the owner. Initial outer locks, pools, backing storage and
global service state are synthetic; no real concurrency is established.

Cleanup still does not return nodes to pools. This new corpus begins each case
fresh; the older request/default regressions retain their persistent allocation
sequences. Complete successful lifetimes, pool return/reuse, backing storage and
startup remain open. Invalid/aliased pointers, unbounded node extents, real
services, live G1/G2, full ABI/compiler identity, matching, complete application
builds and source-transfer gates remain unverified.

## Reproduction and next independent milestone

```powershell
python tools/check_resource_pool_owner.py --recover-initialize --output local/validation/NEW-OBJECT-INIT
python tools/check_resource_pool_owner.py --recover-initialize --mutant init-capacity --output local/validation/NEW-INIT-CAPACITY-NEGATIVE
python tools/check_resource_pool_owner.py --recover-initialize --mutant init-offset --output local/validation/NEW-INIT-OFFSET-NEGATIVE
python tools/check_resource_pool_owner.py --recover-initialize --mutant init-slot --output local/validation/NEW-INIT-SLOT-NEGATIVE
python tools/check_resource_pool_owner.py --recover-initialize --mutant init-query-publish --output local/validation/NEW-INIT-QUERY-NEGATIVE
python tools/check_resource_pool_owner.py --recover-request --output local/validation/NEW-REQUEST-REGRESSION
python tools/check_resource_pool_owner.py --output local/validation/NEW-OWNER-REGRESSION
python -m unittest discover -s tests
```

Next recover **main-object disposal `0x003567F0..0x00356840` and teardown
`0x00356844..0x003568C0`**, replacing the cleanup model through owner failure and
successful release/reuse. Static lead: `next-teardown.log` in this package's
static directory. Vtable `0x00420A3C` +0x30 is `0x003567F0`; +0x34 is
`0x00356844`. The first has no saved Ghidra function object, so verify its extent
against the raw instructions before analysis changes. Disposal invokes teardown,
then returns the object to the current global pool under recovered locks.
Teardown clears +8, visits five owned file slots and cleans both embedded pools.
Inspect its direct helper **`0x002A458C`** before choosing the pool-cleanup boundary.
Reuse already recovered file disposal `0x00356438`, file teardown `0x00356578`
and their close-service source where the integration fixtures permit; they are
not new source targets. Read `resource-worker-file-owner.md` and the pool-owner
report for their existing limits. Validate actual return/reuse, counts, cleanup
order and failed-initialization state. Do not repeat request or initialization.
