# Fixed-pool allocation and allocation-produced lifetimes

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry **`0x00144978`** is recovered in
[`src/resource_fixed_allocate.c`](../../src/resource_fixed_allocate.c).
This adds **one bounded entry contract**, bringing recovery to **51 plus two
adapted worker regions**. The existing insertion, free and router integration
and supporting checker add no new entry contracts.

## Strategic review and acceptance

The previous fixed-free milestone is complete. Its recorded source/tool hashes,
772-byte binary hash and full comparison object were checked against disk before
changing the shared header; see
`local/validation/fixed-allocate-20261008-audit/handoff-check.json`.
This follows A07/G2's source/build and controlled-comparison criteria
and replaces the fixed-allocation dependency of raw allocator `0x002B26F0` in the
new connected checker. Optional preparation, compiler research and deferred live
gates are not prerequisites, and the existing working tree was preserved.

Acceptance selected before implementation: instruction-backed first fit before
rounding, exact-record transfer, splitting with explicit metadata allocation,
used-list insertion, wrapping counters and no-fit return; warning-clean ARM
build; original/rebuilt/independent-oracle comparison of return, guarded state,
ordered accesses and call boundaries; both fixed allocation/free router paths;
persistent exhaustion/drain/reuse; compiled fault rejection and affected
regressions. Metadata allocation and recursive release remain explicit models.

## Instruction-derived contract

Saved inspection is in
`local/validation/allocate-raw-20261007-inspect/exports/`.
The body is `[0x00144978,0x00144AB4)`: **79 ARM instructions**. The subsequent
literal at `0x00144AB4` is `0x00409B24`. Saved/fresh Ghidra instruction bytes,
GNU disassembly and pinned executable bytes all agree; see
`local/validation/fixed-allocate-20261008-audit/static-audit.json`.

The object and metadata layouts are the same as the
[fixed-free contract](resource-fixed-free.md): used head/tail/count at object
`+0/+4/+8`, free head/tail/count at `+12/+16/+20`, available-byte counter at `+24`.
Each 16-byte record is `(payload, size, previous, next)`. The two router objects
are adjacent at `0x004E4100` and `0x004E411C`. r2/r3 are not consumed; the existing
four-word declaration preserves the observed caller interface.

The allocator scans the free list forward and selects the first record whose
unsigned size is at least the **unrounded request**. Empty/exhausted searches
return zero without writes. Only after selecting a record does it round the
request up to 128 bytes, modulo u32. It does not check the rounded fit again.
Consequently a 1-byte record can satisfy a 1-byte request and then underflow
when 128 is subtracted. A request above `0xFFFFFF80` can round to zero. Source
preserves these behaviors rather than imposing alignment or overflow guards.
A second rounding test in the original split arm is redundant: the first
rounding always clears bits 0..6. Its three arithmetic instructions at
`0x001449C4/0x001449C8/0x001449CC` cannot execute. The source uses the equivalent
single rounding expression; the dead literal load/no-op has no source effect.

If selected size equals rounded size, available bytes decrease by the selected
size, the record is removed from the free list, its links are cleared, and free
count decrements modulo u32. Recovered insertion `0x002C3928` then inserts that
record into the used list, before equal unsigned payload keys, incrementing used
count. The payload is reloaded from the record and returned.

Otherwise it requests a fresh 16-byte metadata record using
`0x002C5544(0x100,0x100,0,0x10,1)`. **There is no null-result check.** All four
words are zeroed in order. The new record receives the selected payload and the
rounded size; the selected payload and size are reloaded after metadata
allocation and advanced/decreased by that rounded size. Its list position is
unchanged. Available bytes decrease by the new record's reread size. The new
record enters the used list through recovered insertion, then its payload is
reloaded and returned. The source preserves ordered stores and volatile reloads,
including the counter read after the modeled allocation's recursive effects.

A direct zero request can transfer a zero-sized record or create a zero-sized
used record. The raw allocation router's zero-size fast return prevents that
behavior when entered through `0x002B26F0`. A zero payload key can also be returned
after a successful mutation; zero return alone is not a reliable success test
outside the ordinary nonzero-payload domain. No payload bytes are read or written
by the fixed allocation/free code.

## Build and controlled comparison

Primary evidence: `local/validation/fixed-allocate-20261008-final/COMPLETE.json`.
The freestanding GCC ARMv6K C11 build uses `-O2`, ARM mode, soft-float,
warnings-as-errors and no runtime/SDK libraries. The linked image is **1,376
bytes: 1,352 text and 24 read-only data**. New allocation source contributes
**312 text bytes**. Existing insertion/free and allocation/free routers account
for the remainder. Rebuilt execution is confined to rebuilt text; unresolved
heap/lock linker boundaries are not executed by this fixed-route corpus.

| Observation | Result |
| --- | ---: |
| Original/rebuilt/oracle calls | 1,992 |
| Allocation / free calls | 1,812 / 180 |
| Exact transfers / splits | 196 / 600 |
| No-fit / router zero-size returns | 928 / 88 |
| Rounded-size overrun / rounding-wrap probes | 72 / 24 |
| Persistent allocation/free/reuse lifetimes | 36 |
| New original instruction addresses visited | 76 of 79 |
| Modeled metadata allocations / releases across both paths | 1,200 / 216 |
| External reads / writes across both paths | 40,420 / 26,368 |
| Maximum instructions per call | 174 |

The direct corpus uses empty, zero-size, boundary-size and multi-record free
lists, requests around 128-byte boundaries and u32/sign boundaries, ordinary and
high metadata addresses, used-list insertion positions/equality, all exact-free
unlink positions, and wrapping counters. Accounting probes deliberately need not
match list lengths. Wrapped payload/huge extent fixtures test record arithmetic,
not real wrapped memory arenas or complete malformed-list handling.

The oracle selects records using host sequences, computes rounding with integer
division, and rebuilds list links declaratively. Each machine is checked against
its complete guarded byte snapshot, independently of the other machine. Ordered
external read addresses/widths and write addresses/widths/values also agree.
Return r0, r4-r11, d8-d15, stack restoration, caller stack, 8-byte dependency-call
alignment and a 256-byte stack-scratch bound are checked. Unexpected code,
out-of-fixture memory, uninitialized reads and budget excess fail.

On split allocation, the checker verifies full pre-call state and all five
metadata arguments before returning disjoint, writable, nonnull metadata. One
model leaves state unchanged. The other changes the selected payload and size,
used/available counters and routing base, exercising the original's post-call
reloads and captured object. Volatile integer/VFP registers and flags are
clobbered. These are adversarial models, not execution of recursive metadata
ownership. Free calls reuse the previous checker's exact release-state oracle;
release itself is modeled without recursive effects for these lifetimes.

Each persistent lifetime starts with one synthetic 512-byte free extent. Four
allocations split three metadata records and transfer the final exact record;
a fifth allocation returns no fit. Freeing in one of six orders restores the
entire extent and all counters. A 512-byte exact allocation returns the same
payload, and another free restores the pool again. This runs directly and through
both fixed router paths, at ordinary and high payload/metadata addresses. Actual
original/rebuilt pool bytes persist between calls without fixture reset; only
checked metadata dependency effects are applied. Pool construction remains
synthetic. No real allocator heap provides the split records.

## Validation, models and limits

The first build/comparison passed. A subsequent manifest-only fix added the new
Python driver to its own evidence file hashes; the final run retains identical
binary and comparison objects. No behavioral mismatch was suppressed and no
source/oracle assertion was weakened.

Seven independently compiled source faults are rejected: fit after rounding,
64-byte rounding, exact-unlink counter direction, cached selected size across
metadata allocation, wrong metadata size argument, available-byte addition,
and strict rather than inclusive fit. The cached-size fault is first rejected by
the ordered-read check; it removes the post-call read even in the no-effect model.
The existing fixed-free (1,836 calls) and raw-allocation (8,824 calls) regressions
retain their exact previous binary hashes and comparison objects. All 134 public
tests pass. Exact commands, assertions and results are indexed in
`local/validation/fixed-allocate-20261008-audit/COMPLETE.json`.

Models removed in the **new checker**: fixed allocation, ordered insertion,
fixed free and both fixed paths of the allocation/free routers execute original
or rebuilt source. Only allocation is a newly recovered entry. Older raw-router,
worker and retained allocation checkers preserve their documented interception
boundaries; their previous evidence is not broadened.

Open boundaries: recursive metadata allocation/release, allocator/pool
construction, null metadata results, arbitrary cyclic/aliased lists, unsupported
memory, synchronization and complete resource-worker lifetimes. All reachable
allocation instructions execute, but instruction visitation is not exhaustive
predication, alias or input coverage. Missing-record free remains outside this
package's valid-membership domain. Original compiler/full ABI, matching,
G1/G2 live evidence and G3 provenance/transfer gates remain open. This is
project-authored source from pinned original instructions; no external
implementation was imported.

## Reproduce and next independent milestone

Run from `SMT4-decomp`, choosing fresh output directories and sequential Ghidra
jobs on the authoritative project:

```powershell
python tools/check_resource_fixed_allocate.py --output local/validation/NEW-FIXED-ALLOCATE
python tools/check_resource_fixed_allocate.py --mutant cached-size --output local/validation/NEW-FIXED-NEGATIVE
python tools/check_resource_fixed_free.py --output local/validation/NEW-FREE-REGRESSION
python tools/check_resource_allocate_raw.py --output local/validation/NEW-ROUTER-REGRESSION
python -m unittest discover -s tests
```

Next recover worker data allocation **`0x002BF7EC`**, the six-word, variable
alignment metadata wrapper still intercepted by `CompareResourceWorkerIo.java`
and `CompareResourceRegistryWorker.java`. Its saved listing/body through
`0x002BF8A8` and literal at `0x002BF8AC` are in
`local/validation/allocate-raw-20261007-inspect/exports/`. Reuse
`src/resource_allocate_lower.c` and `tools/check_resource_allocate_lower.py`
fixtures: establish unsigned minimum-128 alignment, full-width mask arithmetic
versus the stored/consumed low 16 bits, raw-size/header/back-pointer mutation,
registration, clearing, six-word forwarding, and lock reloads. Keep nonnull raw
storage and modeled locks/zeroing explicit initially; connect recovered raw
allocation/registration/conversion when fixtures support it. The worker call
sites already verify this routine's six consumed arguments, so its recovery
replaces an evidenced worker dependency. Do not repeat fixed-pool recovery or
start a tooling-only worker integration package. The similar `0x002C34F8` listing
is a lead, not an automatically admitted adjacent source target.
