# Fixed-pool free and ordered insertion

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entries **`0x00138354`** and **`0x002C3928`** are recovered in
[`src/resource_fixed_free.c`](../../src/resource_fixed_free.c). They add two
bounded entry contracts, bringing the total to **50 plus two adapted worker
regions**. Caller integration and comparison tooling add no contracts.

## Strategic review and acceptance

The preceding raw-free milestone is complete: all eight audit file hashes,
its primary comparison object and its binary hash agree with disk in
`local/validation/fixed-free-20261008-audit/handoff-check.json`. This directly replaces the two remaining pool mutation models at the router's
boundary. This follows A07/G2's source/build and bounded behavioral-comparison requirements.

Acceptance: recover valid used-record lookup/unlink, address-ordered insertion
including equality, wrapping accounting, right-then-left coalescing and exact
metadata-release arguments/effects; build warning-clean ARM; compare original,
rebuilt and independent byte-oracle state, ordered accesses and consumed ABI;
integrate both fixed-object router routes and persistent drains; reject compiled
faults and run affected regressions. Recursive metadata release remains modeled.

## Instruction-derived source contracts

Read-only saved-project exports are in
`local/validation/fixed-free-20261008-inspect/exports/`. Saved bodies are
`[0x00138354,0x001384B7]` (89 ARM instructions) and
`[0x002C3928,0x002C39BB]` (37). The insertion boundary agrees with the previous
GNU disassembly lead. All 126 instructions are checked against saved Ghidra
listing, GNU disassembly and pinned executable bytes in
`local/validation/fixed-free-20261008-audit/static-audit.json`.

The pool is a 28-byte object: used head/tail/count at `+0/+4/+8`, free
head/tail/count at `+12/+16/+20`, and available-byte accounting at `+24`.
Each separate 16-byte metadata record contains payload address, size, previous
record and next record at `+0/+4/+8/+12`. The two router pool objects are adjacent
at `0x004E4100` and `0x004E411C`. Addresses and counters use modulo-u32 arithmetic.
No payload bytes are accessed by either new routine.

`smt4_resource_fixed_insert(list,node)` reads the tail first. An empty tail
sets both roots to node and clears its two links. Otherwise it reads the new
key once and scans backward until it finds a **strictly smaller unsigned key**.
It inserts after that record, or at the head if none exists. New records therefore
precede every equal key. It updates the affected neighboring/root links and
increments the list count. The head insertion rereads the new node's next link
before updating its successor. Source preserves this read and the ordered stores.
The observed final r0 is the unchanged list address; source exposes that value
without claiming its original C return type or that other callers consume it.

`smt4_resource_fixed_free(object,address)` scans the used list forward and
selects the first record with that payload address. It unlinks the record,
clears its links, decrements the used count, adds its size to available bytes,
then calls the recovered insertion with the free-list roots at `object+12`.
There is **no missing-record guard**: failure to find a record flows into reads
at addresses 8 and 12. Source adds no success/error behavior for this case.

If the inserted record's end equals its right neighbor's start, it adds that
neighbor's size, unlinks and clears the redundant right metadata, decrements
the free count, then releases that metadata through `0x002C43B4`. After this
call it reloads the inserted record's previous link and that predecessor's next
link. If these two records are adjacent, it adds the right size into the left
record, unlinks/clears the right metadata, decrements free count and releases it.
Thus both merges release right metadata first, then the newly freed record.
The reload after release is preserved; recursive effects are not assumed absent.
Only these immediate neighbors are considered. No repeated coalescing loop exists.
The router consumes a void free interface; incidental r0 is not a status result.

## Build and comparison evidence

Primary marker: `local/validation/fixed-free-20261008-final/COMPLETE.json`.
The GCC ARMv6K build is **772 text bytes**: 524 bytes for the two new contracts
and their local unlink helper, plus the existing 248-byte router. Flags are C11,
`-O2`, ARM mode, soft-float, freestanding, warnings-as-errors and no runtime/SDK
libraries. Rebuilt execution stays in rebuilt text; modeled release is intercepted.
The helper is an implementation detail, not a third recovered entry contract.

| Observation | Result |
| --- | ---: |
| Original/rebuilt/oracle calls | 1,836 |
| Direct insertion / direct free / routed free | 528 / 444 / 864 |
| Persistent four-free drains | 36 |
| Neither / left / right / both merges | 666 / 258 / 282 / 102 |
| Used singleton / head / tail / middle removal | 336 / 330 / 330 / 312 |
| Visited new instruction addresses | 125 of 126 |
| Modeled metadata releases, both paths | 1,488 |
| External reads / writes, both paths | 81,324 / 42,984 |
| Maximum instructions per call | 192 |

Insertion fixtures include empty/singleton/multiple records, equal keys, all
insertion positions, zero/max/sign-boundary keys, ordinary/high-bit metadata
addresses and four counter profiles. Free fixtures vary immediate neighbors,
adjacency, used-list positions, accounting profiles and three release-effect
profiles across direct free and both router routes. Counters deliberately need
not equal list length in the wrapping arithmetic probes. Two synthetic extent
profiles check size-sum wrap, including zero payload; these are record arithmetic
tests, not physical-memory allocation claims.

Each persistent drain starts with four adjacent used records and two free
neighbors, then frees in one of six orders. Real original/rebuilt memory persists
between calls without fixture rewrites. All finish with one restored 192-byte
extent, zero used count, one free count and 192 available bytes. Initial records
are synthetic: **fixed-pool allocation and construction are not recovered here**.

The oracle operates on record sequences and byte snapshots, independently of the
instruction load/store algorithm. It checks complete guarded pool/metadata/raw
state before and after every call and immediately before each metadata release.
Actual release arguments/order, 8-byte call-entry stack alignment, r4-r11, d8-d15,
caller stack and a 256-byte stack-scratch bound are checked. Both machines' ordered
external reads, writes, widths, values and release events agree. Unexpected code,
out-of-fixture memory, uninitialized reads and instruction-budget excess fail.

Release models either leave memory alone, poison only retired metadata and
perturb pool counters, or additionally change the surviving left neighbor's size.
The last profile can prevent the later left merge and tests post-release reloads.
Each effect starts from a fully checked release snapshot. Volatile integer/VFP
registers and flags are clobbered on return. These effects are explicit adversarial
models, not a claim to execute recursive allocation ownership or release code.

The unvisited instruction is `0x00138384`, which sets the failed lookup result
to zero. Missing-record/null-metadata/double-free execution is outside the tested
domain. Static preservation is not behavioral validation of that path. Visitation
also does not prove every predication outcome or every possible alias.

## Faults, regressions and limits

Eight separately compiled faults cover equal-key order, signed-key comparison,
count direction, free-byte direction, right/left adjacency, wrong released
metadata and nonzero cleared links. Negative markers require successful builds
and corpus assertions. The affected raw-free and outer-release regressions retain
their previous binary hashes and full comparison objects; all 134 public tests
pass. Exact commands and evidence are indexed by
`local/validation/fixed-free-20261008-audit/COMPLETE.json`.

The initial ARM build passed, but the first comparison harness compile failed
because two Java helpers shared a signature. Renaming the region lookup helper
fixed that support-code error. The first executed comparison passed. Review then
made the visited-instruction metric computed rather than literal; the final run
preserves the same binary and comparison object. No source behavior or comparison
assertion was weakened after a behavioral mismatch.

Models removed: fixed-pool free and ordered insertion execute rebuilt source
in the new checker, including both original router call paths. **Older router,
worker and release checkers retain their documented models**; their previous
evidence is not broadened. The new fixture executes only fixed router routes;
heap-route coverage remains in the unchanged raw-free checker. Its unused heap
and lock linker bindings are not executed in this pool corpus.

Remaining limits: metadata allocation/recursive release, pool construction,
arbitrary malformed/cyclic/aliased lists, complete wrapped memory objects,
concurrency and complete resource-worker lifetimes. Original compiler/full ABI,
binary matching, G1/G2 live evidence, G3/provenance/transfer decisions and native
runtime gates remain open. Source and harness are project-authored from pinned
instructions and existing project tools; no external implementation was imported.

## Reproduce and next independent milestone

From `SMT4-decomp`, use fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_fixed_free.py --output local/validation/NEW-FIXED-FREE
python tools/check_resource_fixed_free.py --mutant equal-order --output local/validation/NEW-FIXED-NEGATIVE
python tools/check_resource_free_raw.py --output local/validation/NEW-ROUTER-REGRESSION
python tools/check_resource_release.py --output local/validation/NEW-RELEASE-REGRESSION
python -m unittest discover -s tests
```

Next recover **fixed-pool allocation `0x00144978`**, using the now-recovered
insertion `0x002C3928` and free `0x00138354` to validate allocation-produced pool
lifetimes. Its existing saved listing and pseudocode are in
`local/validation/allocate-raw-20261007-inspect/exports/`; verify the body through
`0x00144AB0` and literal at `0x00144AB4` before implementation. It is the modeled
fixed-allocation dependency of recovered raw allocator `0x002B26F0`.

The saved instructions show first-fit comparison **before** 128-byte rounding,
an exact-record transfer or a split requiring a 16-byte metadata allocation via
`0x002C5544(0x100,0x100,0,0x10,1)`, used-list insertion, wrapping accounting and
zero on no fit. Check unrounded-fit/rounded-overrun and arithmetic wrap explicitly;
do not silently impose alignment invariants. Initially keep metadata allocation
and recursive release explicit models, then integrate both fixed allocation/free
routes and persistent reuse where the domain permits. This evidenced source
dependency takes priority over tooling-only retained-worker integration. That
integration, construction and synchronization remain subsequent work. No source
for this next target was implemented in this package.
