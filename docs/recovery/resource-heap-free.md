# Resource heap free and coalescing

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entries **`0x0014699C`** and **`0x002B33D8`** are recovered in
[`src/resource_heap_free.c`](../../src/resource_heap_free.c). They add two bounded
entry contracts: **47 plus two adapted worker regions**. The counter wrapper is
named `smt4_resource_heap_free_counted`; the existing `smt4_resource_heap_free`
declaration belongs to the still-modeled outer router at `0x001244E8`.

## Strategic review and acceptance

The previous mutation milestone is complete. Its eight recorded file hashes,
primary comparison object and 1,120-byte binary hash agree with disk; see
`local/validation/heap-free-20261008-audit/handoff-check.json`. This is the
useful next A07 source milestone under G2's bounded comparison criteria: it extends
real allocation arenas through release and reuse. No extraction/compiler detour is needed.

Acceptance: instruction-backed source for used-list unlink, ordered free-list
insertion, right/left/both/neither coalescing and counter decrement; warning-clean
ARM build; original/rebuilt/oracle return and complete guarded-state agreement;
ordered external access agreement; persistent allocation/free/reallocation;
counter wrap, minimum extent, fault rejection and affected regressions. These are
bounded allocator operations, not heap construction, worker integration, a G2 live
gate closure or a complete game allocator.

## Instruction-derived contracts

Saved bodies are `[0x0014699C,0x00146AD3]` (78 ARM instructions) and
`[0x002B33D8,0x002B33F7]` (eight). The free tag literal at `0x00146AD4` is data.
All 86 instruction bytes match the saved Ghidra listing, GNU ARM disassembly and
the pinned image in `local/validation/heap-free-20261008-audit/static-audit.json`.
Read-only saved-project exports and decompiler leads are in
`local/validation/heap-free-20261008-inspect/exports/`. Saved references include
the inner call at `0x002B33E4` and outer-router calls at `0x0012452C/0x00124570`;
this is not complete caller discovery.

The inner inputs are `(subobject, payload)`, with `subobject=heap+0x18` and list
roots at `subobject+0x24`. Addresses, extents and counts use modulo-u32 arithmetic.
The list/node fields are the same as the [allocation mutation contract](resource-heap-commit-block.md).

1. Set `node=payload-16`. Read its metadata halfword and capacity word. Its
   physical extent is `[node-((metadata>>8)&0x7F), payload+capacity)`; direction
   bit 15 and the low group byte do not contribute to the offset.
2. Read the previous and next used-node links. Unlink through neighboring nodes,
   or update the used head/tail at list roots+8/+12. The old allocated header is
   not cleared, and neither tag nor pointer validity is checked.
3. Scan the free list forward by **unsigned address order**, retaining the last
   node below the physical origin. Stop at the first node at/above it, or null.
4. If the extent ends exactly at the right node, extend to that node's end and
   unlink it. Then, if the retained left node ends exactly at the origin, move
   the origin to that node, unlink it, and use its previous link as the new
   insertion predecessor. The right merge happens first. Only these immediate
   neighbors are considered; this is not an arbitrary repeated coalescing pass.
5. When the unsigned resulting extent is at least **16**, write halfword tag
   `0x4652`, zero metadata halfword and capacity `extent-16`. Store predecessor
   and zero next link, then insert after the predecessor (or at the head), using
   the current list links. Update the successor or tail. The original retains
   the `<16` skip path without validation errors; valid backed lifetimes here
   never take it. Source preserves that guard.
6. Original r0 contains the insertion predecessor on return. The source explicitly
   preserves this observed register value; its meaning as a consumed return and
   the original C return type are unknown. Decompiler `void` is not type proof.

The counted wrapper forwards `(heap+0x18,payload)` exactly once, then loads
`heap+0x54`, subtracts one modulo u32, writes it back and leaves that count in r0.
There is no null, tag or zero-counter guard. No allocation payload is cleared
during free, regardless of the allocation-clearing configuration.

## Build and controlled evidence

Primary marker:
`local/validation/heap-free-20261008-lifetimes-r2/COMPLETE.json`.
The pinned GCC build produces **1,568 text bytes**: 416 for inner free, 32 for its
wrapper, and the unchanged 1,120-byte allocation unit. Flags are C11, `-O2`,
ARMv6K ARM mode, freestanding soft-float, warnings as errors, no SDK/runtime
libraries and no external linker bindings. The rebuilt path executes only rebuilt
text, with **zero intercepted calls**. This is behavioral recovery, not binary
matching or a reconstructed application.

| Observation | Result |
| --- | ---: |
| Original/rebuilt/oracle calls | 7,496 |
| Allocation calls, including four direct zero-size commits | 4,036 |
| Direct inner free / counted wrapper free | 866 / 2,594 |
| Persistent arena scenarios | 576 |
| Neither / left / right / both merges | 1,260 / 532 / 580 / 1,088 |
| Used singleton / head / tail / middle removal | 1,156 / 1,248 / 672 / 384 |
| Reallocations / allocation failures | 1,152 / 576 |
| Counter underflows / 16-byte extents | 2 / 4 |
| Original instruction addresses visited | 328, including all 86 new addresses |
| External reads / writes, both paths | 206,668 / 604,676 |
| Maximum instructions per call | 1,705 |

The lifetime grid uses two address patterns (ordinary and high bit), alignment
magnitudes 4/32/128 with both signs, both selection policies, both split settings,
both clearing settings and six free orders. One 2,048-byte-capacity region is
seeded; half the scenarios include a separate 96-byte region. Initial free lists
and option storage are synthetic construction fixtures. Every freed header is
created by actual original/rebuilt allocation instructions, independently predicted
by the existing byte oracle. No free metadata or return is supplied by a call model.

Each scenario allocates sizes 20/33/4/73, rejects an 8,192-byte request, frees three
selected allocations, reallocates 49 bytes, drains the two live allocations, then
allocates and frees the entire restored 2,048-byte region. Successful reuse and
restoration are asserted. Direct and counted frees share persistent memory;
initial counters rotate through zero, `0xFFFFFFFF` and `0x80000000`. Only counted
frees decrement. Four additional probes use actual direct commit instructions to
produce a 16-byte allocation with rounded size zero, then free it through each
entry at both address patterns. This is a bounded arithmetic boundary, not a
claim that normal gameplay requests zero rounded capacity.

The free oracle derives intervals and ordered node sequences, removes members,
relinks surviving nodes, and predicts the resulting bytes. It preserves obsolete
header bytes as well as payload/guards. Both machines agree independently with
this oracle after every call, and their ordered external read/write traces agree,
including access widths and intermediate link/metadata writes. The existing
guarded 128-byte header, 6-KiB arena, caller stack, 256-byte stack scratch limit,
SP, r4-r11 and d8-d15 checks remain. The free wrapper's inner argument and stack
alignment are checked at entry. Unexpected execution, out-of-arena accesses,
uninitialized reads and instruction-budget excess fail.

The first build attempt encountered a name collision with the existing outer
router declaration. Renaming this new wrapper to `smt4_resource_heap_free_counted`
resolved it without changing existing interfaces. The next build and first
executed comparison passed. No recovered behavior or oracle assertion was
changed after a behavioral mismatch.

## Validation and limits

Seven separately compiled faults are rejected: offset mask includes direction,
missed right merge, missed left merge, wrong used-list root, wrong metadata store
width, increment instead of decrement, and rejecting a 16-byte extent. Markers
are `local/validation/heap-free-20261008-negative-*/NEGATIVE.json`; every rejection
requires a successful build and a comparison assertion, not a compile failure.

The affected allocation regression passes at
`local/validation/heap-free-20261008-allocation-regression/COMPLETE.json` with its
original 10,761 calls, identical binary hash and identical comparison object.
Its source and harness are unchanged. This package's shared header additions
therefore preserve the linked allocation unit. The wider modeled selection
checker was unchanged and was not rerun; its existing evidence remains scoped to
its arithmetic-only domain. All **134 public tests pass**. Exact commands, static
audit, regression identity and test logs are indexed by
`local/validation/heap-free-20261008-audit/COMPLETE.json`.

Only the two source entries are new recovered contracts. Caller integration,
oracle, build driver and symbol/report maintenance add no contracts. The new
checker uses real allocation and free code throughout; older resource-worker and
release modes retain their explicit free, allocation and synchronization models.
This does not claim model removal in those older modes.

Unsupported evidence domains remain invalid/double/null free, cyclic lists,
arbitrary aliasing, unaligned headers, wrapping complete arenas, extent below 16,
concurrency, heap construction/destruction and resource-worker service lifetimes.
Source adds no defensive semantics for those inputs. Instruction visitation does
not prove every predication outcome. Original return types/consumers, full ABI,
compiler identity and matching remain unresolved. G1/G2 live evidence, G3,
provenance/transfer decisions and all native runtime gates remain open.

Code is project-authored from the pinned instructions and existing project
harnesses. No external implementation was imported.

## Reproduce and next independent milestone

From `SMT4-decomp`, use fresh ignored outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_heap_free.py --output local/validation/NEW-FREE
python tools/check_resource_heap_free.py --mutant right-merge --output local/validation/NEW-FREE-NEGATIVE
python tools/check_resource_heap_commit_block.py --output local/validation/NEW-ALLOCATION-REGRESSION
python -m unittest discover -s tests
```

Next recover **outer raw-free routing `0x001244E8`**, already declared as
`smt4_resource_heap_free` in `src/resource_release.h`. Check saved boundaries
against `local/validation/heap-commit-20261008-audit/free-router-lead.log` before
implementation. The lead shows two ordered half-open ranges dispatched through
locks `0x002C3AFC/0x002C3A78` to the now-recovered `0x002B33D8`, and two further
ranges tail-dispatched to `0x00138354` with fixed pool objects `0x004E4100/1C`.
Compare range boundaries, overlap priority, u32 end arithmetic, unmatched return,
captured object/lock behavior and exact consumed calls. Reuse the raw allocation
router's state fixtures and this package's arenas for the two heap routes; keep
fixed-pool free and locks explicitly modeled unless evidence makes a small
connected recovery necessary. Then evaluate replacing the older worker's raw-free
model with arena-backed lifetime integration. Do not select the adjacent recursive
heap lookup at `0x00146C20` as a free callee. No new recovery target was implemented
after completing this package.
