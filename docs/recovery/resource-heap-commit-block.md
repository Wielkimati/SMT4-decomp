# Resource heap selected-block mutation

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry **`0x0014F608`**, instruction exclusive end **`0x0014F7E4`**, is
recovered in [`src/resource_heap_commit_block.c`](../../src/resource_heap_commit_block.c).
This adds one bounded entry contract: **45 plus two adapted worker regions**.

## Strategic review and acceptance

The preceding selection milestone is complete. Its 532-byte build, 23,616-case
marker and unchanged source/tool identities were checked against disk in
`local/validation/heap-commit-20261008-audit/handoff-check.json` (the shared header
comment is updated by this package). It removes
the sole modeled callee in the new selection path, rather than repeating selection
or returning to optional extraction. The A07/G2 source/comparison criteria apply;
deferred live gates and independent G3 blockers remain unchanged.

Acceptance: reconstruct the five-word contract at `0x0014F608`, cross-check the
saved boundary and instructions, build ARM source, and compare original/rebuilt
return, memory and accesses for free-list removal/insertion, prefix/suffix
thresholds, direction/configuration effects, metadata and clearing. Execute
recovered selection/wrapper/setters with real mutation on valid backed arenas,
including repeated allocations and no-fit returns. Reject meaningful compiled
faults, preserve the older modeled arithmetic corpus, and run affected checks.
All these bounded criteria pass. This is not a complete allocator lifetime.

## Instruction-derived contract

Inputs are `(lists, block, payload, rounded_size, reverse)`; `reverse` is the
fifth argument, at entry SP. `lists` is subobject+0x24, or heap+0x3C. All address and size
calculations are u32, with no added validity/overflow guards. The routine always
returns `payload`. It makes no lower calls.

| Relative location | Consumed behavior |
| --- | --- |
| lists-4, u32 | Bit 0 enables clearing of the allocated extent |
| lists+0 / +4, u32 | Free-list head / tail |
| lists+8 / +12, u32 | Used-list head / tail |
| lists+16, u16 | Low byte copied into allocated metadata |
| lists+20, u8 | Nonzero permits the direction-sensitive remainder split |
| node+0, u16 | Fragment tag `0x4652`, allocated tag `0x5544` |
| node+2, u16 | Bits 8–14 encode absorbed prefix distance; bit 15 receives direction bit 0; low byte receives group |
| node+4, u32 | Capacity after the 16-byte header |
| node+8 / +12, u32 | Previous / next links |

1. Capture capacity, metadata and links of the selected block. Its physical
   origin is `block - ((metadata >> 8) & 0x7F)`; its end is
   `block + 16 + capacity`. Unlink it from the free list, updating neighbors or
   the corresponding head/tail.
2. The new allocated header is `payload-16`. A prefix of at least **20 bytes**
   becomes a free fragment when `reverse != 0` or the byte at lists+20 is nonzero.
   Insert it at the removed block's position. Otherwise absorb the prefix into
   the allocation, retaining its physical origin for clearing and metadata.
3. A suffix of at least **20 bytes**, from `payload+rounded_size` to the original
   end, becomes a free fragment when `reverse != 1` or the same byte is nonzero.
   Insert after the prefix when one was created, otherwise at the removed
   position. Otherwise extend the allocation to the old end. Every free
   fragment has a 16-byte header and capacity `extent-16`.
4. Read the word at lists-4. When bit 0 is set, clear whole words over the
   allocated physical extent: from absorbed origin or allocated header through
   allocated end. The assembly writes `floor(extent/4)` words, in increasing
   address order; it has no byte-tail loop. This includes absorbed padding and
   header storage, not just requested payload. The validated arenas use
   word-aligned extents.
5. Write the allocated tag and capacity, initialize both link words, and write
   metadata as a halfword twice: first direction/7-bit prefix distance, then
   the low byte of the halfword read at lists+16. Append the header after the
   current used tail. Preserve the original insertion reads/writes, including
   reading the tail's next pointer rather than assuming it is zero.

The three wrapper setters now have bounded consumer meanings: fourth supplies
the low-byte allocation group, fifth bit 0 selects first/smallest-fit, and sixth
byte controls direction-sensitive splitting. Other meanings are not inferred.
The previously recovered setter sources remain unchanged.

Read-only inspection is `local/validation/heap-commit-20261008-inspect/exports/`.
The saved function body is `[0x0014F608,0x0014F7E3]`; calls are saved at
`0x00146B80` and `0x00146C10`. This is not complete caller discovery. The literals
at `0x0014F7E4/+4` are data. All 119 instructions agree byte-for-byte among GNU
objdump, saved Ghidra and the pinned image. The combined static audit checks 242
instructions, including selector/wrapper/setters, and confirms the previous
package's commit disassembly is identical. See
`local/validation/heap-commit-20261008-audit/static-audit.json`.

## Source, build and behavior evidence

Primary marker:
`local/validation/heap-commit-20261008-direct-integrated-r2/COMPLETE.json`.
Pinned GCC builds **1,120 text bytes**: 588 for mutation and its internal fragment
helper, plus the unchanged 532-byte selection/wrapper/setter unit. This is C11,
ARMv6K ARM mode, freestanding soft-float, warnings as errors, without SDK or
external linker bindings. Rebuilt execution stays within rebuilt text; no
original helper or modeled call executes. It is behavioral recovery, not
binary matching or a reconstructed application.

| Observation | Result |
| --- | ---: |
| Original/rebuilt/oracle calls | 10,761 |
| Direct mutation / integrated wrapper calls | 6,153 / 4,608 |
| Persistent arena scenarios, six calls each | 768 |
| No-fit returns | 2,536 |
| Prefix / suffix fragments | 4,577 / 3,005 |
| Nonempty absorbed prefixes / suffixes | 2,790 / 3,844 |
| Cleared allocations / words | 4,117 / 60,510 |
| Wrapper counter wraps | 480 |
| Successful later calls in retained arenas | 1,592 |
| Original instruction addresses visited | 242 (119 mutation) |
| Maximum instructions per invocation | 347 |

The direct grid covers ordinary/high-bit addresses; singleton, head, tail and
interior free-list removal; empty and two-node used lists; both directions;
split byte zero/nonzero (including high-bit byte values); clearing bit 0 versus
unrelated bits; requested sizes 4/8/12/32; backed prefix gaps through 132 bytes;
old 7-bit offsets 0/4/124; and suffix extents 0/4/16/20/24/64. Nine additional
direct probes supply nonboolean direction words with three old offsets.
These offset/nonboolean probes are bounded storage observations, not proof of
reachability from a game-created heap. Suppressed large prefixes demonstrate
7-bit truncation without claiming they can subsequently be freed losslessly.

Integrated scenarios initialize sorted free lists with unequal/equal capacities,
small blocks or empty lists. Alignments are positive/negative powers of two
4–128; both selection policies, splitting options, clearing options and address
patterns execute. Six requests `(0,17,4,64,1,4096)` share the same machine memory
per scenario. Setters execute on every invocation with varying group words;
counter starts at `0xFFFFFFFF`. The terminal large request and exhausted lists
test no-fit behavior without dereferencing synthetic large arenas. This is
retained **arena** integration, not the older retained resource-worker mode.

The byte-oriented oracle replaces the selected free-list element with residual
intervals, appends the allocated header to its independent used-node sequence,
and rebuilds links. It predicts all header/arena bytes and returns independently
of the implementation's ordered access algorithm. Both machines are checked
against it after every call. Their ordered external read/store traces must also
match, including access widths and repeated metadata writes. Two guarded regions
(128-byte header and 6-KiB arena), seeded unrelated bytes, untouched caller stack,
256-byte stack scratch boundary, SP, r4–r11 and d8–d15 are checked. Unexpected
addresses, uninitialized reads, execution outside allowed text and instruction
budget violations fail. Instruction visitation does not prove every predication
outcome. In particular, the used-tail next pointer is zero in consistent lists.

The first driver run built source successfully but failed Java compilation due
to a counter name shadowing an inherited list. The harness qualification was
fixed, and the driver's expected direct-case count corrected before the first
executed comparison. The `r2` comparison passed with the original source;
no source correction or weakened assertion followed a behavior failure.

## Checks and scope

Seven independently compiled faults are rejected: `prefix-threshold`,
`suffix-threshold`, `direction`, `clear-bit`, `offset-mask`, `metadata-width`,
and `used-tail`. Each `local/validation/heap-commit-20261008-negative-*/NEGATIVE.json`
records its built binary hash and actual comparison assertion. Compiler failures
are not accepted as fault detection.

The existing selection checker passes its unchanged 23,616-case corpus with
identical binary hash and comparison object:
`local/validation/heap-commit-20261008-selection-regression/COMPLETE.json`.
Its broader arithmetic probes still model `0x0014F608`; they are not silently
converted into backed arena claims. All 134 public tests pass. The package audit
marker is `local/validation/heap-commit-20261008-audit/COMPLETE.json`, with sequential
commands in `checks.json`, regression identity in `regression-audit.json`, and
test output in `public-tests.log`. The new private harness provides source evidence;
no public-interface implementation changed beyond a header comment.

Only mutation adds a recovered contract. The driver, oracle, fixture and linked
caller integration are supporting work. Earlier wrapper/worker checker modes
retain their documented models; this package does not broaden them. Invalid or
cyclic lists, arbitrary aliasing, unaligned backing, concurrent mutation, arbitrary
overflowing complete arenas, free/coalescing and heap construction/lifetime remain
outside this evidence. The source retains unsigned arithmetic without new guards.

Code and harness are project-authored from the pinned instructions and existing
project infrastructure; no external implementation was imported. Live
G1/G2 evidence, original compiler/full ABI, matching, provenance/transfer decisions
and G3 remain open. No native-port implementation or live session is included.

## Reproduce and next milestone

Run from `SMT4-decomp` with fresh output directories, sequentially for Ghidra:

```powershell
python tools/check_resource_heap_commit_block.py --output local/validation/NEW-COMMIT
python tools/check_resource_heap_commit_block.py --mutant prefix-threshold --output local/validation/NEW-COMMIT-NEGATIVE
python tools/check_resource_heap_allocate_inner.py --output local/validation/NEW-SELECTION-REGRESSION
python -m unittest discover -s tests
```

Next recover **free/coalescing `0x0014699C` together with its counter wrapper
`0x002B33D8`**. The bounded GNU leads in this package's audit directory are
`heap-free-inner-lead.log` and `heap-free-wrapper-lead.log`. The inner range ends
at return `0x00146AD0`, followed by literal `0x00146AD4`; the eight-instruction
wrapper calls it with heap+0x18 and decrements heap+0x54 afterward. These are
static leads only, not verified source or runtime contracts. Check saved-project
boundaries and exact return/width behavior before implementation. Reuse valid
allocation-produced arenas to compare used-list unlink, address-ordered insertion,
neither/left/right/both-neighbor coalescing, restored free metadata and wrapping
counter decrement. Include allocate/free/reallocate sequences and meaningful
faults. Keep the current allocation comparisons and wider modeled selection corpus.

Outer raw-free routing `0x001244E8` is separately evidenced in
`free-router-lead.log`: it calls `0x002B33D8` under locks for two heap ranges and
routes two other ranges to `0x00138354`. Recover it later if it unblocks retained
resource-worker integration. A preliminary window named `inner-free-lead.log`
at `0x00146C20` actually shows recursive heap lookup, not free; do not select a
callee by address adjacency. No additional target was implemented in this package.
