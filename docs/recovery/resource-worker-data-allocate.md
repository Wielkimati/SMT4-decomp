# Worker data allocation and metadata lifetime

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry **`0x002BF7EC`** is recovered in
[`src/resource_worker_data_allocate.c`](../../src/resource_worker_data_allocate.c).
This adds **one bounded source contract**, bringing recovery to **52 entry points
plus two adapted worker regions**. Existing allocation/registration/conversion
integration adds no new entry contracts.

The subsequent [object-allocation package](resource-worker-object-allocate.md)
executes this data source inside bounded worker I/O through the optional
`--recover-allocation` mode. Its raw allocation/registration boundary is shallower
than this report's standalone connected mode. Both corpora remain separately
reproducible; neither broadens older retained-worker modes.

## Strategic review and acceptance

The fixed-pool allocation milestone is complete. Before implementation, its
recorded source and evidence hashes, binary and comparison object were checked
against disk: `local/validation/worker-data-20261008-audit/handoff-check.json`.
This
follows A07/G2 source/build/comparison requirements and the newer source-recovery
priority; the older inner-heap target is already complete. Optional extraction,
compiler research and live gates do not block it.

Acceptance set before implementation: instruction-backed six-word interface,
unsigned minimum alignment, full-width request sizing versus low-16-bit user
placement, metadata/backlink, registration/clearing order, lock reloads,
warning-clean ARM build and controlled original/rebuilt/oracle comparisons.
Connect existing raw allocation, registration and conversion where fixtures
support them; retain explicit storage and service models. Check wrapping and
unusual alignment boundaries, reject compiled faults and run affected checks.

## Instruction-derived contract

The body is `[0x002BF7EC,0x002BF8AC)`: **48 ARM instructions**, with a literal
`0x00465120` at `0x002BF8AC`. Saved Ghidra bytes in
`local/validation/allocate-raw-20261007-inspect/exports/listing.txt`, pinned image
bytes and independent GNU disassembly agree. The static audit is
`local/validation/worker-data-20261008-audit/static-audit.json`; the positive run
also exports the current Ghidra listing.

The six input words are `(first, second, third, size, alignment, direction)`.
The previous worker declaration called the second word alignment, but the actual
alignment input here is the **fifth stack word**; the second is forwarded to the
raw router as its route option. Renaming declaration parameters changes no ABI.

1. Acquire the handle read from allocator state `0x00465124`.
2. Set `A = max_unsigned(alignment, 128)`. Compute raw request
   `R = (size + A + A + 59) & (0 - A)`, modulo u32. The full input width participates
   in this expression. No power-of-two validation is performed.
3. Call `0x002B26F0(first, second, third, R, direction)`. There is **no bypass**
   for `0x20000/0x30000` and **no null-result guard** at this entry.
4. At nonnull raw address `P`, store `R` at `+0`, `A mod 65536` as a halfword at
   `+4`, and zero as a halfword at `+6`.
5. Let `L = A mod 65536`, `M = L - 1` modulo u32, and
   `padding = (L - ((P + 60) & M)) & M`. Return address is
   `U = P + 60 + padding` modulo u32. Store `P` at `U - 4`.
6. Register `P` through `0x002B260C`, clear the **original requested size** at
   `U` through `0x002C3B9C`, reload/release the state handle through `0x002C3A78`,
   and return `U`. Registration and zero return values are ignored.

For ordinary power-of-two alignments, user placement is a ceiling operation.
For other inputs it remains the instruction's bit-mask calculation, not generic
division-based rounding. The minimum is not reapplied after truncation: e.g.
`0x10001` consumes low alignment 1. When `L == 0`, `M == 0xFFFFFFFF` and `U == 0`
even with nonnull `P`; the backlink store is at `0xFFFFFFFC`. Those direct probes
map both the backlink and zero-page storage explicitly. They demonstrate bounded
instruction behavior, not a usable allocation or supported live memory mapping.

The C source requires original 32-bit addresses and valid writable, word-aligned
raw/header/backlink storage. Tested raw results are nonnull and do not cross the
u32 address-space boundary. Selected unusual alignments retain word-aligned
backlinks; arbitrary unaligned stores, top-of-space raw extents and aliasing with
allocator globals are outside the validated domain. Null raw results have static
evidence only; no safe failure behavior is inferred. GCC reorders header stores;
byte state at dependency boundaries agrees, not every intermediate store width
or ordering observed concurrently. Original `d8` preservation is checked.

## Build and controlled comparison

Primary evidence: `local/validation/worker-data-20261008-final2/COMPLETE.json`.
Pinned GCC builds freestanding C11 with `-O2 -march=armv6k -marm
-mfloat-abi=soft`, warnings as errors and no runtime/SDK libraries. The image is
**1,016 bytes**: 992 text bytes and 24 bytes of raw-router constant data. The new
wrapper occupies **184 bytes** including its literal. The rebuilt path executes
only rebuilt code; original game instructions are not reused as helpers.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle allocations | 2,864 |
| Direct probes with raw/registration models | 2,144 |
| Allocations using recovered raw routing/registration/selector | 720 |
| Subsequent recovered release conversions | 720 |
| Allocations with actual modeled byte clearing | 1,970 |
| Wrapping request-size sums | 804 |
| Low-16-bit zero alignment probes | 180 |
| Non-power-of-two effective alignment probes | 1,080 |
| New instruction addresses visited | All 48 |
| Total original addresses visited in connected unit | 288 |
| Modeled service calls across both paths | 28,640 |
| Maximum instructions in one entry call | 226 |

Direct probes cover alignment minimum neighbors; powers of two through 32768;
nonpowers 129/132/192/384; 16-bit truncation boundaries and high-bit alignments;
zero, ordinary and high-bit sizes; per-alignment size-addition wrap boundaries;
every word-aligned residue modulo 256 with low/high-bit raw storage; all six-word
forwarding positions consumed by the raw call; and exact fixed selectors that
must still receive metadata and zeroing here. The oracle uses independent
bit-by-bit selection, cross-checked with division for power-of-two cases.

Six lock-effect profiles preserve or replace the global handle on acquire, raw
storage provision, modeled registration, clearing, or every preceding service.
Models poison volatile integer/VFP registers and flags. Calls check stack
alignment, argument order, caller stack, callee-saved registers, `d8`, stack
restoration/guards, allowed accesses and initialized memory. Random guarded
regions are compared against independent expected bytes at every dependency
boundary and final return. Modeled registration mutates other header fields to
check their preservation. Zeroing writes memory only for sizes at most 1,024;
larger sizes check marshaling/order only. Overflow probes make no capacity claim.

## Connected dependency boundary

The 720 integrated cases execute original/rebuilt versions of raw router
`0x002B26F0`, registration `0x002B260C`, selector `0x002B3340` and conversion
`0x001245F0`. They cover both heap routes and both fixed routes, all four heap
range selections, 128/256/4096 alignment, zero/nonzero requested bytes, both raw
directions, raw route options, tags 0/7/8/0x100/0xFF08, wrapping global/per-heap
accounting, empty/nonempty registration lists and cursor clearing. The appended
allocation is converted from its **actual retained backlink/tag/list bytes**,
restoring accounting and removing a sole node or tail. Existing-header/cursor
fixtures are synthetic; this is not arbitrary list removal coverage.

Models removed **in this connected checker**: worker data wrapper, raw router,
registration, heap selector and conversion. Only the wrapper is newly recovered.
Actual raw storage is supplied at `0x002C3A98` (heap wrapper) or `0x00144978`
(fixed allocation), both still intercepted in this checker despite their separate
recovery. Recursive locks and byte zeroing remain service models. This is a
metadata lifetime through conversion, not a storage free/reuse lifetime. Older
worker/registry modes still intercept worker data allocation; their historical
evidence is not broadened by this package.

## Validation and limitations

Development runs exposed harness defects, not a source disagreement: undersized
copied callee extents; a generic initialization routine that cleared allocation
bytes between allocation and conversion; and omission of the router's `.rodata`
from the copied build recipe. The final harness uses the established callee
extents, resets only registers/stack between calls, and includes/checks separate
text and constant-data extents. The source was unchanged through those fixes.
No oracle result or semantic assertion was weakened to pass them.

Fault checks and affected regression results are indexed in
`local/validation/worker-data-20261008-audit/COMPLETE.json`.
Eight independently compiled faults are rejected: signed minimum comparison,
truncation before request sizing, off-by-one overhead, full-width user mask,
forwarding alignment in place of direction, misplaced backlink, clearing raw
rather than requested size, and releasing a cached lock. The first forwarding
variant failed compilation because its intentionally ignored parameter triggered
`-Werror`; that is **not** counted as a semantic rejection. The corrected variant
explicitly consumes the ignored word and is rejected by the raw-argument check.
The subsequent final positive run has identical binary/comparison results.

The affected worker-I/O regression passes all 3,456 comparisons and retains the
548-byte binary hash and complete comparison object from
`local/validation/worker-io-20261007-dev2/COMPLETE.json`. It continues to model both
allocation wrappers. All **134 public tests** pass. Exact commands/logs and
regression equality are under the audit directory. Full original ABI,
matching, arbitrary reentrancy/aliasing, null raw failures, construction,
synchronization, complete worker/storage lifetimes, and G1/G2 live evidence stay
open. Provenance is project-authored recovery from the pinned original image;
no external implementation was incorporated. No port implementation or source
transfer is claimed.

## Reproduce and next independent milestone

Run from `SMT4-decomp`, using fresh output directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_data_allocate.py --output local/validation/NEW-WORKER-DATA
python tools/check_resource_worker_data_allocate.py --mutant early-truncate --output local/validation/NEW-WORKER-DATA-NEGATIVE
python tools/check_resource_worker_io.py --output local/validation/NEW-WORKER-IO-REGRESSION
python -m unittest discover -s tests
```

Next recover the worker's **file-object allocation wrapper `0x002C244C`**, and
batch its caller integration with this data wrapper in the state-zero I/O region.
Independent pinned GNU inspection saved as
`local/validation/worker-data-20261008-audit/next-object-boundary.log` shows the
13-instruction body through `0x002C247C`, literal `0x00409B24` at `0x002C2480`,
and call `0x002C5544(0x100,0x100,0,size,1)`. Verify the Ghidra function boundary,
no-op diagnostic setup and return forwarding before implementing it. Reuse
`src/resource_allocate_lower.c`, the new data wrapper and
`tools/check_resource_worker_io.py` / `CompareResourceWorkerIo.java`. Add a bounded
connected worker mode with nonnull object/data storage and actual metadata;
preserve the broader legacy modeled corpus. Keep lower file/conversion/OS calls,
storage provisioning and locks explicit. This adds a named source contract and
removes both worker allocation interceptions in the new mode; it does not require
speculative `0x002C34F8` recovery or optional extraction/compiler work.
