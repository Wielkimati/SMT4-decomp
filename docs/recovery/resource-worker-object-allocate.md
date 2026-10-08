# Worker file-object allocation and connected I/O

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry **`0x002C244C`** is recovered in
[`src/resource_worker_object_allocate.c`](../../src/resource_worker_object_allocate.c).
This adds **one source contract**, bringing recovery to **53 bounded entry points
plus two adapted worker regions**. The caller integration reuses the existing
I/O, aligned-allocation and data-allocation sources; it adds no entry contracts.

The subsequent [file-method package](resource-worker-file-methods.md) executes
the three evidenced virtual adapters through `--recover-file-methods`, preserving
this allocation corpus and its metadata checks.

## Strategic review and acceptance

The previous source identities, binary hash and
full comparison object were verified against files; the new header comment was
removed in memory for the old header identity check. Evidence is
`local/validation/worker-object-20261008-audit/handoff-check.json`.
This package
advances A07's source/build/comparison work without repeating that target or
optional preparation. G1/G2 live gates and G3 provenance/ABI gates remain open.

Acceptance was set before implementation: verify original function extent,
diagnostic NOP, exact five-word forwarding and return behavior; build ARM source;
execute both worker allocation wrappers in bounded state-zero I/O comparisons
with retained header/backlink/payload bytes; preserve the broader modeled
regression; reject meaningful source faults. Storage and service models must
remain explicit.

## Original contract and evidence

The function is `[0x002C244C,0x002C2480)`: **13 ARM instructions**. Ghidra's saved
function ends at `0x002C247F`, agreeing with the pinned GNU disassembly. The word
at `0x002C2480` is literal `0x00409B24`. The first instructions preserve input
`r0`, load that literal and set `r1=0xAC`, then execute `MOV r0,r0` at
`0x002C245C`. There is no diagnostic call at that site. Those temporary arguments
are overwritten before the only call, `0x002C5544`.

The recovered contract is:

```c
return smt4_resource_allocate_lower(0x100, 0x100, 0, bytes, 1);
```

The original forwards all 32 size bits in `r3`, places direction 1 on the stack,
and forwards the callee's `r0` unchanged. It neither clears again nor checks the
result. The direct wrapper probes model the lower callee, including zero and
high-bit return values; they do **not** demonstrate successful null handling by
the actual lower allocator. The connected mode executes that lower source with
nonnull writable raw storage. Original source provenance is project-authored
recovery from the pinned executable; no external implementation was reused.

Static evidence is `local/validation/worker-object-20261008-audit/static-audit.json`.
The final comparison exports `original-object-ghidra.txt` and independent
`original-object-disassembly.log`; all 13 new instruction addresses execute.

## Build and connected behavioral evidence

Primary record: `local/validation/worker-object-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K build is **956 bytes**, including
**44 bytes** for the new wrapper. It links the existing worker region,
`resource_allocate_lower.c` and `resource_worker_data_allocate.c`. No original
instructions are reused on the rebuilt path. GCC is the behavioral toolchain;
binary matching and a full original-target build are not claimed.

| Check | Result |
| --- | ---: |
| Connected original/rebuilt/oracle I/O cases | 2,304 |
| Direct original/rebuilt object-wrapper cases | 48 |
| Executed allocations, both paths | 6,912 |
| Original instruction addresses visited in the unit | 269 |
| New object-wrapper addresses visited | All 13 |
| Maximum allocator instructions per call | 58 |
| Maximum enclosing I/O instructions, excluding allocator steps | 2,037 |
| Recorded dependency calls, both paths | 283,392 |

Each connected case executes object allocation and construction, path conversion,
open, size/seek, optional data allocation, locked read, close and optional
destruction, stopping at the existing region boundary `0x00114070`. Object
allocation requests 24 bytes; data allocation runs only for a zero descriptor
data pointer. The alternative supplied buffer is mapped and retains its
preexisting bytes until the modeled read. The actual allocation-produced
metadata survives the rest of the region; the destructor model does not free it.

The corpus crosses both signs of open/read results, six handle patterns,
eight exact/decoy worker flags, supplied versus allocated buffers and six path
profiles (including empty/120-unit paths and conversion failures). File sizes
rotate through 0, 1, 68, 69, 127, 128, 129 and 801. Requested alignments rotate
through 0, 127, 128, 256, 512 and 4096. Object and data raw locations exercise
all 32 word-aligned residues modulo 128. User pointers remain fixed, nonnull,
aligned and backed by guarded synthetic storage. Full-width arithmetic and
unusual alignment coverage remain in the preceding data-allocation checker.

The direct wrapper corpus crosses sizes 0, 1, 23, 24, 25, 127, 128, 255, 256,
`0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFF` with lower results 0, the object address,
`0x80000000` and `0xFFFFFFFF`. It checks exact argument placement, one lower call,
return forwarding, stack guards/restoration and callee-saved registers. These
direct cases allocate no actual payload.

Allocation oracles use division-based rounding, compare complete guarded
regions at every dependency boundary and check header size/alignment/zero tag,
backlink, requested-size clearing and return address. The registration model
writes another header word, which subsequent source must preserve. Every
allocator service changes the shared lock handle, testing reloads; dependency
returns poison volatile integer registers and flags. Original VFP preservation
has prior standalone data/lower evidence and is not a new expanded ABI claim.
The modeled read writes a deterministic bounded payload; all bytes and metadata
are compared afterward. It retains the old deliberately inconsistent returned
read-count fixture, confirming that the worker keeps the requested size.
Complete descriptor/object oracles, state-store order, dependency snapshots,
construction adjustment, path terminators, busy flags, close reloads and stack
guards remain enforced by the existing I/O harness.

## Models removed, retained boundaries and regression

In the **new `--recover-allocation` mode**, object allocation `0x002C244C`, aligned
allocation `0x002C5544` and data allocation `0x002BF7EC` execute original/rebuilt
instructions instead of returning modeled user pointers. Only the first is
newly recovered source. Raw allocation `0x002B26F0`, registration `0x002B260C`,
zeroing and recursive locks are intercepted here, even though routing and
registration have separate recovered sources. Lower path/file calls, virtual
methods and destruction remain models. This is allocation-through-I/O metadata
retention, not allocator ownership, storage free/reuse or a full worker lifetime.
The previous data checker retains its deeper raw-routing/registration/conversion
mode; this new caller evidence does not replace or weaken it.

Fault and regression results are indexed in
`local/validation/worker-object-20261008-audit/COMPLETE.json`.
The legacy mode retains its entire original 3,456-case corpus, 548-byte binary
and comparison object. Its object/data allocation models are unchanged.
Source faults cover wrong object route, truncated size, wrong direction,
modified return pointer, displaced data backlink, non-exact worker flag tests
and cached close handles; **all seven compiled variants are rejected by semantic
assertions**. All **134 public tests pass**, separately from private ARM evidence.
An initial PowerShell invocation wrapped unittest's successful stderr output as
a shell error; the recorded native-subprocess rerun confirms return code zero.

The default source/harness paths remain compatible with older worker and registry
checks. The I/O source itself is unchanged; its shared header adds only the
object entry's provenance comment. Shared harness hooks are inactive by default.
The first development positive passed. The final positive followed small checker
cleanup and an explicit corpus-completeness assertion, with the same compiled
binary and comparison object. No behavioral assertion was weakened.

Null raw storage, arbitrary pointer aliases, general non-power-of-two alignments
in the caller, huge actual files, concurrency/reentrancy, lower file semantics,
construction, recursive metadata ownership, storage freeing and G1/G2 live
agreement remain open. No native port or native service replacement is claimed.

## Reproduce and next independent source package

From `SMT4-decomp`, with new output directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-allocation --output local/validation/NEW-WORKER-ALLOCATION
python tools/check_resource_worker_io.py --recover-allocation --mutant object-size --output local/validation/NEW-WORKER-ALLOCATION-NEGATIVE
python tools/check_resource_worker_io.py --output local/validation/NEW-WORKER-IO-REGRESSION
python -m unittest discover -s tests
```

Next recover the **worker's size, seek and read virtual adapters** and integrate
them with this caller. Pinned table bytes at `0x00420870` contain
`[0x004208B0,0x003FF29C,0x003FF29C,0x004208B0]`; the adjustment at
`0x004208B0-48` is zero. Vtable slots `+0x24`, `+0x0C`, `+0x28` point to
**`0x003DFC54`**, **`0x00354F70`**, **`0x00354F9C`** respectively. This gives
direct evidence of dependency relevance, not an adjacent-function guess.
Their GNU listings and commands are saved as `next-size-method*` and
`next-file-methods*` in the audit directory.

Verify the Ghidra extents, size's 64-bit `r0/r1` return (the worker consumes only
the low word), seek's 64-bit offset and fifth stack word, and read's `object+4`
tail forwarding. The lower targets are `0x002BB8EC`, `0x002ACA78` and
`0x002BB864`; negative-result diagnostic handling calls/tails to `0x002BBD70`
and needs an explicit evidence boundary. Batch these small adapters and their
caller integration, retaining lower file/OS models and the current allocation
corpus. Destructor `0x00354FA4`, raw allocator ownership and full file lifetimes
remain separate; do not select `0x002C34F8` solely by similarity.
