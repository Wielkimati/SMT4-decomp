# Resource aligned allocation and metadata

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x002C5544` is reconstructed in `src/resource_allocate_lower.c`.
Both allocation layers now also execute inside registry construction and retained
worker cleanup/reuse; see [allocation integration](resource-registry-allocation.md).
The standalone corpus and dependency limits below remain unchanged.
This adds one analyzed, understood, implemented, buildable and bounded
behavior-verified entry point: **35 entry points plus two adapted worker regions**.
The existing outer-wrapper and registry/worker checkers still intercept this
layer or its caller. No native allocator, binary matching, concurrency result,
or live verification is claimed.

## Contract

`smt4_resource_allocate_lower(first, second, third, size, fifth)`:

1. Acquire the synchronization object read from `0x00465120 + 4` through
   `0x002C3AFC`.
2. When `first` equals exactly `0x20000` or `0x30000`, forward all five words to
   raw allocation `0x002B26F0`, preserving the original size. Reload/release the
   synchronization object through `0x002C3A78` and return the raw result directly,
   including null. This route performs no metadata registration or zero call.
3. Otherwise request `(size + 0x13B) & ~0x7F`, with 32-bit wrapping addition.
   Preserve all four other arguments, including the full-width fifth stack word.
4. For raw result `raw`, set `user` to the next 128-byte boundary at or after
   `raw + 0x3C`. Store rounded size at `raw`, halfwords `0x80` and zero at
   `raw+4/+6`, and the raw address at `user-4`.
5. Call accounting/registration `0x002B260C(raw)` after writing metadata, then
   clear the original `size` bytes at `user` through `0x002C3B9C`, even for size
   zero. Reload/release the synchronization object and return `user`.

The ordinary path has **no null-result guard** before its metadata stores.
The bounded C contract requires nonnull, word-aligned writable raw storage,
valid metadata/backlink addresses and, for actual clearing, a writable user
extent. The comparison covers every word-aligned residue modulo 128, including
the already-aligned `raw+0x3C` case. Unaligned raw pointers and address overflow
at the top of the address space are outside this package's validated domain.
Size overflow is preserved, not repaired into a safer allocation request.

The source requires original 32-bit addresses. Original code preserves the fifth
word in `s16` and saves/restores `d8`; rebuilt code uses integer registers/stack.
The compiler combines the two halfword stores into one word store. Byte values
and observations at dependency boundaries agree; intermediate store widths and
concurrent observers are not equivalent claims.

## Reproduce and evidence

```powershell
python tools/check_resource_allocate_lower.py --output local/validation/allocate-lower-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/allocate-lower-20261007/COMPLETE.json`.
The driver pins input/tools, builds a **180-byte ARMv6K unit**, exports independent
GNU disassembly, and runs the saved Ghidra project read-only. Generated binary,
listings and traces remain under ignored `local/`. Ghidra jobs must run sequentially
against this project. No original code executes on the rebuilt path.

| Check | Result |
| --- | ---: |
| Original/rebuilt/independent-oracle comparisons | 10,828 |
| Special-route comparisons | 1,272 |
| Null special-route results | 252 |
| Ordinary cases with wrapping size addition | 1,542 |
| Ordinary cases with modeled buffer clearing applied | 5,772 |
| Original instruction addresses visited | All 60 |
| Dependency calls checked across both paths | 103,192 |
| Maximum original/rebuilt instructions per call | 45 |
| Public synthetic tests | 31 passed |

The corpus includes 8,064 size/residue/lock-effect cases with low and high-bit
storage addresses; 1,260 bypass-route cases; 480 single-argument boundary cases;
and 1,024 deterministic random full-width argument cases. Sizes include the
rounding transitions and values immediately around the 32-bit addition wrap.
Selector neighbors and high-bit lookalikes exercise exact special-route equality.

The arithmetic oracle uses division-based rounding independently of the recovered
mask expression. Memory comparisons cover randomized header, padding, payload
and guard bytes before accounting, zeroing, release and final return. Accounting
is modeled by writes to other header fields, whose preservation is checked.
Zeroing applies actual modeled buffer writes only for sizes up to 1,024 bytes;
larger sizes check arguments/order with a call model, not real huge allocations.
In particular, wrapped-size probes do not establish heap capacity or safe clearing.

Six lock-effect profiles leave the handle fixed, change it on acquire, raw
allocation, registration, clearing, or every preceding dependency. Calls clobber
volatile integer/VFP registers and flags. Checks also cover dependency stack
alignment, fifth-word forwarding, result preservation, callee-saved registers,
`d8`, stack restoration, caller stack and state guards, and unexpected accesses.

Six deliberately faulty variants are rejected by semantic assertions: rounding
with `0x13A`, omitting the `0x30000` bypass, moving the backlink, storing a nonzero
second halfword, clearing rounded instead of requested size, and releasing a
cached lock handle. Compilation errors do not count as rejection. Local driver:
`local/validation/check-allocate-lower-negatives.py`; records:
`local/validation/allocate-lower-20261007-negative-*/NEGATIVE.json`.
Production source was not modified for these checks.

The unchanged outer-wrapper checker also passes all 2,824 comparisons using the
updated shared header: `local/validation/allocate-lower-20261007-wrapper-regression/COMPLETE.json`.
It still intercepts this lower entry; this regression does not claim integration.

## Boundaries and continuation

Static evidence comes from `tools/ghidra/InspectResourceAllocate.java` and the
existing `local/analysis/allocate-20261007/exports/` listing. Raw GNU disassembly
and the comparison's Ghidra listing agree on entry extent and call targets.
Raw allocation `0x002B26F0`, accounting `0x002B260C`, byte clearing and recursive
locks remain models; the caller's metadata writes are executed instructions.

Both layers now execute with descriptor/callback construction, ordinary double
clearing, modeled nested locks, retained metadata and reused user addresses;
see [integration evidence](resource-registry-allocation.md). Those callers use
only ordinary allocation; integrated special-route outer clearing is unverified.
Next recover release conversion and its accounting/list effects. Lower allocator
routing and accounting are separate recovery candidates. Real heap/free behavior, file I/O,
concurrency and deferred G1/G2 live evidence remain open. No PC source transfer
or implementation was added.
