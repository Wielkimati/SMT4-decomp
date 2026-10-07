# Resource allocation wrapper

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x002C4BD8` is reconstructed in `src/resource_allocate.c`.
This adds one analyzed, understood, implemented, buildable and bounded
behavior-verified entry point: **34 entry points plus two adapted worker regions**.
It does not implement the lower allocator or integrate this wrapper into the
existing registry/worker checker. Binary matching and live verification are unclaimed.

## Contract

The existing five-word `smt4_file_allocate(first, second, third, size, fifth)`
interface now has a recovered implementation:

1. Load allocator state `0x00465120 + 4` and acquire that synchronization object
   through `0x002C3AFC`.
2. Forward all five 32-bit arguments, without narrowing, to `0x002C5544`.
   The fifth argument is passed on the stack.
3. If the result is nonnull, call `0x002C3B9C(result, size)`. Static inspection
   identifies this as byte clearing. A nonnull result with size zero still calls it.
4. Reload the synchronization handle from state `+4` and release through
   `0x002C3A78`, including on null allocation results.
5. Return the original lower allocation result, preserving it across clearing
   and release. Those calls' incidental return values are ignored.

The wrapper writes only its own stack. Argument names other than `size` remain
conservative; lower routing observations below are not complete public semantics.
Original code saves the fifth word in `s16` and preserves `d8`; the rebuilt C uses
integer registers/stack instead. No original compiler or matching claim follows.

## Validation

```powershell
python tools/check_resource_allocate.py --output local/validation/allocate-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/allocate-20261007/COMPLETE.json`.
The driver pins input/tool hashes, builds a **108-byte ARMv6K unit**, exports
GNU disassembly, and opens the saved Ghidra project read-only. The rebuilt path
executes no original code. Run Ghidra jobs sequentially against this project.

| Check | Result |
| --- | ---: |
| Original/rebuilt/independent expected-call comparisons | 2,824 |
| Null allocation results | 616 |
| Zero-size arguments | 25 |
| Original instruction addresses visited | All 26 |
| Checked dependency calls across both paths | 21,360 |
| Maximum original/rebuilt instructions per call | 26 |
| Public synthetic tests | 31 passed |

The corpus includes 1,750 single-argument boundary variations with distinct
sentinels in all other arguments, 50 actual descriptor/callback request shapes,
and 1,024 deterministic full-width random cases. Return words include zero,
unaligned, high-bit and maximum unsigned values. These are deliberately arbitrary
words under a lower-call model, not assertions that those are valid allocations.

Each dependency is checked for order, register/stack arguments and stack alignment.
Five effect profiles keep the lock fixed, change it on acquire, allocation,
clearing, or every preceding call. Caller-saved integer/VFP registers and flags
are clobbered. Checks cover return preservation, callee-saved registers, `d8`,
stack restoration, incoming fifth argument, caller-stack guards, allocator-state
guards, and unexpected memory accesses. Zeroing is intercepted: its destination
and count are checked, but actual buffer writes are not executed in this corpus.

All five local faulty variants are rejected: unconditional clearing of null, narrowing the
fifth argument, changing the clear size, using a cached lock handle, and discarding
the allocation result. Driver: `local/validation/check-allocate-negatives.py`;
records: `local/validation/allocate-20261007-negative-*/NEGATIVE.json`.
Only semantic assertion failures count as rejection, not compilation failures.
Production source is unchanged by these checks.

## Lower dependency inspection

`tools/ghidra/InspectResourceAllocate.java` exports these functions read-only;
local listing, generated pseudocode and references are under
`local/analysis/allocate-20261007/exports/`. Generated pseudocode stays local.
Ghidra and independent raw ARM disassembly agree on the wrapper and the following
`0x002C5544` behavior; lower entries are static findings, not recovered contracts.

- `0x002C3B9C` is the entry after a NOP at `0x002C3B98`. It clears leading bytes
  to reach word alignment, then branches into the word/tail clear implementation
  at `0x002C4B88`; `0x002C4B84` supplies its zero register first.
- `0x002C5544` acquires/releases the same allocator synchronization object again.
  First arguments `0x20000` and `0x30000` forward the original size and return
  the result of `0x002B26F0` directly, without the metadata/clear path below.
- Other first arguments request `(size + 0x13B) & ~0x7F`, using wrapping 32-bit
  addition. For raw result `raw`, the returned user pointer is
  `raw + 0x3C + ((0x80 - ((raw + 0x3C) & 0x7F)) & 0x7F)`.
  It stores the rounded size at `raw`, halfwords `0x80` and zero at `raw+4/+6`,
  and `raw` at `user-4`. It calls metadata registration `0x002B260C(raw)`,
  clears `size` bytes at `user`, reloads/releases the lock and returns `user`.
  This branch has no null guard before metadata stores. Do not infer graceful
  allocation failure from the outer wrapper's null guard.
- `0x002B26F0` selects lower routes and alignment parameters. Static output shows
  a zero-size early return, heap routes for first arguments `0x100/0x10000`,
  and calls to `0x00144978` for `0x20000/0x30000`. The fifth argument changes
  the sign of the alignment parameter. Complete validity/failure semantics remain open.
- `0x002B260C` updates allocation counters and a linked list, with additional
  indexed accounting. Its Ghidra caller pseudocode omits the argument at the
  call site; ARM data flow retains `raw` in `r0`. It is not a no-argument routine.
- Lock acquire `0x002C3AFC` compares the thread-local register with owner `+4`
  and increments recursion depth at `+8`. Release `0x002C3A78` decrements depth;
  at zero it clears the owner and tail-calls `0x00138FC0`. This accounts for
  nested acquisition in the observed allocation chain; concurrency is untested.

Subsequent recovery of `0x002C5544` now passes 10,828 comparisons with explicit
raw allocation, registration, zero and lock models; see
[aligned allocation evidence](resource-allocate-lower.md). Both special routes,
wrapping size arithmetic, word-aligned raw-address residues, metadata guards and
lock reloads pass. The ordinary path assumes valid writable word-aligned raw
storage. Both layers now execute with descriptor/callback construction and
retained worker reuse; see [integration evidence](resource-registry-allocation.md).
This wrapper's own checker still models `0x002C5544`. Real heap selection,
free-list behavior, concurrency, file I/O and deferred G1/G2 live checks remain open.
No PC-port source transfer or native runtime was added.
