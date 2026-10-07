# Integrated resource signal and locks

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This combines three existing contracts; the total remains twenty-six.

## Executed boundary

[Signal](../../src/resource_signal.c), [lock acquire and release](../../src/resource_lock.c)
now build together in a **476-byte ARMv6K unit**. Both comparison paths execute
their own signal and lock instructions. Only arbitration `0x002A88FC` is
intercepted; the rebuilt path executes no original instructions. No source
behavior changes were needed to compose these routines.

| Entry | Original ARM instruction extent (end exclusive) |
| --- | --- |
| Signal | `0x002C4298`–`0x002C434C` |
| Acquire | `0x001464F8`–`0x001465D4` |
| Release | `0x00138FC0`–`0x00139010` |

The [signal contract](resource-signal.md) and [lock contracts](resource-lock.md)
retain their individual evidence. In this integration, signal's second mode
actually acquires the adjacent word, exchanges the signal word, arbitrates,
then releases the adjacent word. Acquisition can itself arbitrate and change
the global handle before signal reads it. Release can arbitrate again, depending
on the signed value produced by its wrapped negation.

The harness schedules competing writes before exclusive loads and before the
second ordinary mode read. Its arbitration model checks six argument words,
clobbers caller-saved registers/flags, returns chosen result words, updates the
handle, and optionally changes signal/lock words. LDREX/STREX/CLREX instructions
execute, with checked Ghidra userops supplying the scheduled exclusive outcomes.
This is not kernel arbitration or physical ARM concurrency validation.

## Reproduction and results

With the saved Ghidra project closed, from `SMT4-decomp/`:

```powershell
python tools/check_resource_signal_lock.py --output local/validation/signal-lock-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/signal-lock-20261006/COMPLETE.json`.
The driver verifies pinned reference/tool hashes, builds with warnings as errors,
saves original/rebuilt GNU listings and commands, opens Ghidra read-only, verifies
the mapped image hash, and writes success last. Run Ghidra jobs sequentially per
project. The original signal/lock checkers remain available with their prior
boundaries; this integration does not modify their source or harnesses.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle comparisons | 7,556 |
| Included bounded pending prefixes | 36 |
| Returning cases | 7,520 |
| Original instruction addresses visited | 120 (all three extents) |
| Maximum instructions per path | 531 |
| Exclusive-store attempts, both paths | 114,178 |
| Clear-exclusive operations, both paths | 33,088 |
| Modeled arbitration calls, both paths | 37,182 |
| Rebuilt text, including literals | 476 bytes |
| Public synthetic tests | 31 passed |

The corpus includes:

- 256 mode-read cases: eight first and eight second words crossed with four
  failure patterns, including changes between the two mode reads.
- 6,144 acquire cases: eight boundary words at three successive lock reads,
  four repeating store-failure patterns, and three arbitration/interference
  variants. Release initially preserves the word produced by the integrated
  acquisition and arbitration, testing propagation across calls.
- 96 release cases: eight boundary words, four failure patterns and three
  interference variants, reached through the real signal/acquire path.
- 1,024 deterministic mixed boundary/random schedules, rotating both active
  signal modes, up to 15 failed signal stores, and arbitrary result words.
- 36 pending prefixes at limits 1/2/7/31, covering acquisition retry/zero/wait
  loops, signal exchange retry in both modes, and release retry.

A separate transition model produces one ordered plan of ordinary/exclusive
reads, clear operations, attempted values even on failed stores, successful
writes, handle reads and arbitration calls. Both instruction streams must
consume the same complete plan. Checks cover target addresses, ordering, retries,
full object/guard memory, final oracle words, stack restoration/alignment,
callee-saved registers, initialized reads, permitted memory operations, PC
extents and instruction budgets. Pending cases stop before the next exclusive
load; they establish bounded effects, not liveness or return ABI. Instruction
visits include predicated instructions and do not imply exhaustive semantics.

Three local mutants are rejected: exchanging signal before acquiring its lock,
releasing the signal word instead of the adjacent lock, and omitting release.
The first two fail the ordered address/event plan; the last leaves required
lock events unconsumed. Driver: `local/validation/check-signal-lock-negatives.py`.
Results: `local/validation/signal-lock-20261006-negative-*/NEGATIVE.json`.
All mutated sources remain local, and no negative run writes a success marker.

## Limits and next work

Valid aligned original 32-bit addresses are required. Arbitrary thread timing,
hardware exclusive monitors, memory ordering and kernel wake behavior remain
unverified. No file I/O, allocation, full loader, native runtime, binary match or
reconstructed 3DS application is claimed. G1/G2 and live agreement remain open.

The subsequent [synchronous-chain integration](resource-chain-signal.md) now
passes 3,924 comparisons in 1,348 bytes, visiting 335 original instruction addresses.
It carries the arbitration, exclusives and timing models forward; the older chain
checker keeps its modeled signal boundary. The subsequent
[arbitration recovery](resource-arbitration.md) adds `--recover-arbitration` to
this checker: 7,556 cases pass in 496 bytes, visiting 126 original instruction
addresses with only SVC intercepted. The default mode retains the boundary
described above. No emulator, save, profile or original dump was changed.
