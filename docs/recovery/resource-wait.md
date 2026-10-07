# Resource wait loop and delay selection

Subsequent [signal recovery](resource-signal.md) adds source and 3,352 comparisons
for `0x002C4298`, with scheduled exclusive outcomes and lock/arbitration models.
This standalone wait checker retains its original signal interception boundary.

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Entries `0x001181B0` and `0x002BB4F0`, ARM. Addresses are original virtual
addresses; names describe observed roles. Source was reconstructed from local
instructions, without copying external code.

## Recovered contracts

[`resource_wait.c`](../../src/resource_wait.c) implements two contracts:

- `smt4_file_wait` reads the descriptor's state word and returns exactly for
  states 4 or 5. Every other state calls `0x002C4298` with `0x00465024`, then
  `0x002BB4F0` with r0=3,000,000 and r1=0, before polling again. It performs no
  descriptor stores. There is no state recheck between those two calls: even
  completion during the first call still incurs the delay. The reconstructed
  state load is volatile to retain each poll; this is not a portable threading
  or memory-ordering implementation.
- `smt4_file_delay` interprets r0/r1 as a signed 64-bit duration. Values at least
  `0x3477` (13,431) tail-call `0x001382E4` with that duration unchanged. Smaller
  values, including negative ones, multiply the unsigned 64-bit bit pattern by
  `0x44A2FA85` modulo 2^64 and pass the upper 32 bits to `0x001382BC`.
  Both interfaces are treated as void; incidental return registers and flags
  are not claimed.

This corrects the earlier provisional “callback” description of `0x002BB4F0`.
Its long-duration target is an `SVC 0x0A`/return stub; its short-duration target
is a subtract-two, signed-positive busy loop. No callback dispatch occurs in
these recovered entries. The consumed 3,000,000 value selects the SVC path.
The comparison checks duration arguments, not real elapsed time or scheduling.

## Inspected synchronization boundary

The first call, `0x002C4298`, remains explicitly intercepted. Static instructions
show two special state values in the signal object:

- `0xFFFFFFFF`: an LDREX/STREX retry loop stores zero, then calls `0x002A88FC`
  with `(word[0x00471B58], object, 0, 1, 0, 0)`.
- `0xFFFFFFFE`: calls `0x001464F8` on `object+4`, atomically stores one in the
  object, calls `0x002A88FC` with fourth argument `0xFFFFFFFF`, then tail-calls
  `0x00138FC0` on `object+4`. The fifth/sixth arguments are again zero.
- Other observed values return without taking either special path. The original
  reads the state a second time before checking the second special value.

`0x002A88FC` reaches SVC `0x22`. The `object+4` helpers themselves contain
exclusive operations and additional arbitration calls. These observations are
static evidence, not validated synchronization source or a model of contention.
Original library provenance and full synchronization semantics remain open.

## Evidence and reproduction

With the saved Ghidra project closed, run sequentially from the repository:

```powershell
python tools/inspect_resource_wait.py --output local/analysis/wait-next
python tools/check_resource_wait.py --output local/validation/wait-next
python -m unittest discover -s tests -v
```

Both tools require a fresh ignored `local/` output. Ghidra uses the saved import
read-only and verifies the full initialized image hash. The comparison pins
GCC/binutils and JDK/Ghidra as in earlier packages, saves independent objdump
listings, and records source/tool hashes before writing `COMPLETE.json` last.
Do not overlap Ghidra jobs on the same project, even with `-readOnly`.

Successful comparison: `local/validation/wait-20261006/COMPLETE.json`.
Static export: `local/analysis/wait-20261006-reviewed/exports/`.

| Check | Result |
| --- | ---: |
| Wait cases with original/rebuilt delay execution | 191 |
| Included bounded pending prefixes | 21 |
| Direct delay comparisons | 14,479 |
| Original instruction addresses visited | All 25 |
| Maximum executed instructions per call/prefix | 534 |
| Modeled boundary calls, both paths combined | 36,518 |
| Rebuilt ARMv6 unit | 120 bytes |
| Public synthetic tests | 31 passed |

Wait cases cover immediate success/failure, seven pending states including high
bits, 1/2/7/31 iterations, completion at either boundary, and transient terminal
states during the signal call. The 21 pending cases check eight complete
iterations and the next poll; they do not prove infinite behavior or liveness.
Delay cases exhaust 0..13,430 and add 24 explicit boundary values and 1,024
deterministic full-width random bit patterns. An independent BigInteger oracle
checks the scaled argument, including negative and overflow inputs.

Each path runs in a separate instruction emulator and is checked against expected
ordered calls, arguments, descriptor bytes, poll counts, stack alignment, restored
stack/callee-saved registers on return, initialized reads, allowed stores, PC
ranges and instruction budgets. Only signal, SVC sleep and busy-spin targets are
modeled. Rebuilt paths execute no original instructions; GCC specializes the
constant delay inside the wait loop to call the sleep boundary directly.

Three local mutants are rejected: accepting any state >=4, returning after a
terminal state appears during the signal call, and using an unsigned duration
comparison. Driver: `local/validation/check-wait-negatives.py`; records:
`local/validation/wait-20261006-negative-{terminal,early-return,unsigned-delay}/NEGATIVE.json`.
Mutated source stays local and no negative run produces a success marker.

The initial static exports stopped at tail targets absent as separate Ghidra
function objects; the exporter now lists their existing instructions explicitly.
One later attempt encountered the comparison job's project lock. All partial
outputs remain local without completion markers; the sequential export succeeded.

## Remaining work

Twenty-three entry-point contracts now have bounded source/build/comparison
evidence. The subsequent [integrated chain](resource-chain.md) now passes 3,888 comparisons
in 868 bytes with constructor/wait/delay execution and explicit allocation, string,
signal and timing boundaries. Earlier sync/bulk/lifecycle checkers still use their documented
higher-level interception; this package does not silently change their claims.
Then recover the signal/arbitration helpers with explicit exclusive-operation
and contention tests. Actual I/O/allocation, compiler/ABI research, host address
boundaries and a full 3DS rebuild remain open. Live verification and G1/G2 remain
deferred/unpassed. No emulator, save, profile or original dump was changed.
