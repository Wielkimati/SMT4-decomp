# Resource lock acquisition and release

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM acquire `0x001464F8`, instruction extent `[0x001464F8,0x001465D4)`;
release `0x00138FC0`, extent `[0x00138FC0,0x00139010)`. Each is followed by
a handle-address literal. Names describe observed roles, not original symbols.
These two contracts bring the recorded recovered total to twenty-six.

## Source and behavior

[`resource_lock.c`](../../src/resource_lock.c) reconstructs both functions called
by the [signal](resource-signal.md). The argument is an aligned pointer to one
32-bit word in the original address space. Arithmetic wraps modulo 2^32;
comparisons interpret the observed word as signed. The source uses unsigned
arithmetic and explicit sign-bit ranges to avoid signed-overflow undefined behavior.

Acquisition has these phases. Each observation is a new LDREX; each attempted
write is STREX. A failed store repeats the current phase's observation.

| Phase | Observed word `v` | Behavior |
| --- | --- | --- |
| Initial attempt | Signed positive | Attempt `-v`; return on success |
| Initial attempt | Zero or negative | CLREX; enter waiter registration |
| Waiter registration | Negative | Attempt `v-1`; on success enter arbitration |
| Waiter registration | Zero or positive | CLREX; enter second positive attempt |
| Second positive attempt | Positive | Attempt `-v`; return on success |
| Second positive attempt | Zero or negative | CLREX; return to waiter registration |
| After arbitration | Positive | Attempt `1-v`; return on success |
| After arbitration | Zero or negative | CLREX; arbitrate again |

Arbitration uses `(handle, lock, operation=1, count=0, timeout=0)`. The handle
at `0x00471B58` is read anew on every call; return values are ignored. A failed
post-arbitration STREX retries its load without another arbitration call.
No liveness is implied: zero states, unsuccessful exclusives, or repeated
nonpositive observations after arbitration can keep the function pending.

Release repeatedly loads and attempts the wrapped negation `-v`. After a
successful store, it calls arbitration only if that stored value is signed
greater than one, with `(handle, lock, operation=0, count=1, timeout=0)`.
The handle is loaded after the store. In particular, negating `0x80000000`
keeps that word unchanged and does not call arbitration. Arbitration may change
the lock again; neither routine overwrites those modeled effects after returning.
No meaningful C return value is claimed for either entry.

The original routines contain no explicit memory barrier. The source retains
GNU inline LDREX/STREX/CLREX and compiler memory clobbers without introducing
hardware barriers or generic C atomic ordering. The unit uses `-march=armv6k`
so GNU assembly accepts CLREX; other flags follow the existing freestanding
comparison build. This is an architecture-specific source reconstruction,
not portable host synchronization, original compiler identification, or matching.

## Reproduction and evidence

With the saved Ghidra project closed, from `SMT4-decomp/`:

```powershell
python tools/check_resource_lock.py --output local/validation/lock-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/lock-20261006-verified/COMPLETE.json`.
The driver verifies reference/tool hashes, records commands and original/rebuilt
GNU listings, opens Ghidra read-only, verifies the mapped image hash, and writes
success last. Ghidra jobs must run sequentially on this project.

| Check | Result |
| --- | ---: |
| Acquire original/rebuilt/oracle comparisons | 3,092 |
| Release original/rebuilt/oracle comparisons | 1,064 |
| Included bounded pending prefixes | 28 (20 acquire, 8 release) |
| Original instruction addresses visited | 75 (55 acquire, 20 release; all) |
| Maximum executed instructions per path | 518 |
| Exclusive-store attempts, both paths | 21,530 |
| Clear-exclusive operations, both paths | 16,052 |
| Modeled arbitration calls, both paths | 8,554 |
| Rebuilt text including literals | 288 bytes |
| Public synthetic tests | 31 passed |

The main acquire corpus crosses eight boundary words at each of three successive
reads with four repeating failure patterns: 2,048 cases. Release has 32 boundary
cases. Both add 1,024 deterministic mixed boundary/random schedules. The remaining
28 cases stop before the next exclusive load after 1/2/7/31 observations, covering
failed-store, zero-state and arbitration loops. Schedules also preserve the prior
word on selected reads, vary arbitration results, mutate memory at arbitration,
and change the handle to check reloads. This is bounded coverage, not exhaustive
concurrent execution.

A separate transition model creates expected ordered load, clear, store-attempt,
successful-write, handle-read and arbitration events. Both instruction streams
must consume that entire plan, including attempted values on failed STREX.
Original/rebuilt LDREX/STREX p-code executes; Ghidra's `hasExclusiveAccess`
and `ClearExclusiveLocal` userops implement a checked scheduled monitor. Competing
writes are injected before designated exclusive loads. Arbitration `0x002A88FC`
is intercepted on both paths, checks all six argument words, clobbers caller-saved
registers/flags, and optionally changes the lock word. OS arbitration, actual
exclusive-monitor behavior and arbitrary thread timing are not recovered.

Checks cover event order, retry/clear behavior, full object/guard memory, final
oracle words, stack restoration/alignment, callee-saved registers, initialized
reads, permitted memory operations, instruction extents and budgets. Rebuilt
paths execute no original instructions. Address coverage is not exhaustive
semantic coverage.

Four local mutants are rejected: omitted CLREX, wrong post-wait `-v` adjustment,
unsigned release wake predicate, and omitted release retry. Driver:
`local/validation/check-lock-negatives.py`; results:
`local/validation/lock-20261006-negative-*/NEGATIVE.json`. None writes success.
The first development run passed instruction comparisons but its Python coverage
gate mistakenly expected 76 addresses; corrected to the 75 instruction slots
in the disassembled extents. The final fresh run includes the corrected gate
and hashes its own driver.

## Remaining work

The older signal and synchronous-chain checkers keep their existing interception
boundaries. A new [integrated signal/lock checker](resource-signal-lock.md) now
executes both locks and passes 7,556 comparisons in 476 bytes, including all 120
original instruction addresses and 36 pending prefixes. Three integrated mutants
are rejected. Next integrate signal/locks into the synchronous chain, carrying
explicit arbitration/OS models.
The SVC `0x22` marshalling wrapper at `0x002A88FC` is a separate bounded recovery
candidate; kernel semantics and allocation/file I/O remain open. No emulator,
save, profile or original dump was changed. G1/G2/live verification stay deferred.
