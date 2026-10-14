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

## Acquire consumed-r2 extension (2026-10-13)

No reprioritization was needed: base acquire's consumed r2 is a concrete dependency
of recursive ownership and subsequent delivery-lock integration. Prior wait audit
source/tool hashes agree, except the intentionally extended signal header;
`local/validation/acquire-return-20261013-audit/handoff-check.json` records the check.

Acceptance declared before implementation: preserve the base state machine and
return the lock address in r2 after initial fast success, zero after either slow
success; forward this through recursive acquire, preserve incoming r2 when already
owned, and retain retries, CLREX, guarded fields, ABI and pending-prefix evidence.
Require a warning-clean ARM build, original/rebuilt/oracle comparisons, fault
rejections and affected signal/pool regressions. TLS/kernel/monitor models remain
explicit. This extends one existing contract, not the recovered-entry total.

Original `0x001464F8..0x001465D4` starts with MOV r2,r0. Initial STREX uses r3,
so even failed initial stores preserve that address. Once the slow path is entered,
either successful acquisition STREX writes zero to r2. Independent instruction
evidence is in `local/validation/wait-return-20261013-audit/next-lock-acquire.log`
and this package's base `original-001464f8-disassembly.log`.

`src/resource_lock.c` retains the exclusive C state machine, with a 216-byte C body
returning the consumed word and a 16-byte ARM entry bridge publishing it in r2.
The bridge maintains 8-byte call alignment. Recursive acquire `0x002C3AFC` is reused
unchanged: the already-owned route preserves incoming r2; the base route forwards
r2 across its TLS reread and wrapping count increment. Release source is unchanged.
Other raw scratch returns of base acquire are not claimed. The bridge is an ABI
implementation detail, not another original game routine. No call model is removed
in this package; the existing executed base dependency gains its missing contract.

The independent transition oracle now derives r2 from the acquisition phase, and
both original and rebuilt instructions must agree with it. The final recursive
checker varies incoming r2 with count/TLS, checks base-return r2 before wrapper
continuation, and carries r2 across persistent calls without reseeding it. Pending
prefixes assert state/event agreement but make no return or liveness claim.

Validation evidence under `local/validation/acquire-return-20261013-*`:

- `base/COMPLETE.json`: 316-byte unit; all 3,092 acquire and 1,064 release pairs,
  including 28 pending prefixes and all 75 original base instruction sites.
- `recursive-final/COMPLETE.json`: final direct corpus and source/tool identities;
  404-byte unit, 164 pairs, four pending prefixes and two persistent lifetimes.
- `fast-negative/NEGATIVE.json` and `slow-negative/NEGATIVE.json`: compiled faults
  replacing fast address with zero or slow zero with one are rejected at recursive
  cases 0 and 96 respectively by the r2 oracle. These ran before the final additional
  incoming-register variation; that refinement retains the same return assertions.
- `signal/COMPLETE.json` and `backend/COMPLETE.json`: affected executed signal/lock
  and recursive pool-caller regressions, with their original boundaries retained.
- `audit/COMPLETE.json`, `jobs.json`, `public.log`: exact completed jobs, artifact
  verification, final source identities and public regression evidence.

Reproduce from SMT4-decomp, with sequential Ghidra jobs:

```powershell
python tools/check_resource_lock.py --output local/validation/NEW-BASE
python tools/check_resource_recursive_lock.py --output local/validation/NEW-RECURSIVE
python tools/check_resource_recursive_lock.py --mutant acquire-fast-r2 --output local/validation/NEW-FAST-FAULT
python tools/check_resource_recursive_lock.py --mutant acquire-slow-r2 --output local/validation/NEW-SLOW-FAULT
python tools/check_resource_signal_lock.py --recover-arbitration --output local/validation/NEW-SIGNAL
python tools/check_resource_worker_backend.py --recover-clear --recover-locks --output local/validation/NEW-BACKEND
python -m unittest discover -s tests
```

Bounded aligned mapped storage, scheduled exclusives/interference and modeled TLS,
arbitration/kernel results remain the domain. Signal regression executes the SVC
marshalling wrapper but models its kernel result. Pool regression retains its
service/diagnostic boundaries. Physical concurrency, arbitrary caller scratch
provenance, invalid pointers, timing, full startup and deferred live G1/G2 remain
open. The earlier report's counts and boundaries above are historical evidence.

### Next independent source milestone

Recover delivery `0x002AD7E8..0x002AD8F0` scratch-r2 provenance at acquire/release
sites, then replace recursive lock models in create/chain
`--recover-result-diagnostic`. Reuse base/recursive locks and wait source. Inspect
`local/validation/wait-return-20261013-audit/next-delivery-lock.log`,
`src/resource_worker_diagnostic.c`, `tools/ghidra/ResourceDiagnosticDelivery.java`,
and the delivery/wait reports. Failed connect at `0x001382CC`, request
`0x00146964` with skipped close, close SVC 0x23, and retry delay `0x002BB4F0`
can supply incoming r2 to a nonfinal recursive release; establish those consumed
contracts before relinking. Existing C scratch allocations cannot stand in for
original register provenance. Include nested ownership and retry fixtures; do
not count already recovered lock entries again. Keep kernel/TLS policies explicit.
