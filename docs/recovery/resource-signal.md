# Resource signal orchestration

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Entry `0x002C4298`, ARM; instruction extent `[0x002C4298,0x002C434C)`.
Names describe observed roles, not recovered original symbols. This adds one
contract, bringing the recorded total to twenty-four.

## Recovered behavior

[`resource_signal.c`](../../src/resource_signal.c) reconstructs the signal used
by the [wait loop](resource-wait.md). The first word is read as follows:

| Observed state | Effects |
| --- | --- |
| First read is `0xFFFFFFFF` | Exclusive exchange to zero; arbitration with operation 0, count 1, timeout 0 |
| First read differs, second read is `0xFFFFFFFE` | Acquire the lock at object + 4; exclusive exchange to one; arbitration with operation 0, count -1, timeout 0; release that lock |
| Neither condition holds | Return without changing the object or calling a dependency |

The second state read is a separate volatile read. A change between the two
reads can therefore change the selected path. Each exchange loads exclusively,
attempts an exclusive store and retries on failure. It does **not** compare the
loaded value to the earlier mode: even if another writer changes the word,
the successful store still writes the path's constant zero or one. No explicit
memory barrier occurs in this routine. The reconstructed source retains the
LDREX/STREX pair as GNU inline ARM assembly, with C control flow and a compiler
memory clobber; no generic C atomic ordering or host concurrency guarantee is
implied. This is source with a small architecture-specific assembly dependency,
not pure portable C or a binary match.

The handle is loaded from original virtual address `0x00471B58` after the
exchange, and after acquisition on the second path. The arbitration wrapper at
`0x002A88FC` receives the zero 64-bit timeout on the stack. Its local instructions
marshal those words into r4/r5 and execute SVC `0x22`; this package intercepts the
wrapper before execution. All modeled result values, including high-bit results,
are ignored. The second path releases the lock even after such a result. No
meaningful return value is claimed for the signal function.

Lock acquire `0x001464F8` and release `0x00138FC0` now have separate
[recovery evidence](resource-lock.md). This checker still intercepts both, along
with unrecovered arbitration `0x002A88FC`. The models clobber caller-saved registers and
flags, change the lock word, and optionally change signal data or the handle.
They validate call arguments and order, not actual lock ownership, blocking,
kernel wake semantics or worker scheduling.

## Comparison evidence

With the saved Ghidra project closed, from `SMT4-decomp/`:

```powershell
python tools/check_resource_signal.py --output local/validation/signal-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/signal-20261006/COMPLETE.json`. The driver
verifies pinned reference/tool hashes, saves build commands and GNU disassembly,
and opens the saved Ghidra project read-only. It checks the mapped image hash
again and writes success last. Run jobs sequentially on that project.

| Check | Result |
| --- | ---: |
| Original/rebuilt/expected cases | 3,352 |
| Included bounded pending prefixes | 24 |
| Original instruction addresses visited | 45 (all) |
| Maximum executed instructions per path | 139 |
| Exclusive-store attempts, both paths | 15,666 |
| Modeled dependency calls, both paths | 4,842 |
| Rebuilt ARMv6 text, including literal | 188 bytes |
| Public synthetic tests | 31 passed |

The main corpus crosses eight first-read and eight second-read states, four
failed-store counts (0/1/2/7), three interference variants and three boundary
result values: 2,304 cases. Another 1,024 deterministic cases rotate arbitrary
32-bit states/results, both active paths and 0–15 failed stores. The 24 pending
prefixes cover both active paths, 1/2/7/31 failed stores and three interference
variants, stopping before the next exclusive load. They establish bounded
effects, not liveness or return ABI.

The harness executes the original and rebuilt LDREX/STREX p-code. In this pinned
Ghidra language, LDREX is represented by a load and STREX asks the otherwise
undefined `hasExclusiveAccess` userop. An instruction callback records the
exclusive load/reservation; a narrowly checked userop model supplies the
scheduled success/failure outcome. The remaining STREX p-code performs the
actual conditional store. Failed attempts may inject a competing write.
Thus retry branches and stores execute, but the exclusive monitor and competing
thread are explicit models. No physical ARM memory-ordering claim is made.

Checks enforce the separate mode reads, exclusive-load/store pairing, retry and
successful-store counts, state value, lock/arbitration arguments and ordering,
handle reload timing, timeout words, ordered original/rebuilt event traces,
full object/guard bytes, stack restoration/alignment, callee-saved registers,
initialized reads, allowed memory operations, PC extents and instruction budgets.
The rebuilt path executes no original instructions. Address coverage includes
predicated instructions and does not establish exhaustive semantic coverage.

Four local mutants are rejected: omitting retry, caching the first mode read,
changing count -1 to 1, and replacing the zero exchange with an ordinary store.
Diagnostics respectively identify premature handle loading, a missing reread,
incorrect arbitration arguments and a nonexclusive store. Driver:
`local/validation/check-signal-negatives.py`; results:
`local/validation/signal-20261006-negative-{retry,reread,wake-count,plain-store}/NEGATIVE.json`.
Mutated sources remain local; no negative run writes a success marker.

## Limits and next work

The object and lock must have valid aligned original 32-bit addresses. Only
scheduled interference at the documented boundaries is covered; real kernel
arbitration, nonreturning lock acquisition, scheduling and arbitrary concurrent
mutation remain open. The older wait and chain checkers still intercept the
signal entry; they retain their prior boundaries. G1/G2 and live gameplay
agreement remain deferred. No emulator, save, profile or original dump changed.

Acquire/release reconstruction is now complete for the scheduled model in
[lock recovery](resource-lock.md). The new [integrated checker](resource-signal-lock.md)
now executes both locks: 7,556 comparisons pass in 476 bytes, with 36 pending
prefixes and all 120 original instruction addresses visited. Only arbitration
remains intercepted; three integration mutants are rejected. Next integrate
signal/locks into the synchronous chain. Local
GNU listings for both helpers are retained in the successful output directory.
The acquire listing from the prior wait inspection is also available under
`local/analysis/wait-20261006-final/exports/`. Compiler/ABI and host-address
boundary research remain open.
