# Synchronous resource chain with signal and locks

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This integrates twelve existing contracts; the repository total remains twenty-six.

## Executed boundary

The [synchronous chain](resource-chain.md) now executes the recovered
[signal and both lock routines](resource-signal-lock.md) on the same emulated
thread and memory as the loader. The combined **1,348-byte ARMv6K unit** links
`resource_sync.c`, `resource_descriptor.c`, `resource_create.c`, `resource_wait.c`,
`resource_signal.c` and `resource_lock.c`. No C behavior changes were needed.
The rebuilt path executes no original instructions. GCC specializes the wait
loop's constant delay to the modeled sleep call; the original delay selector
executes its long-duration branch.

Signal `0x002C4298`, acquire `0x001464F8` and release `0x00138FC0` are no longer
intercepted in this checker. Signal receives the actual original global address
`0x00465024`; its adjacent lock is `0x00465028`. Arbitration `0x002A88FC` remains
modeled, with the global handle at `0x00471B58` checked at each read. Descriptor
constructor handle acquisition/release are different routines and remain modeled.

Other remaining models cover allocation, clearing, path probing/copying/formatting,
returning result handling and sleep. Worker changes to descriptor state/data/length
are explicitly scheduled at arbitration boundaries, or at signal return when
there was no arbitration, and at sleep. These are not recovered worker or file I/O
implementations. Paths contain no formatting directives; allocation returns a
valid nonnull descriptor.

## Reproduction and evidence

Close the saved Ghidra project, then run from `SMT4-decomp/`:

```powershell
python tools/check_resource_chain_signal.py --output local/validation/chain-signal-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/chain-signal-20261006-final/COMPLETE.json`.
The driver verifies pinned reference/tool hashes, builds with warnings as errors,
exports original and rebuilt GNU listings, runs Ghidra read-only, verifies the
mapped image hash, records source/harness hashes and writes success last. Run
Ghidra jobs sequentially per project.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle comparisons | 3,924 |
| Returning cases | 3,659 |
| Bounded pending prefixes | 265 |
| Pending inside signal/acquire/release | 36 |
| Original instruction addresses visited | 335 |
| Maximum instructions per path | 1,106 |
| Signal calls, both paths | 25,992 |
| Modeled arbitration calls, both paths | 43,270 |
| Exclusive-store attempts, both paths | 164,498 |
| Clear-exclusive operations, both paths | 36,272 |
| Public synthetic tests | 31 passed |

The original 3,888-case chain corpus retains both loader entries, path/mode/list
variants, success/failure, optional size output, 1/2/7 polls and transient terminal
states. Its 229 pending prefixes stop before another signal call. Each executed
signal receives a deterministic schedule rotating inactive and active modes,
boundary lock words, four store-failure patterns, competing writes, handle changes
and arbitrary arbitration result words. The signal object and handle are explicitly
rescheduled at each call; this does not establish unscheduled inter-poll continuity.

An additional 36 cases enter the full loader, construct/link/configure a descriptor,
then stop inside an acquire, exchange or release retry loop at exclusive-load
limits 1/2/7/31. Some reach arbitration and observe worker completion before the
prefix ends. They must leave size and cleanup untouched and may not return from
signal or perform another descriptor poll. These establish bounded effects, not
liveness or a return ABI for nonterminating schedules.

The signal event oracle reuses the independent transition model from
`CompareResourceSignalLock`, translating its synthetic object addresses to the
actual globals. Both instruction streams must consume every ordered read,
exclusive attempt (including failed-store values), clear, successful write,
handle read and arbitration event. Arbitration checks all six argument words,
clobbers caller-saved registers and flags, and applies scheduled competing writes.
LDREX/STREX/CLREX instructions execute with checked Ghidra userops supplying the
scheduled exclusive outcomes.

The surrounding chain additionally checks descriptor/list/path preservation during
signal, neighboring globals, nested stack and callee-saved registers, no descriptor
poll during signaling, mandatory sleep after a transient completion, ownership
transfer and cleanup, output size, and final byte-normalized stores. Both paths
have instruction budgets, PC bounds and initialized-read checks. All 120 signal/lock
instruction addresses plus the earlier 215 chain addresses are visited. The
short-delay branch is covered separately by the wait/delay checker; address visits
include predicated instructions and are not exhaustive semantic coverage.

Four local mutants are rejected: passing the adjacent lock as the signal object,
returning early between signal and sleep, omitting release, and caching the
arbitration handle before acquisition. Driver:
`local/validation/check-chain-signal-negatives.py`; evidence:
`local/validation/chain-signal-20261006-negative-*/NEGATIVE.json`.
Mutated sources stay local; failed runs do not write success markers.
The older chain checker still passes its 3,888 cases with its documented modeled
signal boundary: `local/validation/chain-signal-20261006-baseline/COMPLETE.json`.

## Limits and next work

Actual allocation, worker/file I/O, OS synchronization, arbitration, sleep timing,
hardware exclusive monitors and arbitrary concurrency remain unrecovered or
unverified. This adds integration evidence, not new contracts, binary matching,
a reconstructed application, native runtime or live gameplay agreement. G1/G2
remain open; live checks stay deferred. No emulator, dump, save or profile changed.

The subsequent [arbitration recovery](resource-arbitration.md) reconstructs
`0x002A88FC` and passes direct and signal/lock comparisons through SVC `0x22`.
The subsequent [chain/SVC integration](resource-chain-svc.md) now executes that
wrapper with `--recover-arbitration`: 3,924 comparisons, 1,368 bytes and 341 original
instruction addresses pass. The default mode retains this wrapper-entry model.
Next connect bulk/lifecycle consumers. Kernel behavior remains separately modeled.
Compiler/ABI and host address-boundary research are also ready.
