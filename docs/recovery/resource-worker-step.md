# Bounded resource-worker callback and cleanup step

2026-10-07. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Original worker entry `0x00113D58`, ARM. The reconstructed C interface adapts
the internal region starting at `0x00113DE8` to return its next descriptor when
the original reaches `0x00113DD4`. It does **not** implement the thread-entry ABI.
The count remains thirty-two recovered entry-point contracts, plus this bounded
region. The worker as a whole remains partially recovered.

## Reconstructed behavior

`src/resource_worker.c` retains the original 32-bit descriptor words and pointers.
The step requires a valid descriptor, valid neighbor links and callable callback
addresses. It separates two paths:

- Entry in state 4 or 5 bypasses both callbacks. Under synchronization, the step
  stores the wrapping subtraction `descriptor[1] - descriptor[2]`. A signed-positive
  result retains the node. Otherwise it updates the list head or previous node,
  fixes the next node's backlink, conditionally releases owned data, clears the
  data field and releases the descriptor. The next pointer is captured before
  freeing. Cleanup count `+8` is not reset.
- Other entry states may invoke the `+0x138` path callback under synchronization,
  then clear that field even if the callback replaced it. State is reloaded.
  State 0 enters an explicit unrecovered I/O block; when that block returns, the
  original stores 3, clears `+0x12C`, and stores 4. State 3 advances to 4 directly.
  A resulting state 4 or 5 with a `+0x130` callback invokes it under synchronization.
  Callback and context are reloaded after acquiring the lock. Null context falls
  back to the descriptor address. These callback fields are not cleared.

Except on the freed-node path, the next link is read under a separate acquire/
release pair after processing. Callback changes to this link are observed.
Synchronization handles are reloaded after external operations. Negative
synchronization results call the original result-check boundary; this checker
models that boundary returning. No conclusion about its actual fatal behavior
is drawn.

## Comparison boundary and evidence

```powershell
python tools/check_resource_worker.py --output local/validation/worker-step-next
python -m unittest discover -s tests -v
```

The pinned GCC builds a 708-byte ARMv6K unit. Evidence:
`local/validation/worker-step-20261007/COMPLETE.json`.
All 3,472 original/rebuilt comparisons pass, visiting all 153 original
instructions in the selected region. The driver requires this coverage and
exports a Ghidra listing plus independent GNU disassembly. No original
instructions execute on the rebuilt path. The original region uses its internal
register convention (`r7` descriptor, `r8/r9` globals, `r10=0`, `r11=1`); the C
interface uses an ordinary argument and return value.

The 3,456 independent fixtures cover states 0–6 and unsigned extremes; all four
head/middle/tail/single-node link configurations; wrapping reference/cleanup
counts; owned, external and null data; null/present callbacks and contexts;
callback field replacement on acquire; callback changes to cleanup, data and
next link; and negative synchronization results. Sixteen additional retained-state
steps cover four completions followed by three later passes each: counts 3, 2, 1,
0, with freeing only on the last pass and no repeated terminal callback.

The harness compares complete descriptor/neighbor/global snapshots at dependency
boundaries, final memory against an independent oracle, exact dependency order
and arguments, the returned next link, stack alignment, rebuilt callee-saved
registers and stack guards. It rejects uninitialized memory accesses, unexpected
stores, escaped instruction ranges and reads/writes of a descriptor after free.
Lower calls clobber caller-saved registers and condition flags. All 31 public
synthetic tests pass.

Six faulty variants are checked with `--mutant`: `terminal-callback`,
`unsigned-retain`, `null-context`, `error-survives`, `clear-cleanup`, and
`next-after-free`. Generated variants and diagnostics stay under ignored
`local/validation/worker-step-20261007-negative-*/`; production source is unchanged.

## State-zero error fall-through: original execution probes

An additional 160 original-only probes execute from `0x00113E80` to `0x00114084`.
They visit 159 original instruction addresses, including file-object construction,
allocation routing and teardown. These probes are **not** a recovered I/O source
comparison. Fixtures supply a successful object allocation, a synthetic vtable,
an empty converted path, modeled open/size/seek/read/close/destructor calls, and
returning synchronization operations. They exercise positive/negative open and
read results, handle values 0/1/even/odd, flags 0/1/16/17/2 and supplied/allocated
data. Calls and argument sequences are asserted; per-probe results are retained
in `state0-probes.tsv`.

On negative open, the original stores 5 but still calls size, seek and read.
Negative read also stores 5. After teardown it unconditionally stores 3 and then
4, clearing the file-object field between them. The probes assert the exact state
store sequence, including `[5, 5, 3, 4]` when both results are negative. This resolves
the earlier static uncertainty **when all modeled lower calls return normally**.
It does not prove that real invalid handles survive those lower calls or that
every actual filesystem failure reaches completion. The previous asynchronous
checkers' scheduled terminal state 5 remains a fixture, not observed worker I/O
failure delivery.

## Remaining boundaries and next work

State-0 I/O is still one synthetic block in the original/rebuilt step comparison;
its separate original probes do not remove that dependency. Callback bodies,
synchronization, result handling and release are modeled here. Existing registry
and asynchronous checkers continue to model worker dispatch; this package does
not silently integrate the step into those checkers.

The [completion/release integration](resource-worker-completion.md) now passes
1,728 scenarios and 6,048 retained worker passes in a separate checker. The
standalone checker described above retains its original modeled boundaries.
The [state-zero block](resource-worker-io.md) now has separate recovered source
and 3,456 comparisons, including nonempty paths and failed conversion. This
standalone step checker still models that block. The optional
[I/O/completion integration](resource-worker-io-completion.md) now passes 4,608
scenarios and 16,128 retained passes. Next recover the outer thread wake/stop/list loop.
Object allocation failure, real lower path conversion, arbitrary callback
reentrancy, actual locking/concurrency, timing, a full worker, binary matching and
live gameplay remain unclaimed. G1/G2 remain open; live gameplay stays deferred.
