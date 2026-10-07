# Resource worker: callback and cleanup trace

Continuation, 2026-10-07: the bounded node region is now reconstructed and
instruction-compared; see [worker-step evidence](resource-worker-step.md).
Its 160 separate original I/O probes resolve the error fall-through below when
modeled lower calls return. This report preserves the earlier static trace;
the complete worker remains unrecovered.

2026-10-06, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Original ARM worker entry: `0x00113D58`. This is static analysis, not a recovered
or behavior-verified worker contract. The release wrapper is recovered separately
in [resource-release.md](resource-release.md).

## Evidence and control flow

The offset search in `InspectResourceWorker.java` identifies loads from descriptor
`+0x130/+0x134` in this worker. Shared list head `0x0046500C`, synchronization
object `0x00465010`, 0x144-byte descriptor layout and list links agree with the
already recovered constructor. Other field-offset hits belong to unrelated types;
an offset match alone is not evidence of a descriptor access.

The following observations are confirmed by Ghidra listing and independent GNU
ARM disassembly, with generated pseudocode used only as an analysis aid:

| Address | Observed behavior |
| --- | --- |
| `0x00113DE8` | A descriptor already in state 4 or 5 enters cleanup immediately, bypassing callback dispatch. |
| `0x00113DF8` | For other states, optional `+0x138` callback receives the path at `descriptor+0x2C`, under list synchronization. The worker clears `+0x138` after it returns. |
| `0x00113E60` | Dispatches states 0–3 through a table; state 0 performs file setup/read/destruction, states 1 and 2 skip that work, and state 3 advances to 4. |
| `0x00114070` | Normal fall-through from state-0 I/O explicitly stores 3, clears `+0x12C`, then stores 4. Earlier stores of 5 on negative open/read results are not sufficient to conclude that 5 survives to completion. Error-path semantics still need execution evidence. |
| `0x00114084` | Rechecks state for 4 or 5, then tests the callback at `+0x130`. |
| `0x00114160` | Acquires list synchronization before reloading the callback and context. |
| `0x00114170`–`0x00114180` | Loads context from `+0x134`, callback from `+0x130`; substitutes the descriptor address for null context and calls it with BLX. |
| `0x00114184`–`0x00114190` | Reloads the global synchronization object and releases it after the callback. The callback/context fields are not cleared here. |
| `0x00114284` | Acquires synchronization again, reads the descriptor's next link, releases synchronization, and continues the list. |

Thus the asynchronous packet installed by `0x00155BBC` reaches completion
`0x00155B30` through its stored nonnull context. The worker does not call that
completion again just because a later pass sees a terminal descriptor; that pass
enters cleanup instead. This describes the static control flow, not arbitrary
callback reentrancy or concurrent scheduling.

## Later cleanup

At `0x001141D4`, the worker subtracts `descriptor+8` from `descriptor+4`, stores
the 32-bit result, and keeps the descriptor if the result is signed-positive.
The cleanup count at `+8` is not reset in this block. Otherwise it unlinks the
descriptor using next `+0x13C` and previous `+0x140`, updating the head or neighbor
links as appropriate.

If `+0x10` is zero and data `+0x0C` is nonzero, it calls release `0x002C43B4`
on the data. It then clears `+0x0C` and releases the descriptor itself. The next
link is retained in a register before freeing the descriptor. This explains why
successful asynchronous completion first detaches data and increments cleanup,
while failed completion preserves the data for later worker cleanup. The prior
integration's modeled failure states are fixtures, not proof of which I/O failures
produce a terminal state 5 in this worker.

## Reproduction and next work

```powershell
python tools/inspect_resource_worker.py --output local/analysis/worker-next
```

The script checks the mapped image hash and uses the saved project read-only.
Final bounded export: `local/analysis/worker-20261006-final/exports/`.
Independent worker disassembly is retained in
`local/analysis/worker-20261006-bounded/original-worker-disassembly.log`.
The initial broad offset investigation is local only; the maintained script
exports selected worker, registration, release and immediate lower functions.

The subsequent package recovered and compared worker callback/terminal-cleanup control flow with
explicit I/O and synchronization boundaries, including already-terminal entry,
null-context fallback, callback mutations, retained nodes, and unlink cases.
State-0 probes now confirm stores 3 then 4 overwrite negative-result state 5;
real lower-call failure behavior and real failure delivery remain unclaimed.
The subsequent [I/O/completion integration](resource-worker-io-completion.md)
now executes both recovered regions with completion and retained release.
The [outer wake/stop/list loop](resource-worker-loop.md) now passes a separate
comparison with modeled node processing. Next connect it to that recovered unit.
Release routing now executes inside registry completion in the optional
`--recover-release` checker mode; see [integration evidence](resource-registry-request-release.md).
Metadata cleanup
`0x001245F0`, allocator routing `0x001244E8` and recursive synchronization
`0x002C3AFC/0x002C3A78` remain separate unrecovered dependencies. No live
gameplay, full worker, allocator or file-system implementation is claimed.
