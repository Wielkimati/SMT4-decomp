# Worker completion, publication and retained cleanup

2026-10-07. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This integrates the adapted [worker region](resource-worker-step.md) with five
existing entry-point contracts. The total remains thirty-two recovered entry
points plus one bounded region. Recovered game source is unchanged.

## Executed behavior

The worker region beginning at `0x00113DE8` now calls recovered asynchronous
completion `0x00155B30`, failure test `0x0014E634`, registry publication
`0x0019F990`, cleanup marking `0x002B0468`, and release routing `0x002C43B4`.
Both original and rebuilt paths execute these instructions together. The rebuilt
path executes no original code. Each path retains its own descriptor, packet,
neighbors, registry and allocator state across later worker passes.

Completion publishes the address before calling the registry callback, which
stores address and size. Success detaches the descriptor's data; state-five
failure publishes zeros and retains the data. Completion increments the cleanup
count and releases the packet through the recovered allocator wrapper. The
worker subsequently returns the next link without freeing the descriptor in
that same pass.

Later terminal-entry passes skip completion, even though the callback fields
still refer to the now-freed packet. Each pass subtracts the persistent cleanup
count from the reference count. Fixtures starting with one or four references
free on the first or fourth subsequent pass respectively. Removal fixes the
head/neighbor links, releases nonnull owned failure data, clears the data field,
then releases the descriptor. The next link is returned without reading the
freed descriptor.

Release routing executes for packet, data and descriptor releases. Lower heap
acquire can replace its ranges; lower free changes both synchronization handles.
This checks the allocator's range reads after acquire, its inclusive endpoints,
converted-address forwarding, and both wrappers' handle reloads.

## Reproduction and evidence

From `SMT4-decomp/`, with Ghidra jobs sequential per saved project:

```powershell
python tools/check_resource_worker_completion.py --output local/validation/worker-completion-next
python tools/check_resource_worker.py --output local/validation/worker-step-regression-next
python -m unittest discover -s tests -v
```

Evidence: `local/validation/worker-completion-20261007-final/COMPLETE.json`.
The pinned GCC builds a **1,012-byte ARMv6K unit** with function-section garbage
collection. Reference, source, harness and tool hashes, build commands, independent
GNU disassembly, Ghidra's executed listing and scenario parameters are recorded.
The saved Ghidra project is opened read-only.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle scenarios | 1,728 |
| Paired retained worker passes | 6,048 |
| Completion executions per path | 1,728 |
| Registry callback executions per path | 1,152 |
| Release executions per path | 3,648 |
| Direct / converted releases per path | 2,208 / 1,440 |
| Checked lower allocator calls across both paths | 24,768 |
| Original instruction addresses visited | 219 |
| Maximum instructions per worker pass | 155 |
| Public synthetic tests | 31 passed |

The 219 visited addresses comprise all 75 instructions in the five integrated
contracts and 144 of the 153 selected worker-region instructions. The standalone
worker checker retains coverage of all 153, including returning negative
synchronization results and callback replacement cases outside this corpus.

The corpus crosses four list configurations; three completion paths (state zero
with modeled I/O, state three, and a path callback changing state one to five);
null/low/high-bit data; owned/external buffers; one/four initial references;
output plus callback/output only/callback only; and four allocator profiles.
Those profiles cover a full unsigned range, an overflowing rejecting range,
packet/descriptor exact zero-length endpoints, and ranges changed on acquire.
The state-zero model stores five, then the executed worker overwrites it with
three/four; the scheduled failure case comes from the path callback, not an
assertion that real file errors deliver state five.

Independent final-memory oracles check descriptor and neighbor bytes, registry
publication, packet preservation, list head, opaque worker globals, ownership,
release order and exact cleanup timing on every pass. Original/rebuilt snapshots
at dependency boundaries also check operation ordering and allocator state.
Only relocated callback addresses are normalized for comparison. Stack guards,
rebuilt callee-saved registers, call alignment and both paths' stack restoration
are checked. Lower calls poison caller-saved integer registers and flags.
Uninitialized accesses, unexpected stores, instruction-range escapes, duplicate
completion and packet/descriptor accesses after lower free fail the run.

Five deliberately faulty variants are rejected with `--mutant`:
`terminal-callback`, `clear-cleanup`, `retain-success-data`,
`release-before-cleanup`, and `exclusive-endpoint`. Their generated source and
`NEGATIVE.json` records stay under
`local/validation/worker-completion-20261007-negative-*/`.
The unchanged standalone worker regression passes 3,472 comparisons and its
160 original-only I/O probes under
`local/validation/worker-completion-20261007-step-regression/`.

## Remaining boundaries

Subsequent recovery: [state-zero I/O](resource-worker-io.md) now has a separate
3,456-case original/rebuilt comparison. The optional `--recover-io` mode now
[integrates it with this checker](resource-worker-io-completion.md): 4,608 scenarios
and 16,128 retained passes. The default mode described in this report continues
to model that block.

This checker begins with configured synthetic descriptors and request packets;
it does not execute request submission or descriptor construction. Those remain
covered separately by the [registry/request/release checker](resource-registry-request-release.md),
whose worker dispatch model is unchanged. The single-node region uses the
existing adapted entry/exit interface; the outer thread and list traversal
remain unrecovered.

State-zero I/O, path callback, worker synchronization, recursive heap locks,
metadata conversion and lower free remain modeled. Freed allocations are marked
inaccessible to executed instructions but their backing bytes are retained for
inspection. Allocation reuse/destruction, arbitrary callback reentrancy,
concurrency, timing, full worker behavior, binary matching and live gameplay are
unclaimed. G1/G2 stay open and live gameplay remains deferred.

Next recover the outer worker wake/stop/list loop. Connecting submission,
this step and traversal is a separate integration.
