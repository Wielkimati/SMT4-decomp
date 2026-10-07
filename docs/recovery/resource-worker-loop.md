# Resource worker outer loop

2026-10-07. Owner: decomp. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Dependencies: the [node region](resource-worker-step.md) and its separately checked
[I/O/completion integration](resource-worker-io-completion.md).

Subsequent integration: the [connected worker checker](resource-worker-connected.md)
now executes this loop with node/I/O/completion/release in one continuous
invocation. Its 4,608 scenarios and 20,736 traversals pass; the standalone
loop comparison documented below retains its modeled-node boundary.

`src/resource_worker_loop.c` reconstructs entry `0x00113D58` and its outer
wait/stop/list loop. This adds a bounded entry-point contract, bringing the total
to thirty-three, plus the two existing adapted internal regions. The checker
models node processing on both paths; it does not yet execute the outer loop
together with recovered I/O, completion and release. Full-worker integration
remains unverified.

## Observed contract

- Call `0x002C367C` with event object `0x00465024` before testing stop, including
  when stop was set before entry. The lower call is named event-wait provisionally;
  its blocking behavior is outside this comparison.
- Read the stop **byte** at `0x00465000`; any nonzero value exits. Neighboring
  nonzero bytes do not stop the worker.
- Snapshot synchronization handle `0x00465010`, acquire one handle with wait-all
  zero and timeout `UINT64_MAX`, then read list head `0x0046500C`. Reload the
  synchronization handle for unlock. For either negative result, call checker
  `0x002C54BC` with the result and `1`; if that checker returns, processing resumes.
  Nonzero positive results do not call the checker.
- Retain the selected head across unlock. Read stop before each node and after
  the final node returns null. Continue from the node region's returned next
  pointer, not from a fresh global-head read.
- At an unstopped list end, call `0x00138F5C` on the same event object, then
  request signed 64-bit delay `3000000` through `0x002BB4F0`, then wait again.
  The event operation is named reset provisionally. A stop set during reset still
  allows delay and the next wait before exit; a stop set during delay still
  allows the next wait. No actual elapsed time is established here.

Source uses a volatile byte for explicit stop observations. This preserves the
tested access width and repeated reads; it is not a portable host concurrency
implementation. The original checks null-node before branching on its already
loaded stop byte; source checks the byte before null-node. Both have the same
observable calls and reads within the stated model.

## Reproduction and evidence

Run Ghidra jobs sequentially on the saved project:

```powershell
python tools/check_resource_worker_loop.py --output local/validation/worker-loop-next
python -m unittest discover -s tests -v
```

Evidence: `local/validation/worker-loop-20261007-final/COMPLETE.json`.
The pinned GCC builds a **232-byte ARMv6K unit**. The saved project is opened
read-only. Reference/source/tool/checker hashes, build commands, independent GNU
disassembly, executed Ghidra listings and scenario traces accompany the marker.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle scenarios | 3,456 |
| Original outer-loop instruction addresses visited | 53 of 53 |
| Modeled node visits across both paths | 13,440 |
| Checked lower calls across both paths | 72,576 |
| Maximum executed instructions per invocation | 192 |
| Deliberately faulty variants rejected | 7 |
| Public synthetic tests | 31 passed |

The corpus crosses twelve stop schedules, zero/one/three nodes, one/three passes,
four acquire/unlock result-sign combinations, stop bytes `1/128/255`, and four
head-mutation configurations. Some combinations terminate before reaching their
selected node or error-check stop event; those reach the scheduled final wait.
An initially set stop can also be cleared by the first wait. Both empty and
nonempty lists stop after acquire/unlock or their returning result checkers.

Every modeled boundary changes the shared lock handle. Acquire can replace a
decoy list head; unlock can replace the global head after it was captured. A
separate orchestration oracle predicts ordered boundary events and node addresses.
Original/rebuilt comparisons check snapshots of all 64 fixture-global bytes at
each event and final state. Lower calls poison caller-saved registers and flags.
The node adapter returns through the original region boundary using `r7`, or the
rebuilt C return using `r0`. It does not execute node instructions.

Guards check byte-width stop reads, allowable memory accesses, stack alignment,
stack restoration, callee-saved registers, lower stack guards, uninitialized reads,
instruction bounds and complete selected-instruction coverage. Rebuilt paths
execute no original code. Executed original ranges are `0x00113D58..0x00113DE8`,
`0x001142D4..0x001142E8`, and `0x00114340..0x00114370`, with exclusive endpoints.

All seven `--mutant` variants are rejected: `stop-before-wait`, `cached-handle`,
`head-after-unlock`, `ignore-node-stop`, `skip-reset`, `wrong-delay`, and
`positive-is-error`. Generated mutated sources, assertion failures and
`NEGATIVE.json` markers remain under
`local/validation/worker-loop-20261007-negative-<variant>/`.
The preliminary `worker-loop-20261007-first` comparison passed, but its Python
wrapper initially expected 54 instruction addresses instead of the actual 53.
That run has no completion marker; the final run uses the corrected coverage
count and an added node-boundary stack-alignment assertion.

## Remaining work

Connect this outer loop to the recovered node/I/O/completion/release unit and
exercise multiple descriptors on retained lists. Then connect submission and
descriptor construction to worker traversal. Event wait/reset internals,
lower synchronization, actual file data and allocations, arbitrary reentrancy,
blocking/nonterminating executions, concurrency and timing remain unverified.
The earlier node and I/O source/checkers were not changed in this package.
G1/G2 live evidence remains deferred; no native port or complete reconstructed
3DS application is claimed.
