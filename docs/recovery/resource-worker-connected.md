# Continuous worker, I/O and completion integration

2026-10-07. Owner: decomp. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Dependencies: the [outer loop](resource-worker-loop.md) and
[retained I/O/completion/release unit](resource-worker-io-completion.md).

`tools/check_resource_worker_completion.py --recover-loop` links the existing
outer loop, node, I/O, completion, publication, cleanup and release source into
one ARM unit. The original path starts at `0x00113D58`; the rebuilt path starts
at `smt4_file_worker`. Both execute continuously through successive traversals
and return after a scheduled stop. No game-source changes or new entry-point
contracts are added: the total remains thirty-three plus two adapted regions.

## Connected behavior and corpus

The corpus retains all 4,608 I/O/completion scenarios, including conversion,
allocation, ownership, output and one/four-reference combinations. Four list
configurations put the completing descriptor alone, first, last or between two
other descriptors. These neighbors have nonterminal state one and no callbacks;
their node instructions execute normally. There is one completing descriptor
per scenario, not multiple independent completions or submissions.

One worker invocation processes every pass without resetting registers, stack,
memory, allocator state, callback packet or list links between passes. At the
event-reset boundary the checker pauses instruction stepping only to inspect
oracles; it models the call return and resumes the same machine state. The
completed descriptor is removed on its first or fourth subsequent traversal.
An extra full traversal checks the remaining list after removal, including an
empty list when there were no neighbors. Delay and event-wait then execute,
the wait model sets stop byte `0x80`, and the worker restores its stack/registers
and returns.

Independent oracles check traversal order, publication, ownership, cleanup
timing, backlinks, head updates and release order. Dependency snapshots compare
descriptor/neighbor, packet, registry, worker-global and allocator memory across
both paths. Only relocated callback addresses are normalized. Lower calls
poison caller-saved registers and condition flags; free models alter shared
handles, exercising reloads across I/O, cleanup and outer-loop boundaries.
One allocator profile also returns negative synchronization results at every
acquire/unlock; the original and rebuilt result checkers return normally.

The existing I/O oracles retain conversion-state, object, busy-flag, argument,
error-fall-through and state-store checks. Original state-three/four stores and
GCC's eliminated intermediate store remain explicitly distinguished. Guards
reject accesses after packet/descriptor free or object destruction, unexpected
memory access, instruction escapes, stack damage and incorrect stop-byte width.
Both paths must restore callee-saved registers at final worker return.

## Reproduction

Run Ghidra jobs sequentially on the saved read-only project:

```powershell
python tools/check_resource_worker_completion.py --recover-loop --output local/validation/worker-connected-next
python tools/check_resource_worker_completion.py --recover-io --output local/validation/worker-connected-io-regression-next
python -m unittest discover -s tests -v
```

The loop flag implies `--recover-io`. Existing node-only and I/O modes remain
available. Manifests retain hashes of the reference, source, checker and pinned
tools, build commands, independent GNU disassembly and executed Ghidra listings.
Generated data stays under ignored `local/`; rebuilt paths execute no original
code.

## Evidence

Final comparison: `local/validation/worker-connected-20261007-final/COMPLETE.json`.
The pinned GCC builds a **1,792-byte ARMv6K unit**.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle scenarios | 4,608 |
| Paired continuous traversal passes | 20,736 |
| Executed node visits across both paths | 73,728 |
| Outer wait/reset/delay calls across both paths | 133,632 |
| Returning synchronization-error checks across both paths | 69,696 |
| I/O executions per path | 3,456 |
| Completion executions per path | 4,608 |
| Registry callback executions per path | 3,072 |
| Release executions per path | 9,408 |
| Converted releases per path | 3,600 |
| Checked lower I/O calls across both paths | 372,096 |
| Checked lower allocator calls across both paths | 63,648 |
| Selected original instruction addresses visited | 439 of 439 |
| Maximum executed instructions per full invocation | 3,235 |
| Deliberately faulty variants rejected | 7 |
| Public synthetic tests | 31 passed |

Coverage includes all 364 selected worker instructions and all 75 instructions
of the five integrated completion/publication/cleanup/failure/release contracts.
Worker ranges are `0x00113D58..0x00113E70`, `0x00113E80..0x001142E8` and
`0x00114340..0x00114370`, with exclusive endpoints. Literal pools and unselected
bytes are not counted as instructions. The preliminary `worker-connected-20261007-first`
run passed with 430 addresses before returning-error schedules were added;
the final run covers the nine additional error-path instructions.

All seven `--recover-loop --mutant` variants are rejected: `restart-head`,
`skip-reset`, `wrong-delay`, `terminal-callback`, `retain-success-data`,
`clear-cleanup` and `skip-io`. Markers and assertion logs are retained under
`local/validation/worker-connected-20261007-negative-<variant>/`. The missing
reset variant exceeds the bounded instruction budget without reaching the
required traversal boundary; the others fail state, order, argument or lifetime
assertions. The generated faulty sources remain local.

The earlier `--recover-io` mode also passes unchanged: 4,608 scenarios, 16,128
retained node passes, 382 original instruction addresses and the same 1,560-byte
binary as its prior evidence. Regression marker:
`local/validation/worker-connected-20261007-io-regression/COMPLETE.json`.

## Limits and next work

Follow-up: [registry-to-worker integration](resource-registry-worker.md) now
connects executed submission/construction to this worker with up to three
completing descriptors. The limits below describe this earlier corpus.

Connect registry submission and descriptor construction to this worker traversal,
then exercise multiple completing descriptors and their separate callback packets.
The current descriptors and registry are harness-created. Lower file/conversion,
allocation, event wait/reset, synchronization, delay and path callback calls are
still models. Negative result checkers return in this corpus; aborting behavior
is outside its scope. Real filesystem bytes, concurrency, arbitrary reentrancy,
blocking/nonterminating executions, timing and live gameplay remain unverified.
The stop schedule here is after the final traversal; the separate outer-loop
checker retains its broader stop/head-mutation schedules.

This is bounded integration evidence, not a full reconstructed worker dependency
tree, 3DS application, binary match or native port. Live G1/G2 evidence remains
deferred, and no emulator, profile, save or original input is changed.
