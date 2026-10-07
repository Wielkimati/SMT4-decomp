# Synchronous resource chain through arbitration SVC

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This integrates thirteen existing contracts; the repository total remains
twenty-seven. Names are project descriptions, not recovered original symbols.

## Executed boundary

The [chain with signal and locks](resource-chain-signal.md) now optionally executes
the [arbitration wrapper](resource-arbitration.md) at `0x002A88FC`. The wrapper's
stack loads, register preservation and return execute inside the same emulated
thread and memory as descriptor construction, polling, signaling and cleanup.
Only its SVC `0x22` is intercepted. The original SVC address is `0x002A8908`;
the rebuilt address in this run is `0x0060054C`.

`--recover-arbitration` adds `src/resource_arbitration.c` to the existing chain
build and removes its original-address linker binding. The **1,368-byte ARMv6K
unit** executes no original instructions on the rebuilt path. No recovered C
behavior changed. Without the flag, the earlier wrapper-entry model remains
available for regression comparisons.

At every wrapper entry the harness captures SP, LR, r4-r11 and the caller's
stack. At SVC it checks the operation, handle, address, count and zero timeout
words in r4/r5 against the independent signal/lock schedule. It applies the
scheduled competing writes and worker completion, poisons r0-r5/r12 and flags,
sets the modeled result, and resumes at the wrapper's next instruction. Before
the caller resumes, the harness checks the result, callee-saved registers,
restored SP and unchanged caller stack. These checks run even when the enclosing
signal later enters a bounded retry prefix.

Timeouts are zero in these actual callers; nonzero timeout marshalling is covered
by the direct wrapper corpus. Worker completion still occurs at the arbitration
boundary, or at signal return when no arbitration occurred, and at sleep. The
outer loader must retain its signal-then-sleep ordering and ownership/cleanup
behavior. The existing descriptor, list, path and global guards remain checked.

## Reproduction and results

From `SMT4-decomp/`, with the saved Ghidra project closed, run sequentially:

```powershell
python tools/check_resource_chain_signal.py --recover-arbitration --output local/validation/chain-svc-next
python tools/check_resource_chain_signal.py --output local/validation/chain-svc-regression-next
python -m unittest discover -s tests -v
```

Successful integrated record: `local/validation/chain-svc-20261006/COMPLETE.json`.
Pinned tools/reference and Ghidra mapped-image hashes are checked, GNU original
and rebuilt disassembly is retained, and source/harness hashes are recorded.
Ghidra runs read-only; generated binaries, traces and logs remain under `local/`.
The driver requires the expected case, instruction and wrapper-return counts
before writing the success marker.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle comparisons | 3,924 |
| Returning cases | 3,659 |
| Bounded pending prefixes | 265 |
| Pending inside signal/acquire/release | 36 |
| Original instruction addresses visited | 341 |
| Maximum instructions per path | 1,249 |
| Signal calls, both paths | 25,992 |
| SVC visits and checked wrapper returns, both paths | 43,270 |
| Exclusive-store attempts, both paths | 164,498 |
| Clear-exclusive operations, both paths | 36,272 |
| Public synthetic tests | 31 passed |

The corpus and independent transition oracle are unchanged from the earlier
chain/signal checker. All six original wrapper addresses are visited, in addition
to the previous 335 chain addresses. SVC is counted as visited but intercepted
before execution; the surrounding five original instructions execute. The GCC
wrapper uses one LDRD in place of the original two LDR instructions. Instruction
visits include predicated instructions and do not imply exhaustive behavior.

Four local source mutants are rejected: setting the low timeout word to one,
narrowing count to 16 bits, invoking SVC `0x21`, and discarding the SVC result.
The result mutation is detected at the nested wrapper return even though the
signal caller does not use that result. Driver:
`local/validation/check-chain-svc-negatives.py`; evidence:
`local/validation/chain-svc-20261006-negative-*/NEGATIVE.json`. Each run checks
its expected diagnostic and absence of a success marker. Mutated sources remain
under `local/`; production sources were not changed.

The default wrapper-entry mode also passes all 3,924 cases with its earlier
1,348-byte binary and 335 original instruction addresses:
`local/validation/chain-svc-20261006-regression/COMPLETE.json`. Its event counts
remain unchanged. All recorded source/tool hashes match the final files, and all
31 public tests pass.

## Limits and next work

Kernel arbitration, actual worker/file I/O, allocation, constructor OS calls,
string operations, timing and hardware exclusive outcomes remain modeled.
Signal state is rescheduled at each call as documented in the preceding report;
this does not prove arbitrary concurrency or unscheduled inter-poll continuity.
No live gameplay evidence, binary matching, full application rebuild or native
runtime is added. G1/G2 remain open and live checks remain deferred.

The subsequent [registry-chain integration](resource-registry-chain.md) now
connects bulk and individual synchronous lifecycle callers, preserving registry
pointer/size updates and load order across nested calls. Bulk index/state and
consumed remainder execute in that integration. Keep
asynchronous request/release backends separately modeled until recovered, and
retain the explicit allocation/worker/kernel boundaries. Compiler/ABI and host
address research remain independent ready work.
