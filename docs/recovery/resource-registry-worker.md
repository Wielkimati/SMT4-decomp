# Registry submission through the continuous worker

2026-10-07. Owner: decomp. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Dependencies: [registry submission/construction](resource-registry-request.md)
and [continuous worker/I/O/completion/release](resource-worker-connected.md).

The existing recovered sources now execute together from registry request
`0x0033C844`, through descriptor construction `0x002B0494`, then worker entry
`0x00113D58`, state-zero I/O, completion `0x00155B30`, registry publication
`0x0019F990`, cleanup and release `0x002C43B4`. The new checker links the existing
eight C files into a **2,640-byte ARMv6K unit**. No recovered game source changed
and no new contract is counted: the project remains at thirty-three bounded
entry points plus two adapted worker regions.

## Retained execution and independent checks

Each path submits one, two or three requests, then starts the worker on the same
machine memory. Packets, descriptors, list links, registry entries, formatted
paths and allocator state pass directly from the executed constructor to the
worker. Calling-register and stack setup occurs between submitted calls and
when starting the worker; the worker itself runs continuously across all three
traversals without resetting its registers, stack or memory.

The first traversal performs I/O and completes every submitted request. The
second unlinks and releases those descriptors. The third traverses the remaining
zero, one or two nonterminal neighbors, followed by a scheduled stop at the next
event wait. These neighbors are harness-created and precede submitted nodes;
all completing descriptors and callback packets are constructed by instructions.
No submission runs concurrently with the worker in this corpus.

The 324 scenarios cross request count, initial neighbor count, four lower-call
profiles, three path-mode bytes, and ascending, descending or repeated registry
IDs. Repeated ID zero submissions create separate pending requests because the
loaded pointer remains zero until completion. Each completion must receive its
own packet and publish in traversal order. Nonzero policy and unsigned
out-of-range IDs are also checked for skipped requests.

Independent oracles verify constructor writes, complete guarded descriptor and
registry memory, path formatting and modeled ASCII-to-u16 conversion arguments
and bytes, allocation flags/parameter, zero/high-bit lengths, null/non-null data,
I/O busy state, callback arguments, publication store order, successful data
detachment, packet-before-descriptor release, bidirectional list updates,
traversal order, stop-byte width, stack boundaries and saved registers.
Memory callbacks reject reads or writes after descriptor/packet release and
file-object destruction. Each instruction address must be in the selected
original ranges or rebuilt unit; rebuilt paths execute no original code.

The lower profiles include successful and negative open/read results, tagged
and untagged handles, direct and converted allocator release, changing lock
handles, and returning synchronization errors. The known state-zero error
fall-through is retained: negative I/O results store state five, then the worker
advances through state three to state four and completes. GCC eliminates the
intermediate state-three store; both store traces are checked separately.

## Evidence and reproduction

Final marker: `local/validation/registry-worker-20261007-final/COMPLETE.json`.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle scenarios | 324 |
| Submissions and completions per path | 648 each |
| Skipped registry calls per path | 972 |
| Continuous traversals across both paths | 1,944 |
| Node visits across both paths | 4,536 |
| Recovered I/O executions across both paths | 1,296 |
| Recovered releases across both paths | 2,592 |
| Checked lower I/O calls across both paths | 132,984 |
| Original instruction addresses visited | 578 |
| Maximum instructions per worker invocation | 5,905 |
| Deliberately faulty variants rejected | 7 |
| Public synthetic tests | 31 passed |

The address count is observed coverage of this corpus, not full branch coverage
of every linked contract. Earlier isolated and worker-only corpora retain their
broader individual boundary schedules. Generated GNU disassembly, executed
Ghidra listings, per-scenario results, exact commands, source/tool hashes and
binaries are under ignored `local/`.

Run Ghidra jobs sequentially against the saved read-only project:

```powershell
python tools/check_resource_registry_worker.py --output local/validation/registry-worker-next
python tools/check_resource_registry_worker.py --mutant wrong-packet --output local/validation/registry-worker-negative-next
python -m unittest discover -s tests -v
```

All seven negative controls were rejected: `wrong-packet`, `missing-backlink`,
`retain-success-data`, `clear-cleanup`, `restart-head`, `skip-reset`, and `skip-io`.
They change only generated local source copies; successful rejection requires
a scenario assertion failure, not a compiler or script-loading failure.
Markers and logs are retained under
`local/validation/registry-worker-20261007-negative-<variant>/`. The packet and
backlink variants fail constructor memory oracles; ownership/cleanup variants
fail the release boundary; the others fail traversal extent, outer-call order or
completion memory checks. All final manifest hashes were rechecked against the
then-current source, checkers and configurations. The follow-on reuse package
records regressions for its changed checkers.

## Limits and next work

Lower allocation, file open/size/seek/read/close, object destruction, string and
path conversion, synchronization, event wait/reset, delay and metadata conversion
remain explicit models. File data pointers and lengths are synthetic; real file
bytes are not loaded. Object/data allocation failure coverage is limited to the
listed schedules; object allocation succeeds here. Preterminal failure completion,
arbitrary reentrancy, concurrent submission, real timing, aborting result checks
and live gameplay are outside this package. Existing standalone evidence is
not replaced by this narrower integration corpus.

The follow-on [resubmission/reuse package](resource-registry-reuse.md) now passes
second batches after worker cleanup, allocator address reuse and interleaved
completing/nonterminal nodes. Next inspect the bounded lower allocation wrapper
at `0x002C4BD8` and its dependencies for recovery. Live G1/G2
checks remain deferred. No full reconstructed 3DS application, binary match or
native PC port is claimed.
