# Worker I/O, completion and retained cleanup

2026-10-07. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Owner: decomp. Dependencies: the separately reconstructed
[I/O region](resource-worker-io.md) and [completion integration](resource-worker-completion.md).

Subsequent integration: the [connected worker checker](resource-worker-connected.md)
adds the recovered outer loop and continuous retained list traversal. This
earlier node-pass mode remains available as `--recover-io`.

The worker checker now has a `--recover-io` mode linking the existing
`src/resource_worker_io.c` implementation into the retained worker, asynchronous
completion, registry publication, cleanup marking and release unit. Original and
rebuilt paths each execute their respective instructions throughout these
operations on the same retained machine state. Recovered game source is unchanged.
This adds no entry-point contract: the total remains thirty-two, plus two adapted
internal regions of the same partially reconstructed worker.

## Behavior established

State-zero descriptors execute object construction, path conversion orchestration,
open, size, seek, allocation selection, locked read, close and optional destruction
before the worker invokes recovered completion. Lower calls remain explicit models.
The checker verifies the complete descriptor and object at the I/O exit, then
continues execution without replacing the descriptor, packet, registry, allocator
or list state.

Completion publishes the selected data address and requested size, detaches data
on success, marks cleanup, and releases the packet through the recovered allocator
wrapper. Later worker passes subtract the persistent cleanup count and remove the
descriptor on the first or fourth subsequent pass. Terminal-entry passes do not
invoke the stale callback packet again. The existing path-callback failure cases
still publish zeros and release owned nonnull failure data during removal.

Negative modeled open/read returns temporarily store state five, but the executed
worker then reaches state four and success completion. This confirms the previous
error fall-through observation through publication, under normally returning lower
models; it does not establish actual filesystem failure delivery. A short modeled
read count does not replace requested size. Newly allocated or supplied buffers,
including zero and high-bit addresses, reach publication unchanged.

The original instructions store state three, clear the object field and store
state four. Pinned GCC eliminates the intermediate state-three store in the
rebuilt worker. The checker explicitly asserts each path's store sequence and
agreement at dependency boundaries and final state. There is no intervening call
between those original stores. Concurrent observation of this sequence remains
unverified; this is behavior comparison within the stated sequential model, not
instruction or binary matching.

## Reproduction and evidence

Run Ghidra jobs sequentially on the saved project:

```powershell
python tools/check_resource_worker_completion.py --recover-io --output local/validation/worker-io-completion-next
python tools/check_resource_worker_completion.py --output local/validation/worker-completion-regression-next
python -m unittest discover -s tests -v
```

Evidence: `local/validation/worker-io-completion-20261007-final/COMPLETE.json`.
The pinned GCC builds a **1,560-byte ARMv6K unit**. Manifests record reference,
source, checker and tool hashes; commands, independent GNU disassembly, executed
Ghidra listings and scenario parameters stay alongside the marker. The saved
Ghidra project is read-only, and rebuilt paths execute no original code.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle scenarios | 4,608 |
| Paired retained worker passes | 16,128 |
| I/O executions per path | 3,456 |
| Completion executions per path | 4,608 |
| Registry callback executions per path | 3,072 |
| Release executions per path | 9,408 |
| Converted releases per path | 3,600 |
| Checked lower I/O calls across both paths | 372,096 |
| Checked lower allocator calls across both paths | 63,648 |
| Original instruction addresses visited | 382 |
| Maximum executed instructions per pass | 2,169 |
| Deliberately faulty variants rejected | 8 |
| Public synthetic tests | 31 passed |

The 382 visited addresses comprise all 163 selected I/O instructions, all 75
instructions of the five integrated entry-point contracts, and 144 other worker
instructions. The separate worker checker covers the remaining nine selected
worker instructions, including negative synchronization and callback-replacement
cases outside this integration corpus.

The original 1,728-scenario corpus is retained; its 576 state-zero cases each
expand into six conversion profiles, giving 3,456 I/O cases and 1,152 other cases.
Four list configurations, three data addresses, two ownership modes, one/four
references, three publication configurations and four allocator profiles are
crossed. State-zero cases derive open/read results from the allocator profile,
handle from publication/ownership, construction and close side effects from list
configuration, and allocation flags/size/address from the documented fixture
indices. These cover both open/read signs, six handles, eight exact/decoy flags,
five sizes and three allocation results. This is a deterministic selected corpus,
not the Cartesian product of every lower-call parameter.

Conversion fixtures cover empty, one-unit, multi-unit and 120-unit output, plus
failure on the first or third conversion. Models mutate conversion state and
consume variable byte counts. Other scheduled effects replace the I/O lock during
read, change the handle during preclose, clear the object before its optional
destructor, change heap ranges on acquire, and change synchronization handles on
free. I/O and release use the same retained heap-lock field, so later release
observes the handle left by read/release.

Independent oracles check memory, converted path, state stores, dependency order
and arguments, publication, ownership and exact cleanup timing. Dependency
snapshots normalize relocated callbacks only. Guards enforce stack bounds,
alignment/restoration and rebuilt callee-saved registers. Lower calls poison
caller-saved registers and flags. Unexpected memory accesses, uninitialized reads,
instruction escapes and accesses after packet/descriptor free or object
destruction fail the run.

Eight deliberately faulty variants are rejected with `--recover-io --mutant`:
`skip-io`, `short-read-size`, `cached-close-handle`, `terminal-callback`,
`clear-cleanup`, `retain-success-data`, `release-before-cleanup`, and
`exclusive-endpoint`. Generated sources, assertion failures and `NEGATIVE.json`
records stay under `local/validation/worker-io-completion-20261007-negative-*/`.
They fail on dependency order, size/descriptor agreement, close-handle reload,
completion lifetime, packet-release timing or inclusive allocator endpoints.
All 31 public tests pass.

The default completion regression also passes all 1,728 scenarios / 6,048
retained passes, retaining its 1,012-byte binary and 219 original addresses.
Evidence: `local/validation/worker-io-completion-20261007-completion-regression/COMPLETE.json`.

## Remaining boundaries

The checker still begins with configured synthetic descriptors and packets.
Request submission/construction are separately checked. The subsequent
[outer-loop package](resource-worker-loop.md) reconstructs the wake/stop/list
loop with node processing modeled; connecting it to this integration is next.
The default completion
mode continues to model the entire I/O block, preserving its earlier scope.

Lower file operations, conversion, object/data allocation, recursive locks,
worker synchronization, path callback, metadata conversion and lower free remain
modeled. Object allocation success and bounded path conversion are preconditions.
Real file contents, arbitrary reentrancy, allocation reuse, concurrency, timing,
the full worker, binary matching and a native port remain unclaimed. G1/G2 stay
open and live gameplay checks remain deferred.
