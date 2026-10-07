# Registry resubmission and allocator address reuse

2026-10-07. Owner: decomp. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Extends [registry-to-worker integration](resource-registry-worker.md).

Subsequent integration, 2026-10-07: `--recover-allocation --resubmit` now executes
both recovered allocation layers during these retained batches. See
[allocation integration](resource-registry-allocation.md) for metadata ownership,
nested lock/clear ordering, backlink conversion models and 324 passing scenarios.
The default mode and historical evidence below retain allocation interception.

The existing recovered registry, constructor, worker, I/O, completion and release
sources pass two successive request batches on retained machine memory. The
**2,640-byte ARMv6K binary is unchanged** from the earlier integration, SHA-256
`f34e1c9548c3a1180e20c11d0615c27e45ae8f70028715f0921127b75a55efaa`.
This package changes comparison tooling, not recovered game source. The total
remains thirty-three bounded entry points plus two adapted worker regions.

## Retained state and explicit scheduling

The 324 scenarios cross one to three requests per batch, zero to two nonterminal
neighbors, four lower-call profiles, path-mode bytes 0/1/255, and ascending,
descending or repeated registry IDs. Both original and rebuilt paths execute:

1. Submit the first batch through registry request `0x0033C844` and constructor
   `0x002B0494`. For this corpus, the harness inserts state-one pending neighbors
   after successive submissions, while the worker is stopped. Subsequent requests
   append through constructor instructions. This produces completing nodes both
   before and after pending nodes, including middle-node removal and survivor
   backlink updates. The fixture insertions are modeled, not recovered submissions.
2. Invoke worker `0x00113D58` continuously for three traversals: I/O and completion,
   descriptor cleanup, then surviving pending nodes. Stop at the fourth wait.
3. Call the registry again for each distinct entry whose pointer is nonzero.
   Those requests must return successfully without allocation, even after their
   completed descriptors have been freed.
4. Start the second batch without rebuilding descriptor, registry, path, heap or
   neighbor memory. Reissue prior IDs whose pointer and policy are zero; use fresh
   IDs 10 onward for the others. Policy-one entry 65 remains ineligible when null.
   Old registry sizes remain untouched until a new completion publishes its size.
5. The allocator model returns the freed descriptor addresses in reverse order
   and packet addresses rotated by one. Old bytes and guards remain present;
   an address becomes live only when its allocation call returns. Recovered
   construction must clear and initialize it, including its list links and new
   callback context. Data-result addresses use a distinct range in the second batch.
6. Invoke the worker for another three continuous traversals and check completion,
   cleanup, surviving list links and all guarded memory again.

The CPU register/stack call setup is renewed for submissions and each worker
invocation. Each worker invocation retains registers, stack and memory across
its own traversals. Restarting the stopped worker and clearing its stop byte are
explicit scheduler models. This is serialized resubmission after cleanup, not
concurrent submission or an uninterrupted worker across both batches.

The independent memory and boundary oracles from the earlier integration remain.
Lifetime checks reject any instruction access overlapping a freed descriptor or
packet until allocation returns that address. They remain active during the
second submission batch. The original/rebuilt I/O, release and reuse event orders
must agree. Local `results.tsv` records each scenario's final IDs, descriptor and
packet assignments and the complete I/O/release/reuse event sequence.

## Evidence and reproduction

Final marker: `local/validation/registry-reuse-20261007-final/COMPLETE.json`.
All counts below combine the original and rebuilt paths unless stated otherwise.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle scenarios | 324 |
| Submissions and completions | 2,592 each |
| Reused allocations in second batches | 2,592 |
| Resubmissions of prior null-result IDs | 414 |
| Loaded-entry skips after cleanup | 684 |
| All skipped calls, including bounds/policy | 2,628 |
| Continuous worker traversals | 3,888 |
| Node visits | 9,072 |
| Worker invocations with a pending node between requests | 288 |
| Recovered I/O executions | 2,592 |
| Recovered packet/descriptor release executions | 5,184 |
| Checked lower I/O calls | 285,768 |
| Original instruction addresses visited | 578 |
| Maximum instructions per worker invocation | 9,841 |

Run Ghidra jobs sequentially against the saved read-only project:

```powershell
python tools/check_resource_registry_worker.py --resubmit --output local/validation/registry-reuse-next
python tools/check_resource_registry_worker.py --resubmit --mutant skip-reused-clear --output local/validation/registry-reuse-negative-next
python tools/check_resource_registry_worker.py --output local/validation/registry-worker-regression-next
python tools/check_resource_registry_request.py --recover-release --output local/validation/registry-request-regression-next
python -m unittest discover -s tests -v
```

Nine faulty variants are rejected by scenario assertions: `skip-reused-clear`,
`missing-next-backlink`, `wrong-packet`, `missing-backlink`, `retain-success-data`,
`clear-cleanup`, `restart-head`, `skip-reset`, and `skip-io`. The first specifically
skips descriptor clearing when reused memory still contains terminal state four;
the second omits the surviving next node's backlink update. Mutations affect only
local generated copies. Compilation/script failures do not count as rejection.
Evidence is under `local/validation/registry-reuse-20261007-negative-<variant>/`.

The default 324-scenario worker corpus and 1,271-scenario registry/request/release
corpus pass with the shared allocation hooks. Their markers are under
`local/validation/registry-reuse-20261007-worker-regression/` and
`local/validation/registry-reuse-20261007-request-regression/`. All 31 public
synthetic tests pass.

## Limits and next work

The allocator chooses addresses in the harness; its implementation is not
recovered. Lower file, allocation, synchronization, string/conversion, event and
delay calls remain models. Nonterminal neighbors do not transition to completion
in this corpus. There is no concurrent submission, real file data, real timing,
allocation-failure expansion, registry data unloading, hardware or live gameplay
agreement. Earlier standalone boundary coverage remains separate evidence.

Next recover a bounded lower dependency, beginning with inspection of the
constructor's allocation wrapper `0x002C4BD8`. Raw ARM disassembly shows lock
acquire `0x002C3AFC`, five-argument forwarding to `0x002C5544`, a conditional
non-null call to `0x002C3B9C`, lock-handle reload/release `0x002C3A78`, and return
through `0x002C4C3C`. The conditional call's semantics and allocator beneath it
still need inspection; this is a candidate, not another recovered contract.
Live G1/G2 checks remain deferred. No PC-port source transfer or native runtime
was added.
