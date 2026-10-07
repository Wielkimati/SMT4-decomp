# Registry callers through the synchronous resource chain

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This integrates seventeen existing contracts. The repository total remains
twenty-seven; names are project descriptions, not recovered original symbols.

## Executed boundary

The individual synchronous lifecycle caller at `0x00297714` and bulk loader at
`0x0033C8A0` now execute the [synchronous chain through SVC](resource-chain-svc.md).
Bulk calls also execute the consumed index helper at `0x0029706C` and remainder
at `0x002C61B0`. Registry callers, permutation, descriptor construction, polling,
signal, locks and arbitration marshalling execute on the same emulated thread
and memory. No original instructions execute on the rebuilt path.

`tools/check_resource_registry_chain.py` builds a **1,760-byte ARMv6K unit**.
Function sections and linker garbage collection exclude the unexercised
asynchronous request, release and completion wrappers from this integration.
No recovered function behavior changed; existing comparison harnesses gained
address and nested-call hooks with their previous defaults retained.

The independent oracle calculates the 33 PRNG advances, permutation, eligible
registry IDs and final registry bytes. It checks actual index/remainder arguments
and global state, then observes each call into the real synchronous wrapper.
It does not replace that call or reset its CPU state. Each nested return must
restore the caller's SP, callee-saved registers and entire caller stack.

Every load gets a distinct modeled allocation. Earlier descriptors remain in the
same linked list, with their contents, forward links and backlinks checked across
later loads. At the registry boundary, the oracle checks size publication before
pointer publication, exact byte-store order, opaque fields, adjacent guards and
all input paths. A null successful result still preserves the individual caller's
return value of one. A failure publishes zero size and zero pointer. Bulk loading
continues after either result; loaded and policy-ineligible entries stay intact.

The allocation model supplies fresh bytes and addresses but does not implement an
allocator. Worker completion, strings, constructor synchronization, timing, SVC
results and exclusive outcomes retain their explicit models. Signal schedules
are reset per signal call, as in the preceding checker. Constructor handle/path
mode inputs are supplied per load. These are controlled scenarios, not evidence
of arbitrary concurrency or an operational file loader.

## Corpus and reproduction

From `SMT4-decomp/`, run Ghidra jobs sequentially with its saved project closed:

```powershell
python tools/check_resource_registry_chain.py --output local/validation/registry-chain-next
python tools/check_resource_chain_signal.py --recover-arbitration --output local/validation/registry-chain-svc-regression-next
python tools/check_resource_chain.py --output local/validation/registry-chain-regression-next
python -m unittest discover -s tests -v
```

The driver pins the reference and tool hashes, verifies the Ghidra mapped bytes,
retains original/rebuilt disassembly and checks corpus counts before writing
`COMPLETE.json`. It records source/harness hashes. Ghidra remains read-only;
generated binaries, fixtures and traces stay under ignored `local/`.

Individual fixtures cover all 67 IDs and five unsigned out-of-range IDs, loaded
and null pointers, policy bytes 0/1/128/255, successful/non-null, successful/null
and failed results. Bulk fixtures use eight PRNG seeds, six registry profiles
and the same three outcomes. Paths include empty strings, ordinary paths,
prefixes, colons at the scan boundary and a 250-character path. Modes are
0/1/255; sizes include zero, maximum unsigned and high-bit values.

Thirty additional cases stop in bounded pending prefixes: six individual and
twenty-four bulk cases. They stop either in the wait loop or inside an exclusive
retry, at bulk load positions 0, 1, 33 and 66. Completed earlier entries remain
published; the current entry retains its stale size/null pointer, and later
entries are untouched. This checks partial progress without claiming liveness.

Successful record: `local/validation/registry-chain-20261006-verified/COMPLETE.json`.

| Check | Result |
| --- | ---: |
| Individual original/rebuilt/oracle comparisons | 1,734 |
| Bulk original/rebuilt/oracle comparisons | 168 |
| Returning cases | 1,872 |
| Bounded pending prefixes | 30 |
| Original instruction addresses visited | 479 |
| Nested loads entered, both paths (including pending) | 12,366 |
| Index calls, both paths | 11,088 |
| Signal calls, both paths | 25,062 |
| SVC visits and checked wrapper returns, both paths | 38,544 |
| Maximum steps in one outer or nested segment | 8,613 |
| Public synthetic tests | 31 passed |

All 67 instruction addresses in the two registry callers are visited, as are
all 341 addresses in the prior chain/SVC corpus. Index/remainder coverage remains
bounded to the consumed positive domain; exact addresses are in `visited.txt`.
SVC is intercepted before execution. Instruction visits include predicated
instructions and do not imply exhaustive behavior.

Four local source mutants are rejected: passing the pointer field instead of
the size field, making an individual null result return failure, stopping bulk
loading on the first null result, and treating high-bit policy bytes as inactive.
The driver is `local/validation/check-registry-chain-negatives.py`; each
`registry-chain-20261006-negative-*/NEGATIVE.json` records its diagnostic and
confirms that no success marker was written. Production sources were unchanged.

The prior 3,924-case chain/SVC regression passes unchanged in
`local/validation/registry-chain-20261006-svc-regression/COMPLETE.json`.
The 3,888-case earlier chain regression also passes in
`local/validation/registry-chain-20261006-chain-regression/COMPLETE.json`.
All 31 public tests pass. The marker records the source/harness hashes used for
that run. A subsequent header-comment change and current-source regression are
recorded in [request recovery](resource-request.md).

## Limits and next work

Actual worker/file I/O, allocation, asynchronous request/release backends, kernel
behavior and hardware concurrency remain unrecovered. The remainder retains its
adapted C r0 return interface and positive consumed domain. Full signed/zero
division ABI, original compiler identity and host address boundaries stay open.
No live gameplay, binary matching, full 3DS rebuild or native runtime is added.
G1/G2 remain open; live checks remain deferred.

The subsequent [request recovery](resource-request.md) reconstructs asynchronous
submission and completion, including descriptor ownership and callback setup.
Its [registry lifecycle and constructor integration](resource-registry-request.md)
now passes 1,163 scenarios under explicit lower dependency models. Next trace
worker dispatch. Keep release backend `0x002C43B4` separate until recovered.
The independent compiler/ABI and host-address work remains ready.
