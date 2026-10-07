# Registry completion with recovered release routing

2026-10-07. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All original entry addresses are ARM. This integrates twelve existing contracts;
the repository total remains thirty-two. Recovered game source is unchanged.

## Executed boundary

The [registry asynchronous chain](resource-registry-request.md) now executes
release routing `0x002C43B4` from completion `0x00155B30`. Registry request,
asynchronous backend/wrapper, descriptor construction, callback installation,
completion, registry publication, descriptor helpers and release run together
on retained emulated memory. The rebuilt path executes no original instructions.

Completion publishes the output and runs the registry callback before marking
descriptor cleanup and releasing the request packet. Successful completion
detaches data; state-five completion retains it. The harness checks ownership
at release entry, then executes the release instructions through recursive
synchronization acquire, optional metadata conversion, allocator free and
synchronization release. Those four lower operations remain modeled.

Release uses inclusive unsigned allocator ranges after synchronization acquire.
Overflowing range endpoints admit no address under the original comparisons.
The conversion result reaches free unchanged; the synchronization handle is
reloaded after free. Allocator state persists between completions in retained
request scenarios, including all six orders of three outstanding requests.

## Corpus and reproduction

From `SMT4-decomp/`, with Ghidra jobs sequential per saved project:

```powershell
python tools/check_resource_registry_request.py --recover-release --output local/validation/registry-request-release-next
python tools/check_resource_registry_request.py --output local/validation/registry-request-regression-next
python -m unittest discover -s tests -v
```

Successful integrated record:
`local/validation/registry-request-release-20261007/COMPLETE.json`.
The **1,148-byte ARMv6 unit** builds twelve existing contracts using function
sections and linker garbage collection. The saved Ghidra project is read-only.
Reference/tool/source/harness hashes, build commands, original/rebuilt disassembly,
scenario log and exact instruction coverage are retained locally.

| Check | Result |
| --- | ---: |
| Prior eligibility/completion/retained-request scenarios | 1,163 |
| Additional range/effect/outcome combinations | 108 |
| Total original/rebuilt/oracle scenarios | 1,271 |
| Submissions/completions/release executions per path | 850 each |
| Skipped registry calls per path | 790 |
| Direct/converted release executions per path | 565 / 285 |
| Original instruction addresses visited | All 294 |
| Maximum instructions per outer call | 242 |
| Checked lower calls across both paths | 22,988 |
| Public synthetic tests | 31 passed |

The added corpus crosses twelve range profiles with three acquire effects and
three completion outcomes (nonnull success, null success, state-five failure).
Profiles cover both ranges' exact starts/ends, zero lengths, excluded neighboring
addresses, overlap, the full unsigned interval and overflowing endpoints.
Acquire can replace initially accepting or rejecting ranges before returning.
Free changes the synchronization handle, checking the subsequent reload.
Conversion models return zero, one, high-bit and maximum unsigned words.

The oracle checks all modeled memory and guards, exact registry publication
order, external stores as byte multisets, lower-call order/arguments, SP,
integer callee-saved registers, d8 and caller stack preservation. Lower boundaries
poison caller-saved integer registers and condition flags. Extra lower calls,
missing lower calls and original instructions on the rebuilt path fail the run.

Five local mutants are rejected: exclusive first endpoint, discarded conversion
result, cached synchronization handle, widened first endpoint addition, and
packet release before marking descriptor cleanup. The driver is
`local/validation/check-registry-request-release-negatives.py`; each
`registry-request-release-20261007-negative-*/NEGATIVE.json` records the diagnostic,
mutant hash and absence of a success marker. Production source remains unchanged.

The default-mode regression also passes all 1,163 scenarios, with the prior
1,036-byte binary and 266 original instruction addresses:
`local/validation/registry-request-release-20261007-regression/COMPLETE.json`.

## Limits and next work

The harness supplies valid disjoint packet/descriptor fixtures and scheduled
completion states after submission returns. Allocator routing profiles and
conversion results are artificial wrapper tests; they do not establish that
those addresses represent real allocations. Lower metadata destruction, free
lists, reuse, recursive locks, worker scheduling, descriptor destruction, file I/O,
callback reentrancy and concurrency remain unrecovered or modeled. The modeled
free does not destroy packet contents. Live gameplay and binary matching remain
unclaimed; G1/G2 are still open.

Default checker mode retains the earlier intercepted-release boundary. Other
request/lifecycle checkers still intercept release. The subsequent
[bounded worker step](resource-worker-step.md) now has source/comparison evidence
and separate original state-zero error probes. Its
[completion/release integration](resource-worker-completion.md) now checks
retained cleanup passes in a separate harness. This registry submission checker
still models worker dispatch; connecting both harness boundaries remains open.
