# Resource release routing

2026-10-06, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x002C43B4` is reconstructed in `src/resource_release.c`. This adds
one analyzed, understood, implemented, buildable and bounded behavior-verified
contract, bringing the repository total to thirty-two. Binary matching and live
gameplay verification remain unclaimed.

## Contract and boundaries

`smt4_resource_release(uint32_t address)` uses allocator state at `0x00465120`:

1. Acquire the recursive synchronization object whose address is stored at `+4`,
   through `0x002C3AFC`.
2. Read the two bases at `+0x24/+0x28` and lengths at `+0x34/+0x38`. An address
   inside either inclusive unsigned interval `[base, base+length]` goes directly
   to the lower free routine. Sums wrap at 32 bits: a wrapped end below its base
   accepts no addresses. A zero-length interval accepts its base.
3. Outside both intervals, call `0x001245F0` and use its returned address.
4. Call lower allocator routing `0x001244E8` once with the selected address.
5. Reload the synchronization object at `+4` and release it through `0x002C3A78`.

There is no null guard or defined return-value contract. The wrapper itself
does not write allocator state or dereference the supplied address. Lower calls
can have effects. In particular, static inspection shows `0x001245F0` reads a
header pointer at `address-4`, updates accounting/list metadata, and returns that
header; its project name `smt4_resource_release_convert` does not mean it is pure.
The lower allocator uses its own ranges and free operations. Those implementations
and validity requirements are not reconstructed by this package.

## Validation

```powershell
python tools/check_resource_release.py --output local/validation/release-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/release-20261006/COMPLETE.json`.
The separate **112-byte ARMv6K unit** executes no original code on the rebuilt
path. Both paths model the same four lower boundaries. Tool, source and reference
hashes, original/rebuilt disassembly and exact original coverage are recorded.
Ghidra opens the saved project read-only; jobs must run sequentially per project.

| Check | Result |
| --- | ---: |
| Boundary scenarios across 100 pairs of range profiles, three acquire effects | 2,592 |
| Deterministic full-width random scenarios | 1,024 |
| Total original/rebuilt/oracle comparisons | 3,616 |
| Direct-address / converted-address cases | 1,517 / 2,099 |
| Original instruction addresses visited | All 28 |
| Maximum instructions per call | 28 |
| Checked lower calls across both paths | 25,894 |
| Public synthetic tests | 31 passed |

The independent oracle uses non-wrapping mathematical intervals and rejects
overflowing endpoints. Cases include zero, maximum unsigned, sign boundaries,
overlapping/disjoint/identical ranges, zero lengths, and each endpoint's neighbors.
The acquire model can change ranges before returning; the free model changes the
synchronization object, testing the subsequent reload. Conversion results include
zero, one, high-bit and maximum values. Caller-saved integer registers and flags
are poisoned at every boundary. Checks cover call order/arguments, unchanged
allocator state and guards except for modeled changes, unexpected accesses/stores,
SP/callee-saved registers, d8 preservation, and stack guards.

Four local mutants are rejected: exclusive first endpoint, discarded conversion
result, cached synchronization object, and widened first endpoint addition.
The driver is `local/validation/check-release-negatives.py`; per-mutant
`release-20261006-negative-*/NEGATIVE.json` records the diagnostic and absence
of a success marker. Production source is unchanged by mutation checks.

## Limits and next work

2026-10-07 continuation: release routing now executes inside registry asynchronous
completion with `check_resource_registry_request.py --recover-release`.
All 1,271 integrated scenarios and 294 original instruction addresses pass;
see [integration evidence](resource-registry-request-release.md). The standalone
contract and lower models documented here remain unchanged.

The models deliberately accept arbitrary address words to test wrapper routing;
they do not establish that those words are valid real allocations. No free-list
reuse, metadata destruction, recursive-lock implementation, concurrency, file I/O
or actual release of game memory is validated. Existing lifecycle/request
checkers and default registry-request mode still intercept `0x002C43B4`.

The [worker trace](resource-worker.md) identifies the actual descriptor callback
and later cleanup paths. Continue with bounded worker reconstruction while
retaining explicit lower models.
Live evidence and G1/G2 remain deferred and unpassed.
