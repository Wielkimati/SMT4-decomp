# Integrated synchronous resource chain

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This package integrates existing recovered source; it adds no new entry-point
contracts to the twenty-three already recorded.

## Executed boundary

The synchronous backend `0x002C5E90`, wrapper `0x002C3344`, four descriptor
helpers, constructor `0x002B0494`, wait loop `0x001181B0` and delay selector
`0x002BB4F0` now build together in an **868-byte ARMv6 unit**. Both comparison
paths execute their own constructor and wait instructions. The original calls
the delay selector; GCC specializes its constant duration to the sleep boundary.
The rebuilt path executes no original instructions. Existing source needed no
behavior changes to compose successfully.

Sources: [synchronous loader](../../src/resource_sync.c),
[descriptor helpers](../../src/resource_descriptor.c),
[constructor](../../src/resource_create.c), [wait/delay](../../src/resource_wait.c).
The original addresses, instruction-derived contracts and individual comparison
domains remain in [sync](resource-sync.md), [create](resource-create.md) and
[wait](resource-wait.md). Their older checkers retain their original boundaries.

The integrated checker still models buffer clearing, prefix probing, length,
copying and formatting, allocation, handle acquisition/release, the returning
result handler, signal and sleep. These models validate arguments and order on
both paths. They do not implement actual file I/O, allocation, OS scheduling,
arbitration or formatting. In particular, input paths here contain no format
directives. Signal/sleep models inject scheduled descriptor state/data/length
changes; they do not reconstruct the worker that supplies those changes.

## Comparison evidence

With the saved Ghidra project closed, from `SMT4-decomp/`:

```powershell
python tools/check_resource_chain.py --output local/validation/chain-next
python -m unittest discover -s tests -v
```

Successful record: `local/validation/chain-20261006-final/COMPLETE.json`.
The tool validates pinned input/tool hashes, saves GNU disassembly and build
commands, opens the saved Ghidra import read-only, verifies the initialized image
hash, and writes success last. Run Ghidra jobs sequentially on this project.

| Check | Result |
| --- | ---: |
| Original/rebuilt/expected integrated cases | 3,888 |
| Included bounded pending prefixes | 229 |
| Returning cases | 3,659 |
| Original instruction addresses visited | 215 |
| Maximum executed instructions per path | 348 |
| Modeled boundary calls, both paths combined | 122,858 |
| Public synthetic tests | 31 passed |

The corpus combines both loader entry points, six paths (empty, relative,
prefixed, colons at offsets 7/8, and 250-byte relative), mode bytes 0/1/255,
existing list lengths 0/1/7, success/failure, optional size output, 1/2/7 wait
iterations, and three completion schedules. It rotates seven flag values,
four parameters, null/nonzero data, three lengths, and five synchronization
result pairs through those combinations; this is not their full Cartesian product.
High-bit result handling is modeled as returning. Transient terminal states
during signaling must still be followed by sleep; pending prefixes must not
detach data, report size, mark cleanup or return.

Checks cover dirty allocation clearing, list links before path handling, nested
formatted-path preservation, descriptor defaults before release, reloaded handle,
configuration before waiting, ordered signal/sleep calls and arguments, exactly
one state read per wait poll, size and ownership before cleanup, final descriptor
and existing-list bytes, preserved input/globals, and the byte-normalized external
store multiset (including redundant zero stores). Stack alignment/restoration,
callee-saved registers, initialized reads, allowed memory operations, PC ranges
and instruction budgets are enforced. Pending prefixes check bounded effects,
not return ABI or liveness.

All 92 synchronous, 103 constructor and 15 wait instruction addresses are visited,
plus the five delay-selector addresses on the long-duration path. The short-delay
multiply/spin branch is not reached by this integration; the standalone wait/delay
package retains its exhaustive short nonnegative-duration corpus. Address visits
include predicated instructions and are not exhaustive semantic coverage.

Three local mutants are rejected: waiting before setting the parameter, omitting
the list backlink, and adding a terminal-state early return between signal and
sleep. The latter is caught by extra state reads violating the poll contract,
before reaching the initially anticipated diagnostic. Driver:
`local/validation/check-chain-negatives.py`; evidence:
`local/validation/chain-20261006-negative-{configuration-order,backlink,early-return}/NEGATIVE.json`.
Mutated sources stay local and no negative run writes a success marker.

## Limits and next work

Allocation must return a valid nonnull descriptor; paths and list nodes must be
valid and nonoverlapping, and lists finite/acyclic. Concurrent mutation outside
the scheduled models, allocation failure, invalid or format-bearing paths,
nonreturning error handlers and actual timing are outside this evidence.
No full game loader, binary match, reconstructed 3DS application or live gameplay
agreement is claimed. G1/G2 remain open and live checks remain deferred.

Subsequent [signal recovery](resource-signal.md) reconstructs `0x002C4298` with
3,352 comparisons and scheduled exclusive outcomes in its standalone checker.
Both [lock routines](resource-lock.md) are now also recovered; their
[integration with signal](resource-signal-lock.md) passes 7,556 comparisons in
476 bytes with only arbitration intercepted. The subsequent
[full chain integration](resource-chain-signal.md) now executes signal/locks too:
3,924 comparisons, 1,348 bytes and 335 original instruction addresses, retaining
explicit arbitration and timing models. This older checker retains its signal
model and passes its 3,888-case regression after the harness extension.
Integration into the older bulk/lifecycle
checkers is still pending; they retain their documented higher-level models.
Original compiler/ABI and host address-boundary research remain open. No emulator,
save, profile or original dump was changed.
