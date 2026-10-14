# Asynchronous resource request and completion

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All entry addresses below are ARM. Names describe observed behavior, not original
symbols. Instruction-derived source is in `src/resource_request.c` and its header.
Four new contracts bring the repository total to thirty-one.

## Recovered behavior

| Address | Contract |
| --- | --- |
| `0x002AE72C` | Format a path, allocate/fill a request packet, clear an optional address output, construct a descriptor with a completion callback, set mapped flags and the supplied parameter |
| `0x002B6820` | Forward five request arguments and supply a sixth parameter of four |
| `0x00155BBC` | Call the descriptor constructor, then write callback/context at descriptor offsets `0x130`/`0x134`; return the descriptor |
| `0x00155B30` | Publish completion output, invoke an optional callback, detach successful data, mark cleanup, and release the request packet |

The request packet is a 24-byte allocation with six 32-bit fields:

| Offset | Field |
| --- | --- |
| `+0` | File descriptor address, stored after construction |
| `+4` | Optional user completion callback |
| `+8` | Opaque callback context |
| `+12` | Original flags |
| `+16` | Supplied parameter |
| `+20` | Optional address-output pointer |

The backend calls allocation `0x002C4BD8(256,256,0,24,0)`. It initializes the last
five fields before creating the descriptor; the first word retains allocation
contents until construction returns. It clears a nonnull address output before
construction. The constructor receives mode zero, internal callback `0x00155B30`
and the packet address. Flag mapping is `(flags & 1) | ((flags & 2) << 3)`;
descriptor setters retain their existing state-zero guard. There is no wait,
signal or direct invocation of the completion callback in these routines.

Path behavior matches the synchronous loader: a nonzero mode byte, or an accepted
prefix, uses the path itself as a format. Otherwise the original fixed format is
used. String operations remain modeled; the reconstruction does not introduce
format escaping, bounded formatting or new error handling.

Completion treats exactly descriptor state five as failure. Failure writes zero
to a nonnull output and calls the optional user callback with `(0,context,0)`.
It preserves the descriptor's data pointer. Every other tested state follows the
success branch: publish descriptor `+12`, invoke `(data,context,size)` using size
at `+24`, then clear the saved descriptor's data pointer. Output publication
precedes the user callback; detachment and cleanup follow it. Cleanup increments
the selected descriptor's word at `+8` with unsigned wrap, then release
`0x002C43B4` receives the packet address, not the file data address.

The cleanup descriptor pointer is reloaded from the packet after the callback.
Controlled callback mutation proves the distinction: replacing packet `+0`
redirects cleanup to that descriptor, while success still detaches data from the
original saved descriptor. Another model changes the old data word; failure
preserves that change, and success clears it. This does not establish arbitrary
callback reentrancy or concurrent worker behavior.

The original backend transports the fifth argument through `s16` while preserving
`d8`. This is a raw 32-bit context value, not evidence of a floating-point field.
The checker exercises high-bit context values and verifies both halves of saved
`d8`, integer callee-saved registers, SP and stack arguments. The rebuilt soft-float
C preserves the same bits without reproducing that register allocation.

## Evidence and reproduction

Ghidra and independent GNU ARM disassembly agree. The read-only inspection is
`local/analysis/request-20261006/exports/COMPLETE.txt`. Generated pseudocode is
kept local and was cross-checked against instructions: notably, its failure
callback rendering omitted an argument whose zero value is explicit in ARM.

Run Ghidra jobs sequentially with the saved project closed:

```powershell
python tools/inspect_resource_request.py --output local/analysis/request-next
python tools/check_resource_request.py --output local/validation/request-next
python tools/check_resource_registry_chain.py --output local/validation/request-registry-regression-next
python -m unittest discover -s tests -v
```

Successful comparison: `local/validation/request-20261006/COMPLETE.json`.
The **564-byte ARM unit** contains four new routines and four previously recovered
descriptor helpers. The rebuilt path executes no original instructions.

| Check | Result |
| --- | ---: |
| Backend/wrapper original/rebuilt/oracle comparisons | 2,016 (1,008 each) |
| Direct callback-constructor comparisons | 48 |
| Completion comparisons | 1,728 |
| Total comparisons | 3,792 |
| Original instruction addresses visited | All 139: 116 new and 23 helper addresses |
| Maximum instructions per path | 91 |

Request cases cover six paths, modes 0/1/255, seven flag patterns, optional output
and callback, descriptors accepting/refusing setters, full-width contexts and
parameters. The wrapper's fixed parameter is checked separately from the backend's
sixth argument. Constructor cases preserve null, high-bit and Thumb-bit callback
values without invoking them. Completion covers eight descriptor states, three
data values, three size values, optional output/callback, three cleanup counters
and the controlled callback effects described above.

The harness checks packet contents at constructor entry, descriptor fields,
output publication and callback arguments/order, saved registers/stack, all
external byte stores and guards. Allocation, constructor, clear/prefix/format,
user callback and release calls are explicit models on both paths. Caller-saved
registers and flags are poisoned at those boundaries. Final source, harness,
tool and reference hashes are recorded with disassembly and exact coverage.

Four local source mutants are rejected: narrowing the callback context, replacing
the wrapper parameter four with zero, cleaning up the cached descriptor after
callback replacement, and moving successful detachment before the callback.
The last mutation is rejected when the callback changes the data word: that
change wrongly survives the early detach. Drivers are
`local/validation/check-request-negatives.py` and its focused
`check-request-detach-negative.py` continuation. Successful negative markers:

- `local/validation/request-20261006-negative-narrow-context/NEGATIVE.json`
- `local/validation/request-20261006-negative-wrong-default-parameter/NEGATIVE.json`
- `local/validation/request-20261006-negative-cleanup-old-descriptor/NEGATIVE.json`
- `local/validation/request-20261006-negative-early-detach-verified/NEGATIVE.json`

Each checks its expected diagnostic and absence of a success marker. Earlier
negative-driver attempts are retained locally; their expected diagnostic was
reached earlier by another oracle check. Production sources were unchanged.

All 1,902 registry-chain comparisons pass again with current headers:
`local/validation/request-20261006-registry-regression/COMPLETE.json` (1,760 bytes,
479 original instruction addresses). All 31 public tests pass. Final request
and registry-regression source/harness hashes match their respective markers.

## Remaining boundary

Supported fixtures use valid disjoint allocations and writable word-aligned output
locations, stable paths without formatting directives, and constructor results
with the original descriptor extent. Null allocation/constructor returns, memory
aliasing between packet/output/descriptor, invalid callbacks and concurrent
mutation are unclaimed. Incidental return registers of void routines are unclaimed.

The real allocator, worker scheduler, callback dispatcher, release backend and
file I/O remain unrecovered. Completion is tested directly, independently of
request submission; this is not a working asynchronous loader. No live gameplay,
matching binary, full application rebuild or native runtime is added. G1/G2
remain open and live checks remain deferred.

The subsequent [registry integration](resource-registry-request.md) connects
request `0x0033C844` and callback `0x0019F990` to this source and the recovered
descriptor constructor: 1,163 scenarios pass with explicit worker scheduling
and release models. Next trace the dispatcher that consumes descriptor `+0x130/+0x134`
before claiming actual asynchronous execution. Release backend `0x002C43B4`
and compiler/host-address research remain separate recovery work.

## Concrete path-prefix integration (2026-10-13)

The optional `--recover-prefix` checker mode now executes recovered predicate
`0x002B0674` and reuses the existing full-length source `0x002C32E4`. See
[the prefix report](resource-path-prefix.md) for exact two-pass read semantics,
caller integration, bounded instruction support and current evidence. Formatting
and the other documented service boundaries remain modeled. The default mode
retains this report's earlier prefix model; it has not silently gained recovery.
