# Resource allocation metadata release

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x001245F0` is reconstructed in
[`src/resource_release_convert.c`](../../src/resource_release_convert.c).
This adds one bounded entry-point contract, bringing the total to **36 plus two
adapted worker regions**. Original compiler, binary matching, complete allocator
recovery and live gameplay agreement remain unclaimed.

## Contract

The input is an allocated payload address. Its word at `address-4` identifies
the raw allocation header. The accounting object is the address at allocator
state `0x00465120+8`. These are original 32-bit addresses; arithmetic wraps at
32 bits. The function has no null or validity guard and returns the raw header
without calling the underlying free operation itself.

| Object | Offset | Observed use |
| --- | --- | --- |
| Raw header | `+0` | u32 allocation size subtracted from accounting |
| Raw header | `+4` | u16 amount deducted when deriving the second per-heap amount; the recovered ordinary allocator writes 128 here |
| Raw header | `+8` | u16 tag: only its low byte controls accounting; the full halfword is cleared on release |
| Raw header | `+12`, `+16` | Previous/next list-node addresses; a node is embedded at raw header `+12` |
| Accounting object | `+0`, `+4` | List head and tail |
| Accounting object | `+8` | Tracked node, cleared only if it equals the removed node |
| Accounting object | `+24`, `+28` | Allocation count and total size |
| Accounting object | `+60+4*i` | First per-heap counter |
| Accounting object | `+92+4*i` | Second per-heap counter |

The function first subtracts one from the count and `raw[0]` from total size.
If the tag's low byte is below eight, it calls heap selector `0x002B3340` twice:

1. Reload the accounting pointer and allocation size after the first call;
   subtract that size from the first selected counter.
2. Reload the accounting pointer, allocation size and `+4` halfword after the
   second call; subtract `size - halfword - 60` from the second selected counter.

Each call supplies its own index. The initial tag decision is not repeated,
even if the first helper call changes the tag. The checker models the selector;
its actual range-selection implementation is not recovered here. Index values
0 through 7 are supplied in the direct corpus to exercise distinct counter slots,
not to assert that the real selector can produce every such value.

The node is then removed from its list. The routine patches both neighbors for
a middle node, the head or tail for an endpoint, or clears both endpoints for a
singleton. It clears the tracked-node word only on equality, clears the tag
halfword, and returns the raw address. The removed node's own links, payload,
size, alignment field and payload-minus-four backlink are preserved.

The bounded contract requires valid, word-aligned, nonoverlapping backing for
the header/backlink, accounting object and distinct neighboring nodes, with
well-formed list links. Malformed aliasing lists, inaccessible addresses and
concurrent mutation are outside this evidence. The selector's deliberate state
changes are adversarial dependency effects, not observations of concurrency.

## Direct evidence

`local/validation/release-convert-20261007/COMPLETE.json` records a **252-byte
ARMv6K unit**, SHA-256
`67bfc947b477d92d2541aec149041bc020a7b4d03002cc24d03ef28db660796b`.
All **7,608 original/rebuilt/oracle comparisons** pass, visiting all **64**
original instruction addresses. There are 1,159 cases taking the per-heap path,
4,636 modeled selector calls across both paths, and at most 57 instructions
per direct call. Rebuilt execution uses no original instruction helpers.

The corpus covers every low-byte tag with three upper-byte patterns, all four
list positions, matching/nonmatching tracked nodes, all word-aligned raw
residues modulo 128, high-bit raw storage, counter underflow, full-width size
values, halfword boundaries, and deterministic random inputs. Its byte-level
oracle checks guards and untouched bytes. At each selector boundary it checks
the preceding accounting effects, then can replace the accounting pointer,
size, alignment and tag before returning a separately chosen index. Unexpected
reads/stores, instruction escapes, stack bounds/alignment, callee-saved registers
and d8 preservation are checked.

```powershell
python tools/check_resource_release_convert.py --output local/validation/release-convert-next
python tools/check_resource_release_convert.py --mutant full-tag --output local/validation/release-convert-negative-next
```

## Retained registry integration

`--recover-conversion` adds this source to the registry worker checker and
requires `--recover-allocation`. The allocator still obtains raw storage from a
model and calls a modeled registration routine. That routine now supplies valid
accounting/list metadata, so the original and rebuilt conversion instructions
can consume it later. Append/prepend fixture variants cover all four removal
positions; they do not establish the original registration algorithm.

The accounting object and allocation headers remain on the same emulated
machine through submission, callback, worker cleanup, and the second batch's
reuse. Conversion must read the allocation's actual retained backlink. Every
conversion checks counter changes, surviving neighbor links, tracked-node
behavior, tag clearing, payload/guard preservation and the raw argument delivered
to modeled free. At each completed batch, all modeled registered allocations
have been removed and the list, total counters and per-heap counters are zero.

`local/validation/registry-conversion-20261007/COMPLETE.json` records **324
scenarios**, **3,180 ARM bytes**, and **713 original instruction addresses**.
Counts below combine original and rebuilt paths:

| Check | Result |
| --- | ---: |
| Allocation and conversion executions | 5,184 each |
| Allocator zero calls | 10,368 |
| Selector calls during conversion | 6,912 |
| Reused payload allocations | 2,592 |
| Submissions and completions | 2,592 each |
| Continuous worker traversals | 3,888 |
| Node visits | 9,072 |
| List removal topologies | 4 |
| Word-aligned raw residues modulo 128 | 32 |

The integrated binary SHA-256 is
`ffab34d4bf4ed4aebe0527298726ca35652f9dbb96fcf44541f4faf4c13c1c02`.
The maximum worker invocation executes 10,133 checked instructions, including
nested conversion. Existing publication, I/O event, ownership and reuse checks
remain active.
Default checker modes retain their prior modeled conversion boundary.

```powershell
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --output local/validation/registry-conversion-next
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --mutant conversion-broken-next --output local/validation/registry-conversion-negative-next
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --output local/validation/allocation-regression-next
python tools/check_resource_registry_worker.py --resubmit --output local/validation/reuse-regression-next
python -m unittest discover -s tests -v
```

Run Ghidra jobs sequentially against the saved read-only project. Original and
rebuilt disassembly, tool/source/reference hashes, exact coverage and case logs
are retained under each ignored output directory.

## Fault detection

All nine direct mutants are rejected: `full-tag`, `wrong-count`,
`byte-alignment`, `omit-overhead`, `stale-selector`, `retain-cursor`,
`clear-byte`, `broken-next`, and `cached-account`. The failures identify wrong
accounting, missing helper/state reloads, damaged neighbor links or a partially
cleared tag. All four integrated mutants (`conversion-full-tag`,
`conversion-broken-next`, `conversion-clear-byte`, `conversion-omit-overhead`)
are rejected by memory or unexpected-store checks against retained headers.

Per-run `NEGATIVE.json` markers and assertion diagnostics are under
`local/validation/release-convert-20261007-negative-*/` and
`local/validation/registry-conversion-20261007-negative-*/`. The drivers compile
mutated copies only under their ignored output directories; production source
is unchanged. All 31 public synthetic tests also pass.

Both prior 324-scenario modes pass with identical binary hashes and comparison
counts to their preceding evidence: allocation-only mode at
`local/validation/registry-conversion-20261007-allocation-regression/COMPLETE.json`
and the modeled-allocation retained-reuse mode at
`local/validation/registry-conversion-20261007-reuse-regression/COMPLETE.json`.
All four positive manifests' source/tool hashes match the final workspace.

## Remaining boundaries and next work

Heap selection, raw allocation/free, allocation registration, zeroing, recursive
locks, lower file/OS calls, strings and scheduling remain explicit models. Worker
data/file-object allocation retains its prior boundaries. This work recovers
metadata removal, not a complete usable allocator or an actual filesystem.

Next recover heap selector `0x002B3340`, then registration/accounting
`0x002B260C`, and replace those models in the retained-header corpus. Raw heap
routing and recursive lock implementations remain later bounded tasks. Live
G1/G2 evidence is still deferred and unpassed. No PC implementation or
revision-pinned source transfer was added.
