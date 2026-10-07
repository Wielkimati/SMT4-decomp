# Resource heap selection

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x002B3340` is reconstructed in
[`src/resource_heap_index.c`](../../src/resource_heap_index.c).
This adds one bounded entry-point contract: **37 plus two adapted worker
regions**. It does not establish a full allocator, binary matching or live
gameplay agreement.

## Contract and instruction evidence

The input is an unsigned 32-bit address. The function does not dereference it.
It reads four ranges from allocator state at `0x00465120`:

| Index | Start word offset | Length word offset |
| --- | --- | --- |
| 0 | `+0x1C` | `+0x2C` |
| 1 | `+0x20` | `+0x30` |
| 2 | `+0x24` | `+0x34` |
| 3 | `+0x28` | `+0x38` |

Each range includes both endpoints, from `start` through `(start + length)`
modulo 2^32, using unsigned comparisons. A wrapped end below its start gives
an empty range, not a circular interval. Zero length includes exactly its start.
The earliest matching index wins. No match returns zero, indistinguishable
from a match in range zero. Results are only 0 through 3; the eight-slot
accounting arrays and low-byte tag test do not imply eight selector results.

The function occupies `[0x002B3340,0x002B33CC)` (35 ARM instructions), followed
by the state-address literal at `0x002B33CC`. GNU disassembly and the saved
Ghidra listing agree on unsigned conditions, wrapping ADDs and branch order.
There are no calls and no stores outside the stack. Original r4/r5 are saved.
The reconstructed contract assumes all state words are readable and stable
during a call; concurrent modification and original load timing are unclaimed.

Read-only inspection exports at
`local/validation/heap-index-20261007-inspect/exports/` include the original
listing, generated analysis and references. The two known callers each call
the selector twice: release conversion at `0x00124630` / `0x00124650`, and
registration at `0x002B264C` / `0x002B266C`. Registration remains a model.
No saved Ghidra database edits or new reference extraction were needed.

## Direct comparison

`local/validation/heap-index-20261007-direct/COMPLETE.json` records **17,740
original/rebuilt/oracle cases**, all **35 original instruction addresses**,
and a **64-byte ARMv6K** build. SHA-256:
`557d6e7a04c9322f49d4131b9f5bae417ab983e4b1014601e2f1f7bcfc3a8bde`.
Maximum execution length is 45 instructions. Neither path intercepts a call;
the rebuilt path executes no original code.

The corpus isolates each of the four ranges using eleven boundary start and
length values, probes both endpoints and their neighbors, adds 2,048 seeded
random range configurations with seven probes each, and tests all sixteen
membership combinations at a shared zero-length endpoint. It includes zero,
high-bit addresses, maximal lengths, wrapping sums, overlap and unmatched
addresses. Raw addresses need neither alignment nor mapped backing.

There are 8,036 unmatched cases and 2,757 overlapping cases. Result counts for
indices 0/1/2/3 are 11,340 / 2,581 / 2,051 / 1,768. A membership-bitset oracle
chooses the first matching interval. The checker also enforces instruction and
read bounds, rejects non-stack writes, checks state/guards and callee-saved
registers, and verifies stack restoration.

## Retained allocation integration

The optional `--recover-selector` mode requires `--recover-conversion` and
`--recover-allocation`. It executes the selector's original/rebuilt instructions
inside conversion and returns through the actual LR to the caller. The
registration model uses an independent range-membership oracle for its counters;
it does not execute original or recovered registration instructions.

The 324 retained scenarios still allocate packets and descriptors, publish
completion, traverse the worker, unlink and free headers, then reuse the same
payload addresses in a second batch. Synthetic stable range profiles cover
separate descriptor/packet ranges, reversed assignment, no match, and overlap.
The integrated selector results are 0 and 1. Slots 2 and 3 are empty wrapping
ranges so release routing converts all payloads. Their successful selection is
covered by the direct corpus, not this retained corpus.

Marker: `local/validation/heap-index-20261007-integrated-final/COMPLETE.json`.
The unit is **3,244 ARM bytes** and visits **728 original instruction addresses**.
Across both paths it executes **6,912 selectors**, **5,184 allocations**,
**5,184 conversions**, **2,592 reused allocations**, **2,592 submissions and
completions**, **3,888 worker traversals**, and **9,072 node visits**. All four
list-removal positions and 32 raw-address residues modulo 128 remain covered.
The maximum worker invocation executes 10,185 checked instructions.
Integrated binary SHA-256:
`67517b9f418debf9a2e0a250b1c904eec5a206381778be63146caa1723bc166d`.

This fixture adds 25 selector addresses to the prior corpus and no longer
visits ten release-routing addresses (`0x002C43D4..0x002C43E4` and
`0x002C43F4..0x002C4404`): their lower-bound conditions now reject before
loading lengths. The prior conversion mode retains its fixture and coverage.
The first integrated development run passed behavioral assertions but emitted
no COMPLETE marker because the wrapper incorrectly expected 738 addresses.
The trace established the ten-address difference; the final run uses 728.

The option also passes without `--resubmit`:
`local/validation/heap-index-20261007-single-batch/COMPLETE.json` records 324
single-batch scenarios, 3,456 selector executions, 2,592 allocations/conversions
across both paths, the same binary hash and 728 original instruction addresses.
It does not claim address reuse.

## Reproduction and fault detection

From `SMT4-decomp`, use new ignored output directories and run Ghidra jobs
sequentially against the authoritative saved project:

```powershell
python tools/check_resource_heap_index.py --output local/validation/NEW-DIRECT
python tools/check_resource_heap_index.py --mutant exclusive-end --output local/validation/NEW-NEGATIVE
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --output local/validation/NEW-INTEGRATED
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --output local/validation/NEW-CONVERSION-REGRESSION
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --output local/validation/NEW-ALLOCATION-REGRESSION
python tools/check_resource_release_convert.py --output local/validation/NEW-DIRECT-CONVERSION-REGRESSION
python -m unittest discover -s tests -v
```

All seven direct mutants are rejected: `exclusive-start`, `exclusive-end`,
`wide-end`, `signed-start`, `reverse-priority`, `wrong-fallback`, and
`skip-fourth`. Their `NEGATIVE.json` markers and wrong-result diagnostics are
under `local/validation/heap-index-20261007-negative-*/`.
Both integrated mutants, `selector-reverse-priority` and
`selector-wrong-fallback`, are rejected at the recovered selector's return;
markers are under `local/validation/heap-index-20261007-integrated-negative-*/`.
Each driver mutates a private copy in its output directory, leaving production
source unchanged.

The three relevant earlier modes pass again with identical binary hashes and
complete comparison objects to their previous records:

| Regression | New marker below `local/validation/` | Previous record |
| --- | --- | --- |
| Retained conversion with modeled selector | `heap-index-20261007-conversion-regression/COMPLETE.json` | `registry-conversion-20261007/COMPLETE.json` |
| Retained allocation with modeled conversion | `heap-index-20261007-allocation-regression/COMPLETE.json` | `registry-allocation-20261007/COMPLETE.json` |
| Direct conversion with adversarial selector model | `heap-index-20261007-direct-conversion-regression/COMPLETE.json` | `release-convert-20261007/COMPLETE.json` |

All **31 recovery/tooling tests** pass. The historical 50-test run also
included 19 local automation tests. The observed command outcome is recorded
in `local/validation/heap-index-20261007-public-tests.json`.
`local/validation/heap-index-20261007-package.json` indexes all six positive
manifests and nine negative markers, records exact regression equality, and
confirms final source/tool hashes and 44 local documentation links.

## Limits and next work

Raw allocation/free, registration/accounting, zeroing, recursive heap locks,
lower file/OS calls, strings and scheduling remain explicitly modeled. The
worker's separate data allocator `0x002BF7EC` and file-object allocator
`0x002C244C` retain their existing models. Older checker modes still model heap
selection, including the direct conversion corpus with adversarial selector
side effects. This optional recovery does not broaden those older claims.

Next recover **registration/accounting `0x002B260C`**, then replace its model
in the retained-header corpus. Start with this package's inspection exports
and the original callers `0x002C55D0`, `0x002BF884`, `0x002C3590`. The inspected
routine reads the tag from accounting `+0x38`, updates counters, appends a node
at raw `+12`, and copies that tag to raw `+8`; verify those instructions before
implementing. The current model's arbitrary prepend/tag profiles are synthetic,
not a recovered registration contract. Keep old modes intact when adding a
recovered registration mode. Raw heap routing and recursive-lock recovery remain
later targets. Live G1/G2 gates remain deferred and unpassed; PC implementation
and revision-pinned transfer were not started.

During this session, baseline commits appeared from outside this worker in both
repositories (decomp `5c82ec0bea84fba235c989a46b5bf9d7e499ff00`, port
`5869acd0a910a92270d5ba5d3baa4ad6281c63e3`). The decomp commit explicitly
excludes this active package. They were preserved; this worker did not commit,
stage, reset or discard work. Final positive-manifest source/tool hash checks
still match the workspace. No gate was closed by the existence of those commits.
