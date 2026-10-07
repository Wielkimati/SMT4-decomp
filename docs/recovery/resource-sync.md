# Synchronous resource loading and descriptor helpers

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Addresses below are original virtual addresses. All six recovered entries are ARM.
Names are project annotations. Source was reconstructed from the local instructions;
no external implementation was copied.

## Contracts and dependency boundary

[`resource_sync.c`](../../src/resource_sync.c) recovers the orchestration at
`0x002C5E90` and the two-instruction wrapper at `0x002C3344`. The wrapper forwards
the path, optional size-output pointer and flags, setting the fourth argument to
**4**. This overrides the descriptor constructor's observed default of `0x80`.
The fourth argument's deeper meaning remains unknown.

The backend clears a 256-byte stack buffer. If byte `0x00465040` is nonzero, it
skips the path-prefix probe. Otherwise it calls `0x002B0674`. A nonzero mode or
probe result selects formatting with the **path itself as the format string**;
otherwise the format at `0x00409740` is `rom:/%s`, with path as its argument.
This is preserved as a variadic dependency, not silently changed to a string copy.
The static probe scans for a colon within the first eight characters. Its source
and formatting implementation are not part of this package.

The formatted path and zero are passed to descriptor creation `0x002B0494`.
Flag bit 0 becomes descriptor flag bit 0; flag bit 1 becomes bit 4. All other
input flag bits are ignored here. Two state-gated setters configure the descriptor,
then `0x001181B0` waits. Static inspection of that wait routine shows a loop until
state 4 or 5. The subsequent [wait/delay package](resource-wait.md) recovers that
loop and its delay selector; the earlier callback interpretation was incorrect.
This checker still intercepts the entire wait call.

On state 5 the backend writes zero through a nonnull size output, marks the
descriptor for cleanup, and returns zero. Otherwise it captures the data pointer
at `+0x0C`, optionally copies the length at `+0x18` to the caller, clears the data
pointer, marks cleanup, and returns the captured pointer. The successful path
still copies length and marks cleanup when the captured data pointer is null.
The caller's size output is written before marking cleanup on both paths.

[`resource_descriptor.c`](../../src/resource_descriptor.c) recovers four helpers:

| Entry | Contract |
| --- | --- |
| `0x002B0468` | Increment the u32 at `+8` modulo 2^32; no allocation release occurs in this helper |
| `0x002B0478` | If state word `+0` is zero, store the full u32 argument at `+0x24` and return 1; otherwise leave it unchanged and return 0 |
| `0x0014E744` | Same gate, writing `+0x28` |
| `0x0014E634` | Return 1 exactly when state word `+0` equals 5 |

Descriptor representation uses u32 words at observed offsets, retaining unknown
fields. The source requires the original 32-bit address space. The validated
domain uses aligned, nonoverlapping descriptor and optional size-output storage,
a valid short path without format directives, and a nonnull descriptor returned
by creation. Wait completion is modeled as state 4 or 5. Invalid pointers,
allocation failure, overlong/format-bearing paths, aliasing, concurrent writes,
and nonterminating waits are not validated. No extra null check is invented for
the creation result; the original also immediately dereferences it.

The following dependencies are explicitly intercepted on both comparison paths:

| Address | Observed boundary / static lead |
| --- | --- |
| `0x002C3B98` | Clear buffer |
| `0x002B0674` | Path-prefix predicate |
| `0x002BE850` | Formatting entry, reached in Thumb mode by the original BLX |
| `0x002B0494` | Create a 0x144-byte descriptor, add it to a list, initialize fields and path |
| `0x001181B0` | Wait until descriptor state 4 or 5; invokes signal and delay dependencies |

Constructor inspection identifies allocation entry `0x002C4BD8`, clearing at
`0x002C4B84`, synchronization calls at `0x002C4350`/`0x002C54A4`, and list links at
descriptor `+0x13C`/`+0x140`. The list root comes from `0x00465000 + 0x0C`.
These are static leads, not implemented allocation or file I/O. The wrapper,
backend and four helpers execute real instructions on each comparison path;
the rebuilt path executes no original instructions.

## Evidence and reproduction

`tools/inspect_resource_sync.py` exports Ghidra listings, references and pseudocode
for twelve bounded targets, after checking the entire initialized image hash.
The read-only export is `local/analysis/sync-20261006/exports/`. GNU objdump agrees
with the recovered entries; independent disassembly is saved by the checker.
Generated pseudocode remains private analysis, not source evidence by itself.

With the saved Ghidra project closed, run from `SMT4-decomp/`:

```powershell
python tools/inspect_resource_sync.py --output local/analysis/sync-next
python tools/check_resource_sync.py --output local/validation/sync-next
python -m unittest discover -s tests -v
```

The checker uses the existing pinned GCC/binutils, JDK and Ghidra. It builds a
separate 360-byte ARMv6 unit. `COMPLETE.json` records source/tool hashes and is
written only after all comparisons and corpus-size checks succeed. New outputs
must be under ignored `local/`; the saved import is read-only.

Successful record: `local/validation/sync-20261006/COMPLETE.json`.

| Check | Result |
| --- | ---: |
| Backend comparisons | 2,016 passed |
| Three-argument wrapper comparisons | 504 passed |
| Four direct descriptor helpers | 192 each; 768 total passed |
| Original instruction addresses visited | All 92 |
| Maximum executed instructions per call | 81 |
| Modeled dependency calls, both paths combined | 21,840 |
| Public synthetic tests | 31 passed |

The harness uses separate original/rebuilt machines and independent expected
descriptor snapshots. It checks ordered dependency calls and arguments, mode
short-circuiting, scratch-buffer clearing, flags and parameter before waiting,
size output and pointer detachment before cleanup, return value, full descriptor,
input preservation, exact external write trace/count, stack alignment/restoration,
r4-r11, initialized reads, allowed stores, PC ranges and instruction budgets.
Helper cases include high-bit states/values and cleanup-counter wraparound.
Backend cases include null/nonzero data, absent/present size outputs, mode bytes
0/1/255, predicate results 0/1/0xFFFFFFFF, ignored high flag bits, arbitrary lengths,
and descriptors that reject configuration. Address coverage includes predicated
instructions; it is not an exhaustive proof over all possible inputs.

Local negative checks reject omitted pointer detachment, incorrect flag mapping,
and a generic nonzero-state failure predicate. Driver:
`local/validation/check-sync-negatives.py`; records:
`local/validation/sync-20261006-negative-{ownership,flags,failure-state}/NEGATIVE.json`.
The omitted store is detected even for a null data pointer by the write count.
Mutated source stays local and no negative run produces a success marker.

## Next work and limits

Subsequent package: [descriptor creation](resource-create.md) now passes 10,080
comparisons in 388 bytes, with explicit allocation/synchronization/string boundaries.
The subsequent [wait/delay recovery](resource-wait.md) adds 14,670 comparisons
with signal/sleep/spin modeled. The subsequent [integrated chain](resource-chain.md) now passes 3,888 comparisons
in 868 bytes with constructor/wait/delay execution. Next: signal/arbitration recovery. Integrating this new unit into the bulk/lifecycle comparison chain is
still pending; the earlier harnesses retain their documented higher-level models.
This synchronous-loader package brought the total to twenty bounded contracts;
the subsequent constructor and wait/delay packages raise it to twenty-three.
Actual file I/O/allocation, compiler/ABI research and host address boundaries remain
open. G1/G2 and live verification remain deferred/unpassed. No emulator, save,
profile, original dump, PC runtime or full 3DS build was changed by this package.
