# Resource registry lifecycle recovery

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All addresses are original virtual addresses, ARM mode. Names are descriptive,
not original symbols. Source in [resource_lifecycle.c](../../src/resource_lifecycle.c)
was reconstructed from instructions; no external implementation was copied.

## Loaded-pointer trace

The registry at `0x0049382C` has 67 entries of 16 bytes. Reviewed accesses establish
u32 path address at `+0`, loaded address at `+4`, a size/output word at `+8`, and a
policy byte at `+12`; the final three bytes remain opaque. The size interpretation
is supported by the reload routine's comparison and copy length, not a full file
backend recovery. Entries store original 32-bit addresses, not host pointers.

The existing initializer `0x003F05F0` gives NKMSortIndex slot 1, clears its loaded
address `0x00493840` and size, and sets its policy byte to one. Further writers:

| Routine / store | Observed behavior | Recovery state |
| --- | --- | --- |
| `0x0033C8A0` / `0x0033C93C` | Builds indices 0..66, performs 33 swaps using `0x0029706C`, visits all resulting entries, loads null entries with nonzero policy via `0x002C3344(path, &size, 0)`, then stores the returned address | Subsequently recovered with index/file interception; see [bulk report](resource-bulk.md) |
| `0x00297714` / `0x0029775C` | Individually loads a null entry only when policy is zero | Reconstructed and compared with backend interception |
| `0x0033C844` / backend | Passes `&loaded`, callback `0x0019F990`, and entry context to `0x002B6820` for a null zero-policy entry | Request wrapper reconstructed; scheduling unverified |
| `0x0019F990` / `0x0019F994` | Stores callback r0 into `entry+4` and r2 into `entry+8` using ARM STM | Reconstructed and compared directly |
| `0x002A49E0` / `0x002A4A24` | Releases a nonnull zero-policy entry, then clears only its loaded address | Reconstructed and compared with backend interception |
| `0x0025C848` / `0x0025C8D8`, `0x0025C8E0` | Reload path replaces loaded address and size if sizes differ; equal-size path copies into the old allocation and releases the new one | Subsequently recovered with concrete gate/state dependencies; file/release/copy modeled; see [reload report](table-resource-reload.md) |

Thus the individual load wrapper does **not** populate NKMSortIndex from its
initial policy-one state. The bulk loader's store is the concrete static path
to that slot; its observed incoming call is `0x001C03C0`. Execution timing and
runtime loaded bytes remain unverified. A raw aligned-pointer scan found nine
registry-base literals and no interior registry pointers. Ghidra references and
this scan are not an exhaustive census of computed aliases or indirect writes.

Backend adapters are also identified: `0x002C3344` sets r3 to 4 and tail-calls
`0x002C5E90`; `0x002B6820` forwards its fifth argument and adds a sixth argument
of 4 before calling `0x002AE72C`. Asynchronous orchestration and completion are
now reconstructed in [request recovery](resource-request.md); four is the
descriptor parameter supplied by this wrapper. Allocation, filesystem operations
and scheduling remain modeled/unrecovered.
Release dependency `0x002C43B4` is also external.

## Recovered contracts

All three indexed wrappers reject unsigned IDs >=67 with zero. Checks precede
registry access. For a valid ID:

| Entry state | Load/request return and effect | Release return and effect |
| --- | --- | --- |
| Nonnull loaded address | 1, no backend call regardless of policy | If policy zero: release then clear address, return 1; otherwise 0 |
| Null address, zero policy | Call backend and return 1 | 1, no backend call |
| Null address, nonzero policy | 0, no backend call | 1, no backend call |

Synchronous load passes path, `&size`, zero; then stores the backend's r0 even
if it is null. Return 1 means the wrapper took or accepted that path, not proven
successful I/O. The request wrapper passes path, `&loaded`, zero, callback,
entry context; it ignores the backend return. It does not itself mark an entry
pending or set its size. Release preserves the size, path, policy and reserved
bytes, including stale size after clearing the address. The callback writes
address and size without validation and has a void contract.

Supported memory is a stable readable/writable registry in a 32-bit address
space, aligned callback entry, and backend behavior honoring the declared ABI.
The callback's two word destinations must be writable. Concurrent mutation,
MMIO, invalid callback destinations and atomicity between writes are unclaimed.
Registry bytes use explicit little-endian access; no original structure padding
or host-pointer layout is assumed. This is not a safe file parser or host loader.

## Reproduce and results

Close the saved Ghidra GUI project, then run from the repository:

```powershell
python tools/inspect_resource_registry.py --output local/analysis/registry-next
python tools/check_resource_lifecycle.py --output local/validation/lifecycle-next
python tools/check_nkm_lookup.py --recover-pairs --output local/validation/consumer-next
python -m unittest discover -s tests -v
```

Inspection uses the pinned JDK/Ghidra, checks the full mapped hash, and processes
the existing project read-only without reanalysis. The saved analysis had no
correct ARM function at `0x0019F990`; only those 12 bytes are cleared/redecoded
transiently for export. GNU objdump independently agrees on the three ARM words.
The saved database is unchanged. Export includes listings, generated pseudocode,
incoming references and raw pointer candidates; game bytes remain ignored.
Successful inspection: `local/analysis/registry-20261006-final/exports/COMPLETE.txt`.
Earlier failed inspection directories retain the missing-function/context errors.

The lifecycle unit uses the existing pinned GCC/ARMv6 flags and links at harness
address `0x00600000`. Successful comparison:
`local/validation/lifecycle-20261006-final/COMPLETE.json`.

| Check | Result |
| --- | --- |
| Load / request / release comparisons | 2,304 each |
| Callback comparisons | 2,144 |
| Total | 9,056 original/rebuilt/expected cases |
| Original instruction addresses visited | All 65 across the four routines |
| Rebuilt unit | 312 bytes, four contracts; no binary matching claim |
| Maximum executed instructions per call | 21, excluding intercepted backends |
| Public synthetic tests | 29 pass |

The existing consumer/helper/quotient suite also passes all 5,775 cases after the
shared registry declaration became mutable. Evidence:
`local/validation/lifecycle-20261006-consumer-regression/COMPLETE.json` (472 bytes).
Two local mutants were rejected without success reports: replacing load's
unconditional return 1 with a nonnull-result test, and clearing size during
release. Evidence is in `lifecycle-20261006-negative-null-return/NEGATIVE.json`
and `lifecycle-20261006-negative-clear-size/NEGATIVE.json` under local validation;
the local driver is `local/validation/check-lifecycle-negatives.py`. Repository
source was not modified during these controls.

Cases cover all 67 IDs plus five invalid unsigned boundaries, null/nonzero
addresses, policy bytes 0/1/128/255, null/nonzero backend results, random size
words and randomized neighboring/reserved bytes. The two backend modes either
preserve the output field or write it. Callback coverage varies address and
size independently of the policy and existing loaded address.

The harness checks entire registry snapshots, call count and arguments, unchanged
registry at backend entry, saved registers/SP, allowed writes, initialized reads,
and per-routine instruction ranges. Backend models poison caller-saved registers.
The request test checks its fifth argument on the stack and normalizes the
callback address to the appropriate original/rebuilt implementation. Callback
execution is tested separately; asynchronous timing/reentrancy is not modeled.

**Backend calls are intercepted on both paths.** Neither original nor rebuilt
file I/O/allocation code executes in this comparison. This differs from the earlier
consumer/helper/quotient suite, which executes its full recovered chain. Results
establish wrapper and callback behavior under the documented backend models,
not a functioning loader. Live gameplay remains deferred; G1/G2 remain open.

## Next bounded task

The subsequent [bulk-loader package](resource-bulk.md) passes 1,726 comparisons
with an explicit index-helper contract. Next recover `0x0029706C` in its consumed
positive domain and verify remainder dependency `0x002C61B0`, or follow synchronous
backend `0x002C5E90`. Preserve the distinction between orchestration comparisons with
intercepted dependencies and full backend recovery. Host address boundaries and
original compiler/ABI investigation remain ready independent work.
