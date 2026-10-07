# Allocation through registry construction and retained worker cleanup

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This extends [retained registry reuse](resource-registry-reuse.md) with the
recovered allocation wrapper `0x002C4BD8` and aligned allocator `0x002C5544`.
Both execute during request-packet and callback-descriptor construction, on
the same retained memory used by the worker, completion and release routines.
Recovered game source is unchanged. The total remains **35 bounded entry
points plus two adapted worker regions**; this is integration evidence.

## Executed behavior and oracle

`check_resource_registry_worker.py --recover-allocation --resubmit` links both
allocation sources into the prior worker unit. It removes interception at
`0x002C4BD8`; the nested allocation call returns through its actual instructions
to its request/constructor caller. The rebuilt path executes no original code.

The 324 scenarios retain the existing cross-product of one to three requests,
zero to two pending neighbors, four lower-I/O profiles, path-mode bytes 0/1/255,
and ascending, descending or repeated registry IDs. Two successive batches
reuse freed payload addresses, reverse descriptor assignment and rotate packet
assignment while preserving all heap bytes. Worker traversal, completion,
registry publication, descriptor unlinking and release execute as before.

For each 24-byte packet and 324-byte descriptor allocation, the harness checks:

- Caller arguments `(256, 256, 0, size, fifth)`, with fifth argument zero for
  packets and one for descriptors, survive both allocation layers.
- The lower raw allocator receives the independently calculated rounded size;
  every word-aligned raw-address residue modulo 128 occurs. The raw model
  selects storage for the predetermined aligned payload address.
- The original/rebuilt metadata stores install raw size, alignment halfwords
  and the raw pointer at payload minus four. All surrounding bytes are guarded.
  The accounting model changes only its explicitly owned header fields.
- Boundary ordering is acquire, acquire, raw allocation, accounting, clear,
  release, clear, release. Modeled recursive depth reaches two and returns to
  zero. Deliberate changes to the global lock handle at every boundary test
  the actual reloads; these changes are adversarial model effects, not observed
  concurrent behavior.
- Both allocator clear calls use the payload address and requested byte count.
  The constructor's additional descriptor clear remains checked by the existing
  caller oracle. Neither clear may damage headers, backlinks or neighboring data.
- On raw allocation return, the fixture grants access to reused storage. The
  allocator may then update its metadata and clear the payload. Access after
  modeled free and before this ownership transition remains rejected.
- Release conversion reads the preserved payload-minus-four backlink and
  returns the recorded raw pointer to recovered release routing. Conversion
  itself is still a model: its real accounting/list side effects do not execute.
- Original/rebuilt allocation, reuse, I/O and release event sequences agree.
  Memory, external stores, publication order, ABI preservation, instruction
  bounds and caller stack guards remain checked throughout.

The fixture may choose a different raw offset for a reused aligned payload in
the second batch. This tests replacement of stale metadata, not a recovered
free-list selection algorithm. Ordinary allocation assumes valid writable
word-aligned storage. Both constructors use the ordinary `0x100` selector;
special routes and null/wrapping-size cases remain covered by the separate
[aligned-allocator corpus](resource-allocate-lower.md), not this integration.

## Evidence and reproduction

Marker: `local/validation/registry-allocation-20261007/COMPLETE.json`.
The unit is **2,928 ARMv6K bytes**, SHA-256
`cbe12b06f5491b1fd13ac247d2d13ffe0f3dc7f988e93c5992441603b94f85dc`.
Counts combine original and rebuilt paths except scenarios and instruction
addresses.

| Check | Result |
| --- | ---: |
| Original/rebuilt/oracle scenarios | 324 |
| Submissions and completions | 2,592 each |
| Allocation wrapper/lower executions | 5,184 each |
| Allocator zero calls | 10,368 |
| Checked modeled backlink conversions to raw storage | 5,184 |
| Reused payload allocations in second batches | 2,592 |
| Continuous worker traversals | 3,888 |
| Node visits | 9,072 |
| Worker invocations with interleaved pending nodes | 288 |
| Original instruction addresses visited | 649 |
| Original allocator addresses added | 26 wrapper + 45 ordinary lower |
| Maximum instructions per worker invocation | 9,841 |

Run Ghidra jobs sequentially against the saved read-only project:

```powershell
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --output local/validation/registry-allocation-next
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --mutant wrong-raw-backlink --output local/validation/registry-allocation-negative-next
python tools/check_resource_registry_worker.py --resubmit --output local/validation/registry-reuse-regression-next
python tools/check_resource_registry_request.py --recover-release --output local/validation/registry-request-regression-next
python -m unittest discover -s tests -v
```

All six allocation-specific mutants are rejected: `skip-outer-zero`, `skip-inner-zero`,
`wrong-raw-backlink`, `wrong-rounded-size`, `cached-outer-lock` and
`damage-header`. They modify copies under each ignored output directory;
production recovered source is unchanged. Per-run negative markers and
diagnostics record assertion rejection. The previous `skip-reused-clear`
mutant is no longer useful with recovered allocation: allocator zeroing makes
its condition true, so the constructor still clears the descriptor.

Negative evidence is under
`local/validation/registry-allocation-20261007-negative-*/NEGATIVE.json`.
Failures specifically report missing clear/order, wrong raw-pointer metadata,
wrong rounded size, stale lock-handle use or an unexpected header store.
All 31 public tests pass. The prior 324-scenario retained-reuse mode passes
unchanged, including its original binary hash, in
`local/validation/registry-allocation-20261007-reuse-regression/COMPLETE.json`.
The prior 1,271-scenario registry-request/release mode also passes unchanged in
`local/validation/registry-allocation-20261007-request-regression/COMPLETE.json`.

## Limits and next work

Raw heap selection/allocation, allocation registration/accounting, zeroing,
recursive lock implementations, release conversion/free, lower file calls,
strings, OS calls and scheduling remain modeled. Only the two recovered
allocation layers were added to instruction execution. Worker data allocation
`0x002BF7EC` and file-object allocation `0x002C244C` retain their prior models.
This corpus uses converted releases; the existing separate release and default
worker corpora retain direct-range coverage.

Continuation: release conversion now executes with retained headers under the
additional `--recover-conversion` flag; see [its evidence](resource-release-convert.md).
The original allocation-only mode documented here still models conversion.
Next recover heap selection and allocation registration/accounting. Recursive
heap locks and raw allocation/free remain further bounded tasks. Default worker,
request and synchronous checks keep their documented
allocation boundaries unless explicitly enabled here. Live G1/G2 checks remain
deferred and unpassed. No emulator, save, profile, original input or PC runtime
was changed.
