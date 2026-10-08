# Resource raw-free routing

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry **`0x001244E8`** is recovered in
[`src/resource_free_raw.c`](../../src/resource_free_raw.c), using the existing
`smt4_resource_heap_free` interface. This adds **one bounded entry contract**:
48 entries plus two adapted worker regions. Linked allocation/free code and the
comparison tooling add no recovered contracts.

## Selection and acceptance

The scheduled strategic review verified all eight hashes from the preceding
free/coalescing audit, its primary comparison object and its binary hash against
disk (`local/validation/free-raw-20261008-audit/handoff-check.json`). That milestone
is complete. Optional extraction,
compiler research and deferred live gates are not prerequisites.

Acceptance: recover ordered half-open range selection, overlap priority, u32
arithmetic, short-circuit reads, unmatched behavior and captured heap/lock
forwarding; build warning-clean ARM; compare original/rebuilt calls, guarded state,
ordered accesses and ABI preservation; execute both heap routes through actual
allocation-produced blocks, counted free and reuse; reject compiled faults and
run affected regressions. Locks and fixed-pool free remain explicit models.
The void interface has no return-value acceptance requirement: the evidenced
caller overwrites r0, and no original return type is asserted.

## Instruction-derived contract

Saved body `[0x001244E8,0x001245E3]` contains 63 ARM instructions. The following
three literal words at `0x001245E4/E8/EC` hold `0x00465170`, `0x004E4100` and
`0x004E411C`. Saved Ghidra listing, GNU disassembly and pinned image bytes agree
for all 63 instructions; see `local/validation/free-raw-20261008-audit/static-audit.json`.
The read-only inspection is in `local/validation/free-raw-20261008-inspect/exports/`.

The router reads `base = *(u32 *)(0x00465170+4)` exactly once, even for address
zero. It then tests these ranges in order:

| Start / length fields relative to base | Action on first match |
| --- | --- |
| `+0x14 / +0x18` | Acquire `base+0x74`; counted free `(base+0x1C,address)`; release the same lock |
| `+0x80 / +0x84` | Acquire `base+0xE0`; counted free `(base+0x88,address)`; release the same lock |
| `+0xEC / +0xF0` | Fixed-pool free `(0x004E4100,address)` |
| `+0xF8 / +0xFC` | Fixed-pool free `(0x004E411C,address)` |

A range matches precisely when unsigned `start <= address < u32(start+length)`.
The length is read only when `start <= address`; later ranges are not read after
a match. Zero length and a wrapped end at/below start accept no addresses.
This differs from the inclusive heap-index and outer-release range checks.
There is no null guard, allocation validation or error call for an unmatched
address. Unmatched calls return without modifying external state.

Heap and lock address arithmetic wraps at 32 bits. Both addresses are captured
before acquire; subsequent dependency changes to the global base do not retarget
the current call. The original tail-calls unlock or fixed free. No tail-call
machine-code matching is claimed for GCC. The counted free is `0x002B33D8`, already
recovered with inner free `0x0014699C`; its return count is discarded.

The existing void declaration is retained. The saved reference to this router is
caller `0x002C4414` within recovered release `0x002C43B4`; instruction `0x002C4418`
immediately replaces r0 with the outer lock address. The router's unmatched r0
contains a path-dependent scratch value; modeled dependencies likewise return
arbitrary words. These are not exposed as a fabricated status contract. This is
not proof about every indirect caller or the original C return type.

## Build and controlled comparison

Primary marker: `local/validation/free-raw-20261008-final/COMPLETE.json`.
The pinned GCC build is **1,816 text bytes**, including **248 router bytes** and
the unchanged 1,568-byte allocation/free unit. C11, `-O2`, ARMv6K ARM mode,
freestanding soft-float and warnings-as-errors are used; no SDK/runtime libraries
or original instructions execute on the rebuilt path. External bindings are only
the routing global, acquire, release and fixed-pool free.

| Observation | Result |
| --- | ---: |
| Original/rebuilt/oracle calls | 1,318 |
| Router calls / isolated range probes | 1,190 / 1,062 |
| Backed routed frees / allocation calls | 128 / 128 |
| Persistent arena scenarios | 32 |
| Route 1 / route 2 / pool 1 / pool 2 / unmatched | 216 / 171 / 114 / 159 / 530 |
| Router instruction addresses visited | All 63 |
| External reads / writes across both paths | 21,916 / 47,888 |
| Modeled calls across both paths | 2,612 |
| Maximum instructions per call, including allocation | 1,705 |

The isolated domain has 678 probes from six range profiles, endpoint neighbors,
zero/max/sign boundaries, disjoint/identical/overlapping/empty/wrapped ranges,
three object bases and two dependency-effect profiles; 384 seeded full-width
random probes supplement it. Bases include `0xFFFFFF80`, so individual field,
heap and lock addresses wrap. Arbitrary payloads are accepted only by the direct
counted/fixed-free models; these cases do not claim valid heap ownership.

Each backed scenario selects one of the two heap routes, ordinary/high-bit
addresses, alignment +128/-128, both policies and both split settings. A synthetic
2,048-byte-capacity free region seeds construction. Actual allocation instructions
produce sizes 20/49/73, then routed frees remove middle/head/last allocations.
A 2,048-byte allocation reuses the restored region and is routed back to free.
Header and payload storage persists across all calls; no allocation or counted
free is intercepted in this mode. Counters start at `0xFFFFFFFF`, exercising
wrapped allocation/decrement accounting. Initial construction and nonselected
heap state are synthetic, not recovered.

Both paths agree independently with the reused interval/list byte oracle after
every allocation/free and with the ordered routing-read/call oracle. Complete
routing/global/arena guards, obsolete header and payload bytes, ordered external
loads/stores, dependency arguments and 8-byte stack alignment, r4-r11, d8-d15,
caller stack and a 256-byte stack-scratch bound are checked. The adversarial model
changes the global base after external calls and clobbers volatile integer/VFP
registers and flags. Out-of-fixture reads/writes, unexpected code and instruction
budget excess fail. Instruction visitation is not all predication outcomes.

The first comparison also passed. Review then found that the fixture wrote oracle
header bytes back before a routed free; the final harness excludes existing arena
header storage from routing-fixture writes and verifies its persistent prestate.
The final run retains the same binary and comparison results with this stronger
check. No source change or weakened assertion followed a behavioral mismatch.

## Faults, regressions and limits

Seven separately compiled faults are checked: inclusive end, exclusive start,
added null guard, changed range priority, wrong second heap offset, wrong second
fixed object and reloading the lock after dependencies. Each negative marker
requires successful compilation and a corpus assertion, not a compiler failure.
Exact commands/logs and final regression results are indexed by
`local/validation/free-raw-20261008-audit/COMPLETE.json`.

The free/coalescing regression retains its original 7,496 calls and 1,568-byte
binary; the outer-release regression retains 3,616 calls and its 112-byte binary.
Their binary hashes and comparison objects agree with previous evidence. All
134 public tests pass. These regressions check the shared declaration change;
older workers and release checkers still intercept the router at their original
boundaries. No worker model was silently removed.

In the new backed mode the outer router and counted/inner free execute recovered
source. Only acquire `0x002C3AFC` and release `0x002C3A78` are intercepted on heap
routes. Direct probes also intercept counted free; fixed-pool free `0x00138354`
is always modeled. No claim covers fixed-pool mutation, recursive synchronization,
concurrency, invalid/double frees, heap construction/destruction, arbitrary
wrapping arenas or a complete retained-worker lifetime. r0 is deliberately outside
the consumed void contract. Full ABI/compiler identity, matching, G1/G2 live
agreement, G3/provenance/transfer decisions and native runtime gates remain open.

Source/harness are project-authored from the pinned instructions and existing
project harnesses. No external implementation was imported.

## Reproduce and next independent source package

From `SMT4-decomp`, use fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_free_raw.py --output local/validation/NEW-FREE-RAW
python tools/check_resource_free_raw.py --mutant reload-lock --output local/validation/NEW-FREE-RAW-NEGATIVE
python tools/check_resource_heap_free.py --output local/validation/NEW-FREE-REGRESSION
python tools/check_resource_release.py --output local/validation/NEW-RELEASE-REGRESSION
python -m unittest discover -s tests
```

Next recover **fixed-pool free `0x00138354` and its ordered insertion callee
`0x002C3928`**, replacing this router's remaining fixed-pool mutation model.
The saved inspection above includes the former's full body and call sites;
`local/validation/free-raw-20261008-audit/fixed-insert-lead.log` independently shows
the latter through `0x002C39B8`. Verify its saved boundary before implementation.
The lead finds a used record by payload, unlinks it, adjusts used-count/free-byte
accounting, inserts it by address, merges right then left and releases redundant
metadata through already-recovered `0x002C43B4`. Recover/compare valid record-list
states, insert equality/order, all merge cases, counter wrap and exact metadata
release effects; model recursive metadata release initially, with effects explicit.
Batch the insertion callee because it directly unblocks this source contract.
Do not infer missing-record safety from generated pseudocode.

This next source package takes precedence over a tooling-only worker integration:
there is now concrete bounded game-code evidence for the two unimplemented pool
routes. Arena-backed retained-worker lifetime integration remains useful afterward;
its older models stay documented. No next-target source was implemented here.
