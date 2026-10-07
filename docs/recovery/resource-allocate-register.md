# Resource allocation registration and accounting

2026-10-07, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
ARM entry `0x002B260C` is reconstructed in
[`src/resource_allocate_register.c`](../../src/resource_allocate_register.c).
This adds one bounded entry-point contract: **38 plus two adapted worker
regions**. It does not establish a complete allocator, binary matching or live
gameplay agreement.

## Contract and instruction evidence

Registration receives a raw allocation header. The accounting object is the
pointer at allocator state `0x00465120+8`. All addresses and counters are
32-bit; arithmetic wraps modulo 2^32. There are no null/validity guards.

| Object | Offset | Operation |
| --- | --- | --- |
| Accounting | `+24`, `+28` | Add one allocation and the raw header's u32 size |
| Accounting | `+56` (`0x38`) | Read u16 category tag; low byte below eight enables per-heap accounting |
| Accounting | `+60+4*i` | Add raw size after the first heap-selection call |
| Accounting | `+92+4*i` | Add `raw size - raw u16 at +4 - 60` after the second selection |
| Accounting | `+0`, `+4` | List head and tail; append the new node to the tail |
| Raw header | `+12`, `+16` | Embedded node's previous and next addresses |
| Raw header | `+8` | Copy the accounting object's full u16 tag after insertion |

The function reloads the accounting pointer and size after each selector call,
and the alignment halfword after the second call. Each call supplies its own
index. The initial low-byte decision is not repeated. The final tag is loaded
from the current accounting object; it need not equal the initial tag under
the direct checker's adversarial dependency model.

A nonzero head selects the existing-list path: install the previous tail in
the new node, replace the tail, link the old tail forward, and zero the new
next pointer. A zero head installs both endpoints and zeros both links; an
old tail value is ignored in this branch. The tracked-node word at accounting
`+8` is preserved even if it equals the new node. Unrelated header bytes,
payload, alignment and backlink remain untouched.

The function occupies `[0x002B260C,0x002B26EC)` (56 ARM instructions), followed
by its allocator-state literal. GNU disassembly and the saved Ghidra listing
agree on the halfword accesses, unsigned tag condition, arithmetic and links.
Read-only inspection exports are at
`local/validation/allocate-register-20261007-inspect/exports/`.

The three callers are aligned allocation `0x002C5544` at call site
`0x002C55D0`, worker data allocation `0x002BF7EC` at `0x002BF884`, and
`0x002C34F8` at `0x002C3590`. Each installs size/alignment/backlink first,
passes the raw header, and overwrites r0 before clearing the payload. The
recovered interface is therefore void; the original incidental r0 tag value
is not a claimed return contract. Only the first caller is recovered and
integrated here. Inspection of the other two does not recover them.

The contract requires readable/writable, word-aligned, disjoint header,
accounting and neighboring-node backing. A nonempty list must have valid
links and tail. The empty-head branch also tests a stale nonzero tail.
Aliasing objects, invalid pointers and concurrent mutation are outside the
evidence. Compiler reordering within call-free regions is allowed by this
stable-memory boundary; exact load/store timing is not claimed.

## Direct comparison

`local/validation/allocate-register-20261007-direct/COMPLETE.json` records
**5,962 original/rebuilt/oracle comparisons**, all **56 original instruction
addresses**, and a **224-byte ARMv6K** build. Binary SHA-256:
`583b0768546c46701251311560dd89d7280eb4d00618a2c8a0418ff30597c795`.
Maximum execution length is 55 instructions. There are 997 selected cases and
3,988 modeled selector calls across both paths. Rebuilt execution uses no
original instructions.

The corpus covers all 256 low-byte tags with three high-byte patterns,
empty/singleton/two-member lists, both tracked-node relations, all 32
word-aligned raw residues modulo 128, high-bit backing addresses, counter
overflow, full-width size boundaries, halfword boundaries and 1,024 seeded
random cases. Raw `+8` starts with a tag different from the accounting tag.
The oracle projects an abstract list append and independently calculates
counters. It checks byte guards, untouched fields, bounded reads/writes,
instruction escapes, stack restoration/alignment and callee-saved registers.

The selector model can switch the accounting object, size, alignment and tag
after each call and return different indices. Its indices 0 through 7 test
the eight accounting slots; the actual recovered selector returns only 0
through 3. These deliberate helper effects test reloads, not concurrent game
behavior. The integrated mode below executes the actual selector instead.

## Retained allocation integration

`--recover-registration` requires `--recover-selector`, `--recover-conversion`
and `--recover-allocation`. It links registration and executes it through the
actual call/return inside allocation; no synthetic registration stores or
registration-time lock mutation remain in this mode. Older options retain
their original registration models and acceptance counts.

The fixture selects category `0x8108` or `0xFF03` and occasionally seeds the
tracked-node pointer at the modeled raw-allocation boundary. These are
explicit caller fixtures; category selection and tracked-node management
are not recovered here. Registration itself performs all accounting, tag and
list writes. Guards cover the previously modeled opaque header bytes too.

The same memory persists through registration, construction, submission,
worker completion, release conversion and a second batch reusing freed
payload addresses. Each batch finishes with an empty allocation list and
zero total/per-heap counters. Selection executes inside both registration
and conversion. The stable range fixtures cover results 0 and 1, no match,
overlap and reversed descriptor/packet ranges; results 2 and 3 remain covered
by the [direct selector corpus](resource-heap-index.md).

Marker: `local/validation/allocate-register-20261007-integrated-final/COMPLETE.json`.
The unit is **3,468 ARM bytes**, SHA-256
`edab347a1b7e3d670d40cfaec0a3049cb3238cb4a9cef6c2ee59c652122160a4`.

| Check | Recorded result across both paths unless noted |
| --- | ---: |
| Scenarios | 324 |
| Allocation, registration and conversion executions | 5,184 each |
| Selectors inside registration / conversion | 6,912 / 6,912 |
| Total selector executions | 13,824 |
| Allocator zero calls | 10,368 |
| Reused payload allocations | 2,592 |
| Submissions and completions | 2,592 each |
| Worker traversals / node visits | 3,888 / 9,072 |
| Original instruction addresses | 784 |
| Maximum instructions per worker invocation | 10,185 |

All 56 registration addresses are added to the previous integrated corpus.
Faithful tail insertion gives three removal topologies in this schedule:
singleton, head and middle. The previous synthetic prepend/append mode covers
tail removal as well and retains that assertion. Reaching every original
instruction address does not imply every ARM predication condition is true.
All 32 raw residues remain covered. The ten release-routing addresses omitted
by the selector fixture remain outside this mode, as documented in the
[selector report](resource-heap-index.md).

The first integration run passed all 324 behavior scenarios but failed its
old four-topology coverage assertion, so it has no COMPLETE marker. Its
retained event log independently confirms topology set `{0,2,3}`. The final
mode explicitly requires that set; older modes still require `{0,1,2,3}`.

## Reproduction and regression checks

From `SMT4-decomp`, choose new ignored output directories. Run Ghidra jobs
sequentially against the authoritative saved read-only project.

```powershell
python tools/check_resource_allocate_register.py --output local/validation/NEW-DIRECT
python tools/check_resource_allocate_register.py --mutant broken-tail --output local/validation/NEW-NEGATIVE
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --recover-registration --output local/validation/NEW-INTEGRATED
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --recover-conversion --recover-selector --output local/validation/NEW-SELECTOR-REGRESSION
python tools/check_resource_registry_worker.py --resubmit --recover-allocation --output local/validation/NEW-ALLOCATION-REGRESSION
python tools/check_resource_release_convert.py --output local/validation/NEW-CONVERSION-REGRESSION
python -m unittest discover -s tests -v
```

All nine direct mutants are rejected: `full-tag`, `wrong-count`,
`byte-alignment`, `omit-overhead`, `stale-selector`, `cached-account`,
`broken-tail`, `tag-byte` and `tail-test`. The three integrated mutants
`registration-full-tag`, `registration-broken-tail` and
`registration-tag-byte` are also rejected. Failures identify wrong accounting,
missing reloads/calls, broken neighbor links, partial tag writes or the wrong
empty-list test. Mutated sources stay in their ignored output directories;
production source is unchanged. Markers are under
`local/validation/allocate-register-20261007-negative-*/NEGATIVE.json` and
`local/validation/allocate-register-20261007-integrated-negative-*/NEGATIVE.json`.

The single-batch mode also passes:
`local/validation/allocate-register-20261007-single-batch/COMPLETE.json`.
It covers 324 scenarios, 2,592 registrations/conversions and 6,912 selectors
across both paths, with the same binary hash and 784 original addresses.
It does not claim address reuse.

All three earlier modes pass with identical binary hashes and complete
comparison objects to their previous records:

| Regression | New marker below `local/validation/` | Previous record |
| --- | --- | --- |
| Retained selector with modeled registration | `allocate-register-20261007-selector-regression/COMPLETE.json` | `heap-index-20261007-integrated-final/COMPLETE.json` |
| Retained allocation with modeled conversion | `allocate-register-20261007-allocation-regression/COMPLETE.json` | `heap-index-20261007-allocation-regression/COMPLETE.json` |
| Direct conversion with adversarial selector model | `allocate-register-20261007-direct-conversion-regression/COMPLETE.json` | `heap-index-20261007-direct-conversion-regression/COMPLETE.json` |

All **50 public tests** pass; the command result is in
`local/validation/allocate-register-20261007-public-tests.json`.
`local/validation/allocate-register-20261007-package.json` indexes six positive
manifests and twelve negative markers, checks their source/tool hashes and
regression equality, and records documentation-link checks. Ghidra jobs ran
sequentially and all commands finished.

## Limits and next work

Raw allocation/free, zeroing, recursive heap locks, lower file/OS/string calls
and scheduling remain models. Worker data allocation `0x002BF7EC` and
file-object allocation `0x002C244C` retain their separate models. No complete
heap algorithm, OS behavior, original compiler/full ABI, matching or native
gameplay is established. Live G1/G2 checks remain deferred and unpassed.

Next recover raw allocation routing **`0x002B26F0`** as a bounded function.
Start with this package's inspection exports, then verify its jump-table
words/literals and callers independently. It routes through `0x002C3A98` or
`0x00144978`, with recursive lock calls `0x002C3AFC` / `0x002C3A78` on two
routes. Keep these lower allocation/lock implementations explicitly modeled
until separately recovered. Cover zero size, selector/direction branches,
argument marshalling and null results before adding another optional
retained-worker mode. Do not infer the raw allocator's state layout from the
registration state merely because both use adjacent globals.
