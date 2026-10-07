# Resource registry bulk loader

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All addresses are original virtual addresses in ARM mode. Descriptive names are
project annotations. [resource_bulk.c](../../src/resource_bulk.c) is reconstructed
from the original instructions, with no external implementation copied.

Continuation: [resource-order recovery](resource-order.md) now executes the
consumed index/remainder on both paths, passing 2,520 integrated bulk cases in a
304-byte unit with only file I/O intercepted. The 184-byte mode documented below
retains modeled index returns and passes its independent 1,726-case regression.

## Contract and evidence

`0x0033C8A0` initializes a local byte array to IDs 0..66. For i=0..32 it calls
`0x0029706C(i+1,66)` and swaps array positions i and the returned index. These
are exactly 33 swaps; this is not a complete Fisher-Yates shuffle. All index
calls occur even when every registry entry is already loaded or has zero policy.

It then visits all 67 IDs in the resulting order. For each entry whose loaded
address is zero and policy byte is nonzero, it calls
`0x002C3344(path,&entry.size,0)` and stores the returned word as its loaded address.
Zero returns do not abort the pass, retry the entry, or change the final return
value of one. Already loaded entries are skipped regardless of policy. The loader
does not itself clear size or modify path, policy, or the three reserved bytes.
The backend may leave size unchanged or write it. NKMSortIndex's initial slot-one,
policy-one state therefore qualifies for this path.

Supported scope: an ordinary stable, writable 67-entry registry, valid index
results in the inclusive requested interval, and a backend honoring the declared
calling convention and confined size output. Concurrent registry mutation,
reentrancy, MMIO, backend faults, and invalid index returns are outside this unit's
comparison contract. The C source intentionally adds no parser-style guards or
failure policies absent from the original.

The Ghidra listing agrees with independent GNU ARM disassembly. Read-only export:
`local/analysis/bulk-20261006/exports/`; the inspection script now also exports
the index helper. Original bulk instructions occupy `[0x0033C8A0,0x0033C958)`;
the registry pointer literal follows at `0x0033C958`.

## Index dependency

The helper at `0x0029706C` orders its endpoints using a **signed** comparison,
computes their inclusive width, updates the u32 state at `0x004651C0` with
`state = state * 0x41C64E6D + 0x3039` modulo 2^32, passes `state >> 16` and the
width to `0x002C61B0`, and adds the lower endpoint to that routine's r1 output.
This r1 output is a remainder lead, distinct from the already recovered
unsigned quotient entry `0x002C6C64`. The bulk caller only supplies positive
ordered bounds: lower 1..33 and upper 66. Do not extrapolate this contract to
negative, reversed, overflowing, or full-width intervals.

The helper's state transition and call arguments have static instruction
evidence. Its actual sequence, division dependency, and state side effects are
**not executed by the bulk comparison**. The inclusive result bounds are an
explicit dependency contract for this package. Recovering and comparing this
consumed helper domain is the next bounded task.

## Build and comparison

From the repository, with the saved Ghidra GUI project closed:

```powershell
python tools/inspect_resource_registry.py --output local/analysis/bulk-next
python tools/check_resource_bulk.py --output local/validation/bulk-next
python -m unittest discover -s tests -v
```

The checker pins the input and tool hashes, builds with the existing freestanding
C11 ARMv6 flags, and runs the existing Ghidra project read-only without analysis.
The separate unit is 184 bytes at harness address `0x00600000`. Its external
bindings are registry data, the index helper, and the synchronous load wrapper.
No original instructions execute on the rebuilt path. Both dependencies are
intercepted on **both** paths; this does not recover random-number generation,
file I/O, allocation, or a working resource loader.

The deterministic corpus has 1,726 original/rebuilt/expected cases. It covers
every permitted index return at each of the 33 positions (other positions use
their lower bounds), all-lower and all-upper schedules, and 64 random schedules.
Registry profiles include all eligible, all loaded, zero policy, high-bit policy,
and mixed entries. Backend models include null, nonnull and mixed returns, with
size preserved or written. Randomized size/reserved bytes detect unrelated writes.

The oracle checks the ordered load trace, exact arguments and call counts, the
whole registry at each dependency call and at return, unconditional return one,
stack restoration/alignment, callee-saved registers, initialized reads, allowed
writes and instruction ranges. Caller-saved registers are poisoned at dependency
returns. The memory guards are shared with `CompareResourceLifecycle.java`;
its hash is included in the build manifest. Tests are bounded examples, not
exhaustive coverage of all possible schedules or backend behavior.

Successful evidence: `local/validation/bulk-20261006/COMPLETE.json` records all
1,726 passing comparisons, 43,271 modeled load calls per path, all 46 original
instruction addresses visited, and a maximum of 1,614 executed instructions per
call excluding the intercepted dependencies. All 29 public synthetic tests pass.

Three local mutants were rejected without success markers: using 32 swaps,
inverting the policy test, and returning zero after a null load result. Their
records are `local/validation/bulk-20261006-negative-{swap-count,policy,null-return}/NEGATIVE.json`;
the driver is `local/validation/check-bulk-negatives.py`. Only ignored source
copies were mutated; repository source was preserved.

Live gameplay remains deferred and G1/G2 stay open. No matching claim, bootable
3DS rebuild, host address boundary, or PC-port implementation follows from this
unit. The subsequent index/remainder recovery is linked above. Next: follow
synchronous load backend `0x002C5E90` and identify its file/allocation dependencies.
