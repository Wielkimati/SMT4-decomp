# Loaded table-resource reload

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; names are descriptive. No external source
or private resource strings were copied.

## Strategy review and acceptance

Every source/tool hash in the previous initializer
marker still matched before edits; see
`local/validation/table-reload-20261013-static/prior-handoff-check.json`.
The completed constructor milestone is retained. Its next target extends loaded
resource behavior directly; optional extraction/compiler work and deferred live
checks do not block it. No reprioritization was needed. Small gate/state bodies
were included because they directly unblock this reload contract.

Acceptance declared before implementation: recover ARM `0x0025C848` and bounded
small state dependencies, build warning-clean, compare gate/ID/loaded exits,
equal-size copy versus replacement, release/publication order and state
restoration from constructed registry state. Keep copy/file service models
explicit, reject meaningful faults and retain affected regressions. These are
bounded source criteria; full startup, live I/O and G1/G2 are separate gates.

## Recovered contracts

`src/table_resource_reload.c` and `.h` add four original entry contracts:

| Original ARM interval (end exclusive) | Contract |
| --- | --- |
| `0x0025C848..0x0025C8F4` | Void reload of an already-loaded registry slot |
| `0x0025B9D8..0x0025B9E4` | Store low eight input bits to `0x00465040` |
| `0x0025B9E8..0x0025B9F4` | Signed byte read from `0x00465040` |
| `0x002C5890..0x002C589C` | Read a word at wrapping address `0x00446DA0 + 4*index` |

Saved ARM membership and instruction objects agree with hash-bound bytes and
independent GNU disassembly (`table-reload-20261013-static/membership.txt` and
`reload.log`, `state.log`, `gate.log` under local validation). The getter lies in
its own three-instruction interval; intervening literal words are data. All 52
instruction sites across the four contracts execute in the comparison.

Reload reads gate index 2 **before** validating the unsigned ID. A nonzero gate,
ID >=67, or null loaded word exits without a state write or service call. Policy
is not consulted. For an active entry it remembers whether the signed state byte
is nonzero, writes state 1, and calls load with path, a local size output, zero.
The size output must be initialized by the modeled backend for this C domain.

Equal sizes call copy(old, replacement, size), then release the replacement;
registry pointer and size remain unchanged. Unequal sizes release the old pointer
first, then publish replacement followed by size. There is no null-result test:
a null unequal-size result is published; a zero-size equal path still calls copy
and release. State zero is restored only if initially zero. Initial 1, 128 or 255
therefore ends as **1**, not the original byte. Return-register leftovers are
not a meaningful output of the void contract.

Volatile original-address accesses preserve the checked scalar order/widths.
The gate wrapper uses unsigned 32-bit address arithmetic, including index wrap;
there is no inferred table length or added bounds check. Its caller must provide
a readable word address. Ordinary aligned memory, no MMIO, reentrancy or
concurrent registry mutation is the supported domain. No error policy, null-copy
safety, overlapping-copy semantics, native runtime or service replacement is
invented.

## Integration and modeled dependencies

The new checker reuses the pinned compiler, read-only Ghidra project and
`CompareResourceLifecycle` machine primitives. It links the existing registry
initializer with reload and its three concrete dependencies. Each reload case
executes original or rebuilt initialization before controlled loaded-pointer and
size fixtures are installed. Initial constructor snapshots agree between paths;
reserved and neighboring registry bytes remain guarded through reload. This is
constructed-state integration, not startup-to-file-I/O or persistent multi-reload
lifetime validation.

Only `0x002C3344` load, `0x002C43B4` release and `0x002C6048` copy are intercepted.
The load model writes the local size and returns a controlled address. Copy
checks arguments and performs bounded byte copying for nonoverlapping synthetic
allocations. Release checks the selected address/order but does not free memory.
All models clobber caller-saved registers. Source gate/state dependencies execute
on both paths (the compiler may inline rebuilt bodies); no original binary
helper is used by the rebuilt path. These three dependencies are concrete in
this new comparison; older checker boundaries have not been changed or claimed
recovered retroactively. Supporting build/harness changes add no game contracts.

## Validation

Primary: `local/validation/table-reload-20261013-final/COMPLETE.json`.

- Warning-clean freestanding ARMv6 build: **924 bytes**, including existing
  initializer code/data. Not a whole-game or matching build.
- **289 reload pairs**, **14 direct state-accessor pairs**, **10 direct gate
  pairs**, all **52 original instruction sites**. Read/write/service order,
  complete registry/state/payload guards, saved registers, SP and ARM return
  mode are checked against expected effects and between both implementations.
- Reload IDs 0, 1, 13, 66, 67 and 0xFFFFFFFF; gate 0/0x80000000;
  state 0/1/128/255; unloaded exits; equal lengths 1, 17, 128;
  old size 0xFFFFFFFF replaced by 3 or zero; null publication; explicit loaded
  zero-length copy with null source. Constructed policies include both zero
  and nonzero. Positive copies use aligned nonoverlapping synthetic buffers.
- Direct setter/getter inputs 0, 1, 127, 128, 255, 256 and 0xFFFFFFFF check
  truncation, signed extension and surrounding preservation. Gate reads use
  indices 0, 1, 2, 0x40000002 and 0xC0000002 with zero/nonzero words.

The first development pass also succeeded; the final pass strengthened read
ordering, setter changes and direct wrapping gate checks. This is targeted
verification refinement, not additional recovered code.

Audit: `local/validation/table-reload-20261013-audit/COMPLETE.json`, with
`negative-checks.json`, `regressions.json` and `public-tests.log`.
Three compiled faults (inverted restore condition, unsigned getter, zero size
publication) are rejected by runtime assertions, with no success markers.
The retained lifecycle suite passes **9,056 pairs** with its complete comparison
object and **312-byte binary identical** to `lifecycle-20261006-final`.
All **134 public tests** pass. Final audit checks manifest source/tool hashes,
pinned reference/build hashes, Python syntax, JSON and changed-file whitespace.

```powershell
python tools/check_table_resource_reload.py --output local/validation/NEW-RELOAD
python tools/check_table_resource_reload.py --mutant restore --output local/validation/NEW-NEGATIVE
python tools/check_resource_lifecycle.py --output local/validation/NEW-LIFECYCLE-REGRESSION
python -m unittest discover -s tests
```

All Ghidra jobs ran sequentially and read-only; all commands finished. No commits or live emulator sessions were started.

## Concrete copy continuation and next source milestone

2026-10-13: [copy recovery](table-resource-copy.md) completes the demonstrated
copy dependency. The optional `--recover-copy` mode executes new ARM entry
`0x002C6048..0x002C60D0` and the existing aligned diagnostic copy
`0x002BCFAC..0x002BD020`, now shared without body changes. This adds one original
entry, not two. The 1,680-byte build passes 624 generic-copy and 35 aligned pairs
alongside every retained reload/accessor/gate pair. Exact payload accesses and
115 original sites are checked. Primary evidence:
`local/validation/table-copy-20261013-shared-final/COMPLETE.json`.
The older default mode and all historical results above retain their scope.

The unaligned-LDR probe establishes consecutive-byte Ghidra behavior, not live
alignment-control or fault/cache/timing semantics. Load `0x002C3344` and release
`0x002C43B4` remain modeled in reload; allocation lifetime and live gates stay open.
The next independent source target is the still-modeled path-prefix predicate
`0x002B0674`, shared by synchronous `0x002C5E90` and asynchronous `0x002AE72C`
callers. See the copy report's next milestone for source/checker entry points and
acceptance. Reload sets mode one and skips that predicate; it is not presented
as a prerequisite for remaining reload integration.
