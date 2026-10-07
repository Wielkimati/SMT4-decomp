# NKMSortIndex section-3 pair lookup recovery

2026-10-06. [`src/nkm_section3.c`](../../src/nkm_section3.c) reconstructs
ARM `0x001A0EA4..0x001A0F1C` (end exclusive), EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
The name `nkm_section3_pair_lookup` describes the observed behavior; the keys'
and values' gameplay meaning remains unknown. Source was reconstructed from
instructions, with no external implementation copied.

## Behavior and supported memory

The function requests resource 1, section 3, obtains its payload, and scans
four-byte records. It compares the first little-endian u16 with the full uint32
input. A first match returns the second u16, replacing zero with 50. Exhausting
the count also returns 50. The input is not narrowed: `0x10007` cannot match key
7. A zero-valued first match ends the search even if a later duplicate is nonzero.
Both halfwords are unsigned; values above `0x7FFF` are zero-extended.

The original checks count before the first record and calls the count helper
again after each mismatch, including after the final record. The source retains
that order and the fixed four-byte stride, independent of the entry-size field
used to calculate count. No cache or early high-key shortcut is introduced.

The original instructions at `0x001A0EDC/0x001A0EE0` load/compare the key;
`0x001A0EEC..0x001A0EF8` select the first value or fallback. The count calls are
at `0x001A0ECC` and `0x001A0F04`; the loop uses unsigned comparison. GNU objdump
and the saved Ghidra listing agree. Original length is 120 bytes.

The memory contract requires stable, readable registry/container/section headers
for every load the helpers perform. For positive count, every record visited
must have readable aligned halfwords and reside within one backing object;
address/index arithmetic must not wrap. Concurrent mutation, MMIO, inaccessible
memory and unaligned original halfword loads are outside this contract.

This consumer also supports a helper-rejected section (null result) and a zero
count without reading payload bytes. Synthetic comparisons exercise a missing
section, rejected container magic, rejected section magic, an actual empty
payload, zero declared size, and zero entry-size field. This does not make the
original helpers bounded file parsers: truncated or unreadable headers remain
unsupported, as do arbitrary malformed offsets. See [helper contracts](tbcr-access.md).

## Build and comparison

Close the saved Ghidra project in the GUI, then run from the repository:

```powershell
python tools/check_nkm_lookup.py --recover-pairs --output local/validation/pairs-next
python -m unittest discover -s tests -v
```

`--recover-pairs` implies `--recover-quotient` and `--recover-helpers`. Earlier
modes remain available. The checker verifies input/tool hashes, uses the pinned
ARM GCC build, and runs Ghidra read-only without reanalysis. The reconstructed
path executes only rebuilt code; its external registry data is initialized by
the harness. Loader/lifetimes are not recovered.

The independent fixture oracle constructs a map of first occurrences. Reference
probes sample 32 evenly spaced distinct keys, selected record positions, and
boundary/full-width inputs; this is not exhaustive reference-key coverage.
Synthetic cases cover duplicate precedence, zero first values, first/last/missing
keys, unsigned halfword values, high inputs sharing a low halfword, nondivisible
size, differing entry-size fields, zero counts and rejected sections. Earlier
sections contain decoys. Game table bytes and generated listings remain local.

The strict instruction harness checks callee-saved registers, restored SP,
stack-only writes, bounded/initialized reads and no original code on rebuilt
paths. Pair-call budgets scale with fixture count to permit the linear scan
and repeated quotient calls; earlier routines retain their 512-instruction cap.
It also requires visiting all 30 original consumer instruction addresses.
Address coverage alone does not prove all branch outcomes or inputs.

## Results

Successful run: `local/validation/pairs-20261006/COMPLETE.json`.
The earlier `--recover-quotient` mode also passes after these harness changes:
`local/validation/pairs-20261006-quotient-regression/COMPLETE.json` (352 bytes,
5,539 comparisons, maximum 327 instructions per call).

| Check | Result |
| --- | --- |
| Section-3 original/rebuilt/expected comparisons | 236 passed: 45 reference probes, 191 synthetic |
| Existing section-2 lookup comparisons | 1,770 passed |
| Existing helper / quotient comparisons | 1,154 / 2,615 passed |
| Public synthetic tests | 29 passed |
| Original consumer instruction addresses visited | All 30 |
| Combined ARM unit | 472 bytes, seven entry-point contracts |
| Rebuilt pair consumer | `0x00600050`, 120 bytes; not binary matching |
| Maximum instructions per call | 342,609 (linear scan with repeated division) |

The equal original/rebuilt consumer lengths do not imply matching instructions:
the rebuilt code uses byte loads and different register/branch allocation.

Two local negative controls were rejected with no success report: narrowing the
input to u16 incorrectly returns 65432 for key `0x10007`, and continuing after
a zero first match incorrectly returns the later duplicate's 65535. Original
and expected results are 50 in both cases. Evidence is in
`local/validation/pairs-20261006-negative-narrow-key/NEGATIVE.json` and
`local/validation/pairs-20261006-negative-skip-zero/NEGATIVE.json`; the local
driver is `local/validation/check-pair-negatives.py`. Repository source was
unchanged during those controls.

## Next work

Continuation: the registry trace and four bounded lifecycle contracts now have
source and controlled comparison evidence. See [lifecycle recovery](resource-lifecycle.md)
and [bulk recovery](resource-bulk.md) for the current next task (index helper /
remainder or file backend). The paragraph below records
the original handoff from this package.

Live gameplay agreement remains deferred at the user's request; G1/G2 stay open.
The next static package should trace writes to registry slot 1's loaded pointer
(`0x00493840`) and recover a bounded loader/lifecycle routine when its dependencies
are understood. Original compiler/ABI and explicit host address boundaries are
also ready research. No matching binary, rebuilt application, or native port is
claimed by this unit.
