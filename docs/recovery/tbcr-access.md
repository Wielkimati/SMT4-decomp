# Loaded TBCR/TBL1 helper recovery

Subsequent update, 2026-10-06: the consumed nonzero-divisor quotient is recovered
too. `--recover-quotient` builds a 352-byte unit with no original-code calls on
the rebuilt path; 2,615 quotient, 1,154 helper and 1,770 lookup comparisons pass.
See [the quotient report](unsigned-quotient.md). The original-quotient mode and
its earlier results below are retained as historical evidence.

2026-10-06, A07/A08 continuation. Four helpers are reconstructed in
[`src/tbcr_access.c`](../../src/tbcr_access.c), bringing this package to five
implemented ARM routines including the NKMSortIndex lookup. Each builds and has
controlled instruction-level agreement with the pinned original. None has live
gameplay agreement yet; G1/G2 remain open.

Reference: EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All original addresses below are ARM virtual addresses. Names are descriptive,
not recovered original symbols. Source was reconstructed from the instructions;
no external implementation was copied and no project-wide license is selected.

## Recovered behavior and dependencies

| Original range (exclusive end, excluding literals) | Function | Behavior |
| --- | --- | --- |
| `0x002AC358..0x002AC3AC` | `tbcr_select_section` | Check nonnull TBCR magic and unsigned index below count; read offset at `base+12+index*4`; add base address, header word +4, and selected offset; reject null result or non-TBL1 magic |
| `0x002C0EF0..0x002C0F14` | `tbl1_payload` | Return null for null/wrong magic, otherwise section address +16; no payload read and no use of header word +12 |
| `0x002C0EA0..0x002C0ED4` | `tbl1_entry_count` | Return zero for null/wrong magic/zero entry size; otherwise unsigned word(+4) / word(+8) |
| `0x002C0F18..0x002C0F30` | `resource_select_tbcr_section` | For unsigned resource ID <67, read the 32-bit loaded address at registry + id*16 +4; otherwise select from null; preserve the section index |

The selector's index shift and address sums use uint32 modular arithmetic. This
preserves the observed null-result guard even when offsets wrap, and avoids C
pointer-arithmetic undefined behavior for the selector's computed addresses.
Both GNU objdump and the saved Ghidra listing agree on these instructions; see
[the static analysis](../tbcr-consumers-eu.md).

These are original loaded-memory interfaces, separate from the bounded Python
file parser. They do not validate allocation sizes, directory extents, or payload
lengths. Supported memory is stable, readable, ordinary RAM with the original
word alignment for header/directory/registry loads. Each actually read word must
be backed; a rejected null or wrong-magic pointer requires no later header bytes.
Returned payload pointers need not yet have readable payloads. Invalid inaccessible
addresses, unaligned ARM load behavior, concurrent mutation, and MMIO are unclaimed.
Tests of modular sums use readable low addresses; they do not establish validity
of arbitrary malformed files. Header byte reads themselves must stay within
their backing objects. The existing lookup retains its narrower memory contract.

The source explicitly requires 32-bit pointers. Its registry dependency is a
byte array with the original 67 x 16-byte layout, bound to `0x0049382C` for this
comparison. It does not serialize native host pointers or infer unknown registry
field types. A future 64-bit host adaptation needs an explicit address/registry
boundary; compiling this source unchanged as a host unit is deliberately rejected.
The loader/initializer and resource lifetimes remain unrecovered.

`smt4_unsigned_quotient` still binds to original `0x002C6C64`, with its original
shift/subtract branch targets. Only the consumed r0 quotient for nonzero divisors
is claimed. No division-by-zero contract, other result registers, runtime-library
identity, original compiler, or complete ABI is inferred. There are no helper
return stubs or intercepted calls.

## Reproduce and inspect

Close the Ghidra GUI project, then run from the repository:

```powershell
python tools/check_nkm_lookup.py --recover-helpers --output local/validation/tbcr-access-next
python -m unittest discover -s tests -v
```

Without `--recover-helpers`, the checker retains the earlier original-helper
comparison mode. Both modes require the same pinned local tools, original image,
table, and saved Ghidra project; see [build strategy](../build-strategy.md).
Output must be new and under ignored `local/`. The Ghidra project is read-only.

Successful recovered-helper run:
`local/validation/tbcr-access-20261006/COMPLETE.json`.

| Comparison | Passed cases |
| --- | ---: |
| Selector: null/bad magic/count limits/reordered and duplicate offsets/modular sums and index shifts | 26 |
| Payload: null/bad magic/fixed +16/opaque header word | 458 |
| Count: null/bad magic/zero divisor/unsigned boundaries/floor and random quotients | 457 |
| Registry accessor: every slot 0..66, invalid/high-bit IDs, null slots, boundary slots with distinct containers, section-index forwarding | 213 |
| Full lookup with all four rebuilt table helpers: pinned 1,201 entries and synthetic/boundary inputs | 1,770 |
| Original quotient versus independent mathematical expectation | 818 |

Every direct helper case and lookup compares original/rebuilt/expected r0 values
with separate memory states. Minimal four-byte wrong-magic and twelve-byte
empty-container fixtures detect unwanted later reads. The payload helper also
returns +16 from a four-byte TBL1 fixture, demonstrating that it doesn't inspect
the rest of the header or payload. Registry decoy fields expose wrong offsets.
Count fixtures declare large payload lengths without allocating them, exercising
the fact that count reads only the header. Fixture expectations are constructed
independently from the recovered C; they don't use the safe file parser.

The combined ARM unit is 296 bytes, linked at harness address `0x00600000`.
Rebuilt entries are lookup `0x00600000`, selector `0x00600050`, payload
`0x006000B0`, count `0x006000D4`, registry accessor `0x00600110`. Literal pools
are included in the binary size. It is not binary matching or a bootable game.
All calls preserve r4-r11/SP, write only within the harness stack, and finish
within 136 instructions (budget 512). Rebuilt execution may enter original code
only in the reviewed quotient ranges; entering any original table helper fails.
Entering division with r1=0 also fails. Reads are confined to initialized fixture,
registry, stack, rebuilt-unit, or original-image extents. Flags, caller-clobbered
registers, timing, and stack scratch bytes are not compared.

There are 26 passing public synthetic tests, including four helper-corpus checks.
The private execution results rely on Ghidra ARM semantics; hardware/live evidence
remains open. Generated fixtures/results, original listings, ELF/raw binaries and
logs stay local. `COMPLETE.json` records input, source/header, tool-config and
validation-script hashes, case totals, and the remaining original dependency.

A local negative control removed the selector's computed-pointer null guard.
The checker rejected it with `Out-of-fixture read: 0` and wrote no comparison
success report. Evidence and commands are in
`local/validation/tbcr-access-20261006-negative-null/NEGATIVE.json`; the local
driver is `local/validation/check-tbcr-negative.py`. Repository source was unchanged.
Original-helper mode also passes with the updated harness:
`local/validation/nkm-20261006-helpers-regression/COMPLETE.json` (80-byte unit).

## Next work

The user deferred live gameplay verification until much later (2026-10-06).
The consumed quotient contract at `0x002C6C64` and its branch targets is now
recovered; continue with second NKMSortIndex consumer `0x001A0EA4`.
Compiler/ABI research and the host address boundary are additional ready work.
The eventual live session still needs loaded-resource/lookup observations and
checkpoint/configuration/isolation evidence for G1/G2; do not request it now.
No source has been transferred to the PC port.
