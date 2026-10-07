# NKMSortIndex lookup recovery

The second consumer is now recovered too: [section-3 pair lookup](nkm-section3.md).
Use `--recover-pairs` for both consumers and all recovered dependencies: 472 bytes,
236 pair cases plus the existing 5,539 comparisons. Registry loading remains open.

Latest continuation, 2026-10-06: [quotient recovery](unsigned-quotient.md) removes
the last original-code dependency from the rebuilt lookup path. Six entry-point
contracts build as 352 bytes, passing 1,770 lookup, 1,154 helper and 2,615 quotient
comparisons. Use `--recover-quotient`; the earlier results below remain historical.
The loaded registry/lifecycle and host address boundary are still unrecovered.

2026-10-06. One game routine is reconstructed in
[`src/nkm_sort_index.c`](../../src/nkm_sort_index.c), builds as a freestanding ARM
unit, and agrees with original instructions in a controlled Ghidra execution.
This is not a reconstructed 3DS application or a live gameplay comparison.

Original: ARM `0x002883E8..0x00288424` (end exclusive), EU base v0 expanded-code
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
See [the static evidence](../tbcr-consumers-eu.md). The C and descriptive names
were reconstructed from those instructions; no external implementation was copied.
No project-wide license has been selected.

## Interface and supported memory

The input is a 32-bit unsigned index. The returned register contains a
zero-extended little-endian u16; its gameplay meaning remains unknown.
The source obtains resource 1, section 2, obtains the payload, then obtains the
count, preserving the original call order. It reads at `payload + index*4` when
`index < count`, otherwise at `payload`. The stride stays four regardless of the
section entry-size field. The second halfword of a record is ignored.

The contract requires stable, loaded, readable TBCR/TBL1 memory and a readable
selected halfword with the original alignment. Pointer/offset arithmetic must
remain within its backing object without wrapping the address space. All 32-bit
indices are supported for the pinned valid table, including high-bit values.
Missing resources, null payloads, inaccessible memory, concurrent mutation,
unaligned original loads, MMIO, and address wrapping are outside this source
contract. There is deliberately no new error/zero return for them.

A zero count does **not** stop the original from reading the first halfword.
The controlled zero-size and zero-divisor fixtures retain readable backing bytes
to check this behavior. They do not establish that an absent or truly empty
allocation is safe. Likewise, synthetic nondivisible sizes test the original
count quotient; the safe analysis parser remains a separate interface.

## Dependencies retained in the initial comparison

| Helper | Address | Status |
| --- | --- | --- |
| Resource/section accessor | `0x002C0F18` | Original instructions; registry slot 1 initialized by harness |
| Section selector, called by accessor | `0x002AC358` | Original instructions, including header checks |
| Payload accessor | `0x002C0EF0` | Original instructions |
| Count accessor | `0x002C0EA0` | Original instructions |
| Unsigned division, called by count accessor | `0x002C6C64` and its branch targets | Original instructions; nonzero-divisor quotient tested separately |

There are no helper return-value stubs or intercepted calls. The harness supplies
the loaded registry pointer; it does not execute/recover the loader or initializer.
The full original initialized image remains a private execution dependency.
The division helper's other register results and zero-divisor entry contract are
unclaimed; the count accessor bypasses division for zero entry size.

Continuation: all four table helpers now have recovered source and direct
original/rebuilt comparisons. The `--recover-helpers` build passes the same
1,770 lookup cases using them, with only original division retained. See
[helper recovery](tbcr-access.md) for 1,154 direct cases, address/memory contracts,
and the 296-byte combined unit. The default checker mode retains the original
helper chain documented above.

## Comparison and reproduction

Close the Ghidra GUI project to release its lock. From the repository:

```powershell
python tools/check_nkm_lookup.py --output local/validation/nkm-next
python -m unittest discover -s tests -v
```

The checker requires the prepared EU executable/table, saved Ghidra project,
and pinned tools. See [build strategy](../build-strategy.md). It refuses an
existing output directory, confines output to `local/`, checks input/tool hashes,
builds the source at harness address `0x00600000`, and opens the original project
with `-readOnly -noanalysis`. The database and original files are unchanged.

The Ghidra `PcodeEmulator` executes both the original 60-byte routine and the
80-byte rebuilt unit with independent memory states. Both use the real original
helpers. Each result must also agree with an independent fixture expectation.
The pinned file contributes all 1,201 entries plus boundaries/high-bit/random
indices. Synthetic fixtures cover one entry, nonzero upper halfwords, values
above `0x7FFF`, zero returned halfwords, floor division, zero counts, zero entry
size, differing entry size versus fixed lookup stride, and random records.
Sections 0 and 1 contain distinct decoys to expose wrong section selection.

Observed successful runs: `local/validation/nkm-20261006-r5/COMPLETE.json` and
`local/validation/nkm-20261006-final/COMPLETE.json` (final tool/script provenance).

| Check | Result |
| --- | --- |
| Original/rebuilt/expected lookup agreement | 1,770 cases passed |
| Original unsigned division r0 versus mathematical quotient | 818 nonzero-divisor cases passed |
| Calling convention | r4-r11 preserved and SP restored on every call |
| Memory writes | Restricted to the harness stack |
| Execution bounds | Maximum 124 instructions per call, budget 512 |
| Public synthetic tests | 22 tests, including three comparison-corpus checks |

A negative control built a local copy with stride changed from four to eight.
The same checker rejected it at reference index 1, and emitted no success report.
Evidence and exact commands are retained in
`local/validation/nkm-20261006-negative-stride/NEGATIVE.json` and `commands.json`.
The repository source was unchanged by this control.

`results.tsv`, `division.tsv`, commands, ELF, raw unit, disassembly, fixtures,
and logs stay under the output directory. `COMPLETE.json` is emitted only after
the script's success marker/report and case count are checked. Source, tool, and
input hashes identify the run; the final run also records validation-script hashes.
The reference fixture and return-value tables contain game data: keep them local.

The harness uses initialized memory and checks data-read extents, writes, return
control flow, and preserved registers. It does not compare caller-clobbered
registers, flags, instruction timing, or stack scratch bytes. Decoder prefetch
has separate padding around the rebuilt unit; execution cannot enter that padding.

## Limits and next work

This is instruction-level behavioral agreement using Ghidra's ARM semantics,
not independent hardware evidence. Compiler scheduling and explicit byte loads
make the 80-byte unit different from the original 60 bytes. No matching claim is
made. Original compiler identity and full ABI still need investigation.

Earlier local attempts `nkm-20261006` through `-r4` failed while developing the
harness, with no success marker: legacy emulator context initialization, separate
SLEIGH flag initialization, legacy ARM return handling (`emulator is not STOPPED`),
and current decoder prefetch past the rebuilt unit. The final harness uses the
current emulator API; failures were not counted as successful comparisons.
API/source reference: [Ghidra PcodeEmulator](https://ghidra.re/ghidra_docs/api/ghidra/pcode/emu/PcodeEmulator.html)
and the matching source archive in the pinned local distribution.

A07 now has source, an ARM unit build, and bounded differential evidence. G2
remains open pending the outstanding G1 reference gate and live consumer agreement.
Next: observe resource slot 1 and a lookup call in a user-launched gameplay session;
record the actual loaded-table identity, input/result, and configuration/checkpoint.
The table helpers are now recovered; the quotient and loader remain dependencies.
The second consumer
at `0x001A0EA4` remains static analysis only. No source has been transferred to
the PC-port repository.
