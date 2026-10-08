# Independent executable decompression

2026-10-08 (Europe/Warsaw). The new project decoder independently reproduces
all **3,633,152 expanded EU code bytes** and their pinned SHA-256. This is
decomp-side preparation research, not recovered game source, a new entry-point
contract, an original-target build, or port implementation.

## Selection and acceptance

Their 16 indexed evidence/source hashes
were verified against the working files. The preceding package's uncommitted
changes were preserved. G3's remaining preparation uncertainty is a more direct
dependency than optional allocator configuration integration; stable table
evaluation requires no further allocator descent.

Acceptance for this package was:

1. Establish a separately implemented decoder with explicit provenance; a second
   invocation of CTRTool is insufficient.
2. Inspect the identified compressed input's footer and ExHeader, independently
   expand it into a fresh ignored directory, and compare every byte and the
   accepted expanded hash. Leave reference inputs unchanged.
3. Exercise synthetic valid, boundary and malformed streams, pass affected
   public regressions without private data in the export, and verify that
   meaningful decoder faults are detected.
4. Record the implementation's bounded scope and leave container/filesystem
   independence, deferred live checks and other G3 requirements unclaimed.

All four criteria passed. G3 itself remains open.

## Implementation provenance and independence

[`tools/code_lz.py`](../../tools/code_lz.py) is newly written project Python code
from the LZrev format description in Martin Korth's GBATEK, accessed through
the [GBATEK Markdown mirror](https://github.com/mgba-emu/gbatek/blob/64b5087aa45cd0187b8b239d77e54ee5eb2917d1/ds.md)
at revision `64b5087aa45cd0187b8b239d77e54ee5eb2917d1`. The consulted sections are
“LZrev Compressed Font Resource Format” and “LZrev - Reverse Decompression”.
The mirror's `ds.md` SHA-256 is
`75b69cfac0d9e7252ed2beb5b9e5fa60986e1fac8f490f38590f6399d5130dc1`.
Its original documentation site is [GBATEK](https://problemkaputt.de/gbatek.htm).
The original site could not be fetched in this session; the pinned mirror
and download metadata are preserved only in ignored research storage.

No external decoder implementation or dependency was incorporated. GBATEK was
consulted as format research; its source/pseudocode was not copied into the
repository. No license grant for redistributing that document was established;
the downloaded document stays local. The project-wide source license remains
undecided. This is an independently written implementation, **not a clean-room
claim** or a finding about redistribution rights.

The decoder reverses only the compressed payload, then grows a forward history
of decoded bytes in reverse output order. It restores the immutable prefix and
reverses the history once at the end. It has no CTRTool invocation, shared
decoder module, native library, or game-code execution. Only Python's standard
library is required. The checker imports this decoder directly and validates
the input identities before calling it.

After implementation and the successful reference comparison, the existing
decoder was inspected at Project_CTR tag `ctrtool-v1.3.0`, commit
`e8f5f529c54ff9b22a2491a480ffa69206bf7b19`:
[lzss.c](https://github.com/3DSGuy/Project_CTR/blob/e8f5f529c54ff9b22a2491a480ffa69206bf7b19/ctrtool/src/lzss.c)
and [LzssProcess.cpp](https://github.com/3DSGuy/Project_CTR/blob/e8f5f529c54ff9b22a2491a480ffa69206bf7b19/ctrtool/src/LzssProcess.cpp).
That C implementation uses descending input/output indices and an output buffer
initialized from the compressed bytes. Its C++ wrapper calls `lzss_decompress`.
The new Python implementation does not reuse either file; local source-download
hashes and an import inventory document this boundary. Shared format semantics
are expected; independent implementation does not prove either program correct
on every possible stream. No CTRTool binary was rebuilt or rerun here.

## Observed input and format contract

All paths here are relative to `SMT4-decomp`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `local/reference-eu/base/0000/exefs-original/code.bin` | 2,141,552 | `c9fafbf3a4e46e5f8b984e5b060d7cb90d12f4a0244bbe7440b2cfd97be4f2d9` |
| `local/reference-eu/base/0000/exefs/code.bin` | 3,633,152 | `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd` |
| `local/reference-eu/base/0000/exheader.bin` | 2,048 | `27305333aae9ce837964861a589ee3e44bb7ae234041d31bf97a20bba79cf29e` |

The ExHeader flag byte at `0xD` is `3`, including compression bit 0. Its allocated
segment pages at `0x14`, `0x24`, and `0x34` sum to 3,633,152 bytes. The footer's
last eight bytes are `15 ad 20 0b 90 c2 16 00`. Interpreted in little endian:

| Field | Observed value |
| --- | ---: |
| Compressed span including footer | 2,141,461 |
| Footer length including padding | 11 |
| Expansion beyond input length | 1,491,600 |
| Uncompressed prefix | 91 |
| Compressed payload excluding prefix/footer | 2,141,450 |
| Footer padding | Three `FF` bytes |

Each flag group describes up to eight tokens, highest bit first. A literal
contributes one byte. A match has a four-bit length plus 3 and twelve-bit
distance plus 3; overlapping copies refer to the growing decoded history.
The prefix remains unchanged. These are format facts used by the host tool,
not a recovered game decompression routine.

The strict decoder requires a nonempty payload, footer/span bounds, positive
growth, a bounded declared output, valid history references, complete tokens,
and exact output length. Its default allocation limit is 64 MiB; the reference
checker tightens that to the pinned expanded size. Footer padding and unused
final flag bits are opaque. Zero-growth/uncompressed forms and NDS overlay
autodetection are intentionally unsupported. The format has no reliable magic;
the checker requires pinned compressed bytes and the ExHeader flag rather than
guessing whether a buffer needs decompression. Malformed-input diagnostics and
the allocation limit are host-tool policy, not claimed original-game behavior.

## Reproduction and evidence

From `SMT4-decomp`, Python 3.10+:

```powershell
python tools/check_code_decoder.py --output local/validation/code-decoder-NEW
python -m unittest discover -s tests -v
```

`--reference` optionally selects a different root containing the same pinned
`exefs-original/code.bin`, `exefs/code.bin`, and `exheader.bin` identities. Output
must be new, inside `local/`, and not overlap the reference root. The already
expanded image is used only as the comparison oracle. The checker compares
the decoded bytes, writes and rereads the output, rechecks all three input files,
then emits `COMPLETE.json`. It does not overwrite the accepted extraction.

| Check | Result | Evidence |
| --- | --- | --- |
| Independent reference expansion | Every output byte matches; pinned hash and ExHeader allocation agree; inputs unchanged | `local/validation/code-decoder-20261008/COMPLETE.json`, `comparison.json`, `code.bin` |
| Public data-free suite | 95 tests pass, including 17 new decoder/checker tests | `local/validation/code-decoder-20261008-audit/public-tests.json`, `public-tests.log`, `public-source-export.json` |
| Fault sensitivity | Five syntactically valid decoder mutants rejected by behavioral tests | `local/validation/code-decoder-20261008-audit/negatives.json` |
| Prior handoff retained | All 16 indexed artifacts match their prior hashes before documentation updates | `local/validation/code-decoder-20261008-audit/prior-evidence.json` |
| Implementation provenance | Pinned GBATEK and CTRTool source hashes; decoder import inventory | `local/validation/code-decoder-20261008-research/spec-download.json`, `ctrtool-source.json`, `local/validation/code-decoder-20261008-audit/implementation.json` |
| Package closeout | Indexed evidence/source hashes, links, diff checks and repository boundary checks | `local/validation/code-decoder-20261008-audit/COMPLETE.json` |

The public suite ran from an export of public working files, with no `.git`,
private `local/` tree, or game inputs copied into it. This demonstrates the
suite's data-free inputs; it is not OS-enforced read isolation or clean-machine
qualification. The local audit driver is
`local/validation/code-decoder-20261008-research/run-audit.py`.

Synthetic coverage includes a hand-encoded overlapping match and opaque prefix,
footer lengths 8 through 11 and 255, partial and complete flag groups, lengths
3/4/17/18, distances 3/4/4097/4098, exact allocation limits, truncated footer and
tokens, invalid footer arithmetic, zero growth, unproduced-history references,
output overrun/underrun, trailing tokens, identity drift, swapped expanded input,
wrong ExHeader compression/allocation, output mismatch, output confinement and
overwrite refusal, and failure without a success marker. Mutants alter flag
order, distance bias, length bias, match byte order, and overlapping-copy
handling. All were valid Python and failed behavioral checks.

The private stream contains 183,361 flag bytes, 975,687 literals and 491,201
matches. Decoded matches contribute 2,657,374 bytes, lengths span 3–18 and
distances span 3–4097. No match in this reference overlaps itself; distance 4098
and overlapping behavior are therefore supported by synthetic evidence only.
These observations describe this input, not coverage targets or game recovery.

## Limits and next independent package

Independent **compressed executable expansion** is now validated for the pinned
EU input. CIA/NCCH/ExeFS/RomFS extraction still comes from CTRTool, and independent
container/filesystem parsing is unvalidated. This result does not authenticate
the dump, rerun preparation, validate a compiler, or close G1/G2/G3. Original
sources and existing original/rebuilt harnesses did not change; their ARM checks
were not rerun. No Ghidra or emulator job was started.

The next useful independent package is **A08 compiler/runtime fingerprint and
bounded ABI research for the existing table unit**. Start with
[build strategy](../build-strategy.md),
[the quotient report](unsigned-quotient.md),
[the remainder report](resource-order.md), and
[the source boundary inventory](nkm-host-boundary.md).
Inspect the pinned executable and saved listings for compiler/runtime clues;
record positive and negative evidence without inferring compiler identity from
one idiom. Center the bounded ABI check on `0x002C6C64`, its shared worker
`0x002C61E4..0x002C62D4`, and the table-count caller `0x002C0EA0`. Reuse the
existing quotient corpus and checker infrastructure to document the consumed
argument/result, register-preservation and stack boundary, and compare the
existing GCC artifact at the same contract. Record runtime-library
provenance and matching conclusions as confirmed, candidate or unresolved;
do not claim a full ABI or descend into zero-divisor handling unless it is a
demonstrated dependency. No original compiler installation, port import or
live gameplay is required for that bounded research.

Deferred G1 checkpoint/configuration/profile review and G2 loaded-table/live
consumer agreement remain open. G3 still needs compiler/full-ABI and matching
investigation, reviewed source-transfer revision/mechanism and provenance/license
disposition, prerequisite gates and final review. Native lifetime/service policy
and an asset-backed demonstration remain separate downstream work.
