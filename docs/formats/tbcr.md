# TBCR containers and TBL1 sections (EU base)

Observed 2026-10-06. A05/A06: structural analysis and a read-only analysis reader.
This is not recovered game source or a runtime comparison. All multibyte fields
below are little endian. Offsets in this document's format tables are file offsets,
not original executable addresses.

## Evidence and scope

The input is the completed `local/reference-eu/base/0000/romfs` extraction.
The inventory scans all 20,126 files: 386 `.tbb` files and 18 `.bin` files have a
`TBCR` prefix. All 404 pass the bounded reader, containing 768 `TBL1` sections.
The `.bin` examples are `addon/testdata/content01/aoc_base.bin` through
`content18/aoc_base.bin` inside the **base RomFS**; these are not the separately
supplied DLC contents and do not establish which resources the game uses.

Local evidence: `local/analysis/tbcr-20261006/checked/inventory.json` records each
container's SHA-256, size, fields, extents, and payload hashes. `COMPLETE.json`
records 404 accepted and zero rejected containers. No assets are exported into
source control. The earlier exploratory `initial-probe.json` calls nondivisible
payloads errors; the checked reader supersedes that assumption and retains them.

| Selected file | Bytes | SHA-256 |
| --- | ---: | --- |
| `battle/NKMSortIndex.tbb` | 50,400 | `194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4` |
| `item/ItemTable.tbb` | 202,544 | `42f2519cf70fcadb7d75e24a2e00c69b91c72b3be678b3327d77d6082ba7252a` |

The candidate code is bound to expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
See [consumer analysis](../tbcr-consumers-eu.md) for the independent instruction
checks and limits. No external parser implementation was incorporated.

## Container layout

| Offset | Type | Observed meaning |
| --- | --- | --- |
| `0x00` | 4 bytes | `TBCR` signature |
| `0x04` | u32 | Section base offset, measured from the start of this container |
| `0x08` | u32 | Number of section offsets |
| `0x0C` | u32[count] | Offsets relative to the section base, in directory order |
| After offsets to base | bytes | Opaque extra header bytes, retained |

For section `i`, its file offset is `section_base + relative_offsets[i]`.
This equation is supported by both the corpus and ARM routine `0x002AC358`.
The original helper checks the signature and unsigned index range, then performs
32-bit address additions; it does not receive the file length or validate extents.

Every observed section base and section start is 16-byte aligned. All first
relative offsets are zero; all directories increase strictly. Section counts
range up to 70. Alignment and zero-filled gaps are corpus observations, not checks
that the generic reader requires. The reader supports a preserved leading gap
and zero-section synthetic containers, without claiming they occur in the game.

## Section layout

| Offset from section | Type | Observed meaning |
| --- | --- | --- |
| `0x00` | 4 bytes | `TBL1` signature |
| `0x04` | u32 | Payload size in bytes, excluding the 16-byte section header |
| `0x08` | u32 | Entry-size/divisor field; zero occurs in the corpus |
| `0x0C` | u32 | Always `16` in these 768 sections; exact semantic role unresolved |
| `0x10` | bytes[payload_size] | Opaque payload |
| After payload | bytes | Gap to the next section or end of container; retained |

Routine `0x002C0EF0` returns `section + 16` after null and signature checks;
it does **not** consult the word at `+0x0C`. Do not use that word to move the payload
without further evidence. Routine `0x002C0EA0` uses `+0x04` and `+0x08` as arguments
to a division helper, after rejecting a zero divisor.

All observed trailing gaps contain zeros and have lengths 0 through 14, consistent
with aligning the following section/end to 16 bytes. The reader preserves any
bytes in those gaps rather than requiring zeros or stripping them.

76 sections have a nonzero remainder when payload size is divided by entry size.
Their format-specific explanation is unresolved. Three other sections have an
entry size of zero: section 0 in `saveLoadUI/SaveLoadUITable.tbb`, and sections 0
and 1 in `title/TitleTable.tbb`. Their payload sizes are 168, 344 and 450 bytes.
These are structurally accepted and remain opaque. The reader reports quotient
and remainder when the divisor is nonzero; it permits `entry(i)` only for an exact,
nonzero entry-size layout. It never silently drops a remainder.

## NKMSortIndex structure

Section base is `0x20`, count is 4, and the relative offsets are
`0`, `0x8D0`, `0x9F00`, `0xB1E0`.

| Section | Header offset | Payload bytes | Entry size | Exact entry count | Trailing bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| 0 | `0x0020` | 2,240 | 40 | 56 | 0 |
| 1 | `0x08F0` | 38,432 | 32 | 1,201 | 0 |
| 2 | `0x9F20` | 4,804 | 4 | 1,201 | 12 |
| 3 | `0xB200` | 4,804 | 4 | 1,201 | 12 |

Section 2's 1,201 little-endian u32 values are a permutation of **1 through 1,201**.
They are not zero-based indices into a 1,201-entry array without a conversion.
Section 3 is not a matching inverse u32 permutation: it has 764 zero words and
some values exceed 1,201. Consumer `0x001A0EA4` reads it as pairs of u16; the
first halfword is a lookup key and the second a value, with fallback 50. The
gameplay meaning of those pairs remains open.
Text-like bytes in sections 0 and 1 are leads, not established record types or
encoding guarantees. Do not infer field meaning solely from the filename.

`ItemTable.tbb` provides a second structural check: section base `0x30`, six
sections with `(payload bytes, entry size, exact count)` of `(10560,88,120)`,
`(7680,128,60)`, `(129360,168,770)`, `(12000,60,200)`, `(38400,48,800)`, and
`(4400,44,100)`. All have zero trailing bytes. Item semantics remain unexamined.

## Reader and reproduction

From the decomp repository:

```powershell
python tools/tbcr.py local/reference-eu/base/0000/romfs/battle/NKMSortIndex.tbb
python tools/inventory_resources.py --output local/analysis/tbcr-next
python -m unittest discover -s tests -v
```

The reader is `tools/tbcr.py`. It checks signatures, directory capacity before
count-controlled allocation, strictly increasing section offsets, complete
headers, and payload bounds against the next section or file end. Python integer
arithmetic avoids wrapping offsets into a false valid range. Analysis limits are
64 MiB per file read and 65,536 sections; neither is a claimed game-format limit.
All views refer to immutable original bytes. Opaque words, gaps, empty payloads,
and remainder bytes remain accessible. No decompression or encoding conversion
is attempted.

`inventory_resources.py` writes summaries only into a new ignored `local/`
directory and refuses output within the input tree. It scans prefixes regardless
of filename extension, and reports unsupported/malformed tables explicitly.
`COMPLETE.json` means the scan completed; its accepted/rejected counts determine
whether every candidate passed. Rejected tables also cause a nonzero exit status.

The synthetic suite covers known-good slicing, unknown-byte reconstruction,
truncation, bad signatures, huge counts/offsets, overlap, oversized payloads,
empty tables, zero/nondivisible entry sizes, index bounds, and inventory reporting.
Private corpus acceptance proves structural agreement only. A05/A06 can complete
while A07's recovered-source and original-routine comparison remain open.

## Other observed base-resource prefixes

The inventory records extension/prefix counts, not format decoding or runtime use:

| Extension | First four bytes | Files |
| --- | --- | ---: |
| `.bcwav` | `CWAV` | 8,038 |
| `.bcstm` | `CSTM` | 368 |
| `.stex` | `STEX` | 3,066 |
| `.earg` | `EARG` | 1,411 |
| `.bam` | `ATBC` | 844 |
| `.bcenv` | `CGFX` | 251 |
| `.bccam` | `CGFX` | 65 |
| `.bcanim` | `CGFX` | 10 |
| `.bf` | `00 00 00 00` | 1,437 |
| `.mbm` | `00 00 00 00` | 1,170 |

The zero prefixes do not identify a shared format. Compression, nested archives,
and embedded executable modules remain outside this structural pass.
