# Independent NCCH/RomFS table extraction

2026-10-08 (Europe/Warsaw), bounded A09 preparation research. The new reader
locates `battle/NKMSortIndex.tbb` in the preserved EU application NCCH and
reproduces all **50,400 bytes** of the accepted table. The extracted file also
passes the existing native host evidence bridge. No recovered game source,
entry-point contract, platform service or port implementation was added.

## Strategic review and acceptance

Its 26 indexed artifacts
were checked against disk before implementation; all matched. G3/A09 still has
independent extraction and other reproducibility/provenance dependencies. This
package connects the same useful table to its preserved container without
repeating intake, the host milestone or unrelated allocator recovery. The
existing uncommitted preparation, decoder, ABI and host work was retained.

Acceptance required an independently written bounded reader, reference inventory
and executable-metadata admission, fresh local output matching every pinned table
byte, synthetic bounds/arithmetic/graph/name evidence, host integration and
affected regressions. All passed. CIA decoding, IVFC verification, full filesystem
coverage and G1/G2/G3 acceptance were explicitly excluded; those remain open.

## Implementation provenance

[`tools/ncch_romfs.py`](../../tools/ncch_romfs.py) is new project Python code
written from the reverse-engineering format descriptions on 3dbrew:

- [NCCH, revision 23516](https://www.3dbrew.org/w/index.php?title=NCCH&oldid=23516),
  header, flags and region descriptions.
- [RomFS, revision 23726](https://www.3dbrew.org/w/index.php?title=RomFS&oldid=23726),
  physical/logical layout and level-3 directory/file metadata descriptions.

The downloaded pages identify those revisions. Copies and retrieval hashes are
kept only in `local/validation/ncch-romfs-20261008-research/`: `ncch.html`
SHA-256 `303589f72e11e5be1b560837108e18c91f30ce6c2456464bef0236d6763cce77`,
`romfs.html` SHA-256
`2b00a5460a00c1e6cae7bc2ef8f40dee866c7327f4c64a7ed225f4e7c6e9cc63`.
`spec-download.json` records URLs and sizes. Format documentation was consulted;
no external implementation or hash-table pseudocode was copied or incorporated.
No redistribution license for those documents was established; they remain local.
The project's source-license decision is still open. This is independent
implementation evidence, not a clean-room or redistribution-permission claim.

The parser imports only Python standard-library `dataclasses` and `struct`.
It does not invoke CTRTool, an emulator, Ghidra or original game code. The checker
reuses project hashing, inventory/path and output-confinement helpers; none
performs container decoding. The comparison oracle remains CTRTool's accepted
extraction. Independent implementations can still share an incorrect format
assumption; byte equality is evidence for this input, not universal correctness.

## Admission and observed layout

[`tools/check_ncch_romfs.py`](../../tools/check_ncch_romfs.py) verifies the
accepted preparation's completion-linked input, file and content manifests.
It checks the selected executable record, pinned inventory rows and actual
NCCH/table hashes before parsing. It does not rehash or re-extract all other
contents. The fixed source paths are:

| Artifact under `local/reference-eu/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `base/content.0000.00000000` | 1,875,677,184 | `92d6feba05dbcacda8efb7d51dab6c2da35c079e4e2130848e9a56b1b96c824a` |
| `base/0000/romfs/battle/NKMSortIndex.tbb` | 50,400 | `194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4` |

The independently read header has version 2, 512-byte media units, flags
`0000000001030004`, executable/application form, CTR platform and NoCrypto set.
Program and partition IDs are both `0004000000141c00`, product `CTR-N-AMXP`.
Its declared content extent equals the actual file size. Header/ExHeader/access
descriptor, plain, ExeFS and RomFS extents are in bounds and disjoint. The logo
region is absent. This checks ExeFS's outer extent, not its directory or files.

The bounded IVFC profile uses magic/version `IVFC`/`0x10000`, three block
exponents of 12, header field `0x54 = 0x5C`, zero optional-info size and zero
per-level reserved fields. The documentation calls field `0x54` reserved;
accepting exactly the observed `0x5C` is a profile restriction, not a broader
interpretation of that field. Master-hash size is 896 bytes. The physical order
is header/master hashes, level 3, level 1, level 2. The level-3 physical start
is aligned from the end of the master hashes; its logical offset is distinct.
Logical and physical extents are checked without reading/verifying hash blocks.

| Observed coordinate | Value |
| --- | ---: |
| RomFS offset within NCCH | `0x24C000` (2,408,448) |
| RomFS extent | 1,873,268,736 bytes |
| Level-3 offset within RomFS | `0x1000` |
| Level-3 extent | 1,858,624,099 bytes |
| Directory metadata offset/length within level 3 | 3,812 / 35,212 |
| File metadata offset/length within level 3 | 119,540 / 1,165,556 |
| File-data origin within level 3 | 1,285,104 |
| `battle` directory record offset within directory metadata | 108 |
| Selected file record offset within file metadata | 17,688 |
| Selected file offset within file-data region | 23,386,832 |
| Selected file offset within NCCH | `0x19D46C0` (27,084,480) |

The tool indexes exact variable-length record boundaries and validates names
for 942 directory and 20,126 file records. For this path it traverses only root
directory siblings and `battle` file siblings, checking complete sibling chains
even after a match. Other graph edges and file payload extents are not validated.
Indexing all record boundaries is not whole-filesystem traversal or coverage.
All detailed coordinates, selected metadata and visited offsets stay in the
local `comparison.json`.

## Bounds and behavior

All extents are checked against their containing range before seek/allocation;
u64 arithmetic does not wrap. Exact input size, supported NCCH media-unit profile,
region overlap, IVFC physical/logical layout, table ordering/alignment and data
origin are checked. Record pointers must identify indexed boundaries. The reader
rejects visited sibling/ancestor cycles, wrong parents, duplicate sibling names,
odd or malformed UTF-16, empty non-root names, separators, dot components, NULs
and selected control characters. Names remain case-sensitive and unnormalized;
valid non-BMP UTF-16 is covered synthetically. No path from metadata is used as
a host output path: the checker writes the fixed name `NKMSortIndex.tbb`.

Default limits are 16 MiB combined metadata, 100,000 records, 1,024 name bytes,
32 path components, 16 MiB selected-file data and 64 MiB parser reads. The private
checker tightens the selected-file limit to 50,400 bytes. These are research-tool
admission rules, not claimed original-game behavior. Hash-table bucket contents
and hash-chain links are ignored; path lookup uses tree links.

The checker compares every extracted byte and the pinned SHA-256, writes and
rereads a fresh output under ignored `local/`, then rehashes the entire selected
NCCH, reference table and preparation records. Inputs are read-only and unchanged.
Original dumps/saves were not opened for writing or replaced.

## Validation and reproduction

Run from `SMT4-decomp`, choosing fresh output directories:

```powershell
python tools/check_ncch_romfs.py --output local/validation/NEW-NCCH-ROMFS
python tools/check_nkm_host_reference.py --table local/validation/NEW-NCCH-ROMFS/NKMSortIndex.tbb --unit local/validation/table-abi-20261008/unit --output local/validation/NEW-ROMFS-HOST
python -m unittest discover -s tests
```

`--reference` selects another accepted preparation root, with the same pinned
identities. Output/reference overlap and existing output are rejected. The host
bridge's new optional `--table` argument accepts only a local file with its
unchanged pinned identity/admission contract. Omission retains its previous
default input. It records the actual path in `COMPLETE.json`.

| Evidence | Result |
| --- | --- |
| `local/validation/ncch-romfs-20261008-final/COMPLETE.json` | Independent extraction equals all 50,400 bytes; before/after input hashes match |
| Same directory's `admission.json`, `comparison.json`, `NKMSortIndex.tbb` | Inventory, actual identities, independent metadata/path coordinates and private output |
| `local/validation/ncch-romfs-20261008-host/COMPLETE.json` | Extracted table: 2,568 private and 48 synthetic native calls match verified reused original/GCC observations; nine admission negatives rejected |
| `local/validation/ncch-romfs-20261008-default-host/COMPLETE.json` | Default bridge passes unchanged; all observations byte-identical to both prior and extracted-table runs |
| `local/validation/ncch-romfs-20261008-audit/public-tests.json` | All 131 tests pass from a public source export without private inputs; 21 new reader/checker tests |
| Same audit directory's `mutants.json` | Three syntactically valid parser faults rejected: logical/physical level confusion, omitted data-region base, duplicate sibling acceptance |
| Same audit directory's `host-regression.json`, `prior-evidence.json`, `COMPLETE.json` | Observation equality, prior evidence/source preservation and package closeout |

Synthetic tests cover valid root/nested lookup, Unicode/case, media-unit and
u64 arithmetic, zero-length/end-of-region files, changed/truncated inputs,
master-hash alignment beyond one block, malformed wrapper/table extents,
metadata record boundaries, bad parents/names, missing paths, directory/file
cycles including links after a matched entry, duplicate names and work limits.
Checker tests cover stale/missing/duplicate/wrong inventory, actual-byte drift,
ambiguous/wrong executable metadata, independent header identity, output
confinement/overlap/overwrite and admission failure without success output.

The first synthetic run exposed fixture name-length and Windows short/long temp
path assumptions; those were corrected. The reader also gained an explicit
actual-stream-size check. The earlier exploratory private run under
`local/validation/ncch-romfs-20261008/` predates those changes; the `-final` run
is authoritative for the final implementation. The full public suite ran once
after the coherent changes. The audit driver is
`local/validation/ncch-romfs-20261008-research/run-audit.py`. Exported sources
exclude `.git`, private `local/` and game inputs; this is data-free test evidence,
not OS-enforced isolation or clean-machine qualification.

Host checks rebuild the unchanged MSVC adapter/quotient DLL. They reuse exact
source/binary/fixture-verified ARM observations from the existing unit; no ARM
comparison or Ghidra job ran in this package. The default synthetic host adapter
was unchanged, so its previous 3,192-check/four-mutant evidence was retained,
not rerun. No detached build jobs or emulator sessions remain.

## Limits and next independent package

This closes **independent NCCH extent and RomFS path extraction for the pinned
table**. It does not independently decode CIA, decrypt NCCH, verify signatures,
verify NCCH superblock or IVFC hashes, validate hash buckets/unvisited graphs or
extract every file. Whole-file hashes bind the accepted input; they do not prove
authenticity. Other regions, block profiles, large-file streaming and arbitrary
filesystem extraction are outside this reader's supported scope.

Next select **bounded A09 independent ExeFS-to-expanded-code preparation**.
The table now reaches its preserved NCCH independently, while the completed
[code decoder](code-decoder.md) still begins with CTRTool-extracted compressed
bytes. Closing that gap connects the same accepted container to the analysis
executable without implementing loader/port services or expanding filesystem
scope. This is more useful next than optional allocator integration or broad
unvisited RomFS validation; IVFC verification remains explicitly open.

Reuse this reader's admitted NCCH/ExeFS outer extents and the pinned inventory.
Consult the ExeFS format documentation with recorded provenance; independently
read the directory, locate `.code`, check file extents/overlap and the associated
stored SHA-256. Extract the 2,141,552 compressed bytes and 2,048-byte
ExHeader/access descriptor from the preserved NCCH into a fresh ignored output.
Compare the existing pinned hashes in [reference-eu](../reference-eu.md) and
`tools/check_code_decoder.py`, verify compression/segment metadata, then call
the existing decoder and compare all 3,633,152 expanded bytes and hash.
Cover synthetic malformed/duplicate names, extents/overlap, hash-slot ordering,
hash failures and extraction-to-decoder input mix-ups. Keep the current table
mode and earlier decoder evidence intact. Do not decompress the already expanded
image or imply CIA/IVFC verification, compiler matching or a runtime loader.

G1/G2 live evidence remains deferred. G3 still needs its prerequisite gates,
compiler/full-ABI and runtime-provenance/matching disposition, reviewed
source-transfer/licensing and final review. Native lifetime/service policy and
a native demonstration remain downstream. The recovery boundary remains 43
entry-point contracts plus two adapted internal regions.
