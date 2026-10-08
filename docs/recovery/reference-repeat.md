# A09 preparation repeatability

2026-10-08 (Europe/Warsaw). This package checks G3's fresh-preparation requirement
against the accepted G0 reference. It adds no recovered game code and does not
close G3, establish independent decoding, or start a native port.

## Selection and acceptance

The initial decomp and port trees
were clean. The previous host package's six indexed evidence files and eight
recovered-source identities were rehashed successfully; its behavior checks
were not repeated. Further allocator recovery is not a dependency of preparation
or stable table evaluation.

Acceptance for this bounded package:

1. Complete the existing pinned preparation pipeline in a fresh ignored root,
   leaving supplied inputs and the accepted extraction unchanged.
2. Compare inputs, selected NCCH content, compressed/expanded executable,
   ExHeader and NKMSortIndex identities against G0, backed by actual file hashes.
3. Pass public synthetic tests with private inputs absent from the test export.
4. Record decoder commonality and remaining gates without claiming authenticity,
   a clean-machine build, independent decoding, or reviewed source transfer.

These are the preparation portion of A09. Existing repository baseline commits
remain available; no commit or transfer was performed. A09's reviewed transfer
decision and the other G3 prerequisites are outside this package's acceptance.

## Reproduction

From `SMT4-decomp`, with Python 3.10+ and the pinned local CTRTool binary:

```powershell
python tools/prepare_reference.py --output local/reference-eu-g3-NEW
python tools/check_reference_repeat.py --repeat local/reference-eu-g3-NEW --output local/validation/reference-repeat-NEW
python -m unittest discover -s tests -v
```

Both output roots must be fresh. `--baseline` defaults to `local/reference-eu`.
The checker rejects equal/overlapping preparation/evidence roots and confines
new evidence to `local/`. It does not alter either extraction. Manifest paths
must remain within their root; duplicate paths and incomplete or stale markers
are rejected. It rehashes every base/DLC output file, compares the inventories
and metadata, rechecks each recorded verification log, and separately requires
the accepted four executable/table identities. Only a successful comparison
emits its own `COMPLETE.json`.

For a checkout without private inputs, supply the hash-identified base and DLC
packages and preserved save copies under `../Game`, or pass `--game-dir PATH`.
Use the default `local/tools/ctrtool-v1.3.0/bin/ctrtool.exe` or `--ctrtool PATH`;
the existing preparer verifies the configured executable hash and downloads
nothing. See [reference inputs](../reference-eu.md) and
[analysis setup](../analysis-setup.md) for the separate Ghidra import procedure.
A checkout without the G0 extraction can first prepare a baseline and then a
second distinct root. Absolute input roots may differ; relative input identities
must match. The comparison assumes the configured reference and baseline metadata
are the accepted records; its hashes are integrity checks, not signed provenance.

The actual repeat used `local/reference-eu-g3-20261008`. The preparer read and
hashed original inputs before and after extraction, selected the executable by
NCCH form/content metadata, preserved raw compressed ExeFS code separately, and
completed all 17 contents and 20,423 output files. Base application, manual, and
15 DLC content records remain separate. Original inputs were not rewritten.

## Evidence

Paths below are relative to the decomp repository; generated records and logs
are ignored and private.

| Check | Result | Evidence |
| --- | --- | --- |
| Complete second preparation | 17 contents, 20,423 inventoried files; final input comparison passed | `local/reference-eu-g3-20261008/COMPLETE.json` |
| Actual baseline/repeat bytes and selected identities | Both full output inventories rehashed and matched | `local/validation/reference-repeat-20261008/COMPLETE.json`, `comparison.json`, `preparations.json` |
| Manifest and command determinism | `inputs.json` and `files.json` byte-identical; 21 command records equal after output-root normalization | `local/validation/reference-repeat-20261008-audit/determinism.json` |
| Prior milestone evidence and source identities | Six indexed evidence hashes and eight recovered-file hashes retained | `local/validation/reference-repeat-20261008-audit/prior-evidence.json` |
| Data-free public regression | 78 tests pass: prior 70 plus eight repeat-checker tests | `local/validation/reference-repeat-20261008-audit/public-tests.json`, `public-tests.log`, `public-source-export.json` |
| Package closeout | Evidence identities, documentation links, diff checks and unchanged port state | `local/validation/reference-repeat-20261008-audit/COMPLETE.json` |

The synthetic repeat tests exercise missing/stale completion markers; modified,
missing and extra extracted files; input drift; wrong pinned selected identity;
failed verification despite zero exit status; wrong tool/executable metadata;
duplicate and escaping paths; and output overlap/overwrite refusal. They create
small synthetic manifests and bytes, without calling CTRTool or reading game data.

The full suite ran once from a copy of public working files at
`local/validation/reference-repeat-20261008-audit/public-source-export`, including
the new checker/tests. No `.git`, private `local/`, game files, or sibling `Game`
was supplied to that copy. The export records per-file hashes and base revision
`72ee6a30622fd19e33161ab8f597fa4989082b05`. This is evidence that the public suite
needs no supplied game data, not OS-enforced read isolation or a clean-machine
qualification. No original/rebuilt ARM regression was needed: recovered source,
fixtures and build/check paths were unchanged.

Accepted selected identities (both preparations):

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Base executable NCCH | 1,875,677,184 | `92d6feba05dbcacda8efb7d51dab6c2da35c079e4e2130848e9a56b1b96c824a` |
| Compressed code | 2,141,552 | `c9fafbf3a4e46e5f8b984e5b060d7cb90d12f4a0244bbe7440b2cfd97be4f2d9` |
| Expanded code | 3,633,152 | `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd` |
| ExHeader/access descriptor | 2,048 | `27305333aae9ce837964861a589ee3e44bb7ae234041d31bf97a20bba79cf29e` |
| NKMSortIndex | 50,400 | `194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4` |

The base and DLC input hashes and both save identities match G0. Complete input
paths/hashes remain in the private inventories. The output inventory SHA-256 is
`291405f226c305799d7061b30ae4c7ed9a0389683c35947e405e1bb996b42362` and input-manifest
SHA-256 is `8356ec8388e5dd4c7d241832992a6f9fe6385833ab60704482de6f8aae6c5b53` in both
runs. `manifest.json` differs because its command arguments contain the new
absolute output root; normalized command records match, including signature
exceptions. There are 46 recorded signature-exception lines, including summary
and detail lines, not 46 distinct signatures. Internal hash success does not
establish retail authenticity.

## Decoder boundary and next independent task

Both complete runs use the same pinned CTRTool 1.3.0 executable, SHA-256
`79021f283b2199950eb22cf3c459806b9c8aaaf68f65c80100107d3454a1c224`, and unchanged
`tools/prepare_reference.py`. NCCH-driven expansion and the earlier raw-ExeFS
expansion check use CTRTool's decoder. Repeating either path cannot independently
test a shared decoder defect. No separately implemented decoder ran here.

The next bounded package is **independent compressed-code decoder validation**:
inspect `local/reference-eu/base/0000/exefs-original/code.bin` and its compression
metadata/footer, select or implement a separately sourced decoder with explicit
provenance, and compare its output byte-for-byte with
`local/reference-eu/base/0000/exefs/code.bin` and the pinned expanded hash above.
Use a fresh ignored output directory and synthetic valid/truncated/back-reference
boundary cases. Do not decompress the already expanded image. Establish decoder
independence from CTRTool's implementation, not merely a different wrapper or
invocation. Keep host decoding research separate from recovered game source.
That package can close the executable decompression uncertainty; it must not
claim independent CIA/NCCH/RomFS decoding unless those paths are also validated.

G1/G2 live checkpoint, profile/configuration, loaded-table agreement and review
remain deferred. G3 still needs its prerequisite gates, original compiler/full
ABI and matching decision, independent decoder evidence, reviewed source
transfer/licensing disposition and final reproducibility review. Host lifetime
and service policy and an asset-backed native demonstration remain downstream.
The recovered boundary stays at 43 entry contracts plus two adapted regions.
