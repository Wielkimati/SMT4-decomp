# Private NKMSortIndex file-to-memory evidence bridge

2026-10-08, A08 build/interface research. Reference: EU base v0, expanded code
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
This adds a private research check, no recovered entry points, port code, resource
service, source transfer or live evidence. G1/G2/G3 remain open.

## Selection and acceptance

The completed [ABI package](table-abi.md) and current handoff both selected this
bridge. It connects the safe file reader, original/GCC consumer observations and
the [host address adapter](nkm-host-boundary.md), resolving a useful A08 evidence
gap without allocator work. A stable supplied registry is sufficient; heap
configuration integration remains independent. The existing working tree held
the completed preparation, decoder and ABI work and was preserved.

Acceptance: verify reference/source/binary/fixture identities before reuse;
admit and parse the pinned private table; execute both consumers through the
native adapter with stable synthetic registry bytes; compare to original/GCC
observations; cover reference boundaries, first-match/zero fallback and synthetic
admission failures; preserve the synthetic default and pass affected regressions.
All criteria have evidence below. Whole-project gates and native policy remain
separate dependencies.

## Admission and exact reuse boundary

[`tools/check_nkm_host_reference.py`](../../tools/check_nkm_host_reference.py)
is a separate opt-in command. It reads at most 50,401 bytes from the existing
local table and requires the 50,400-byte pinned identity:
`194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4`.
The contract and recovery-tool pins must agree; the original executable is also
hash-checked. Both private inputs are checked again after the run.

`tbcr.parse` validates extents while retaining all unknown and trailing bytes.
The research admission policy additionally requires aligned section headers and
both consumed sections to contain exactly 1,201 four-byte records. Section 2
starts at file offset 40,736; section 3 at 45,568. Each has a 4,804-byte payload
and 12 retained trailing bytes. This stricter policy is not recovered behavior
for malformed files. It is not installed as a runtime loader.

Reuse checks enforce the exact eight-file source inventory in
`config/nkm-host-contract.json`, all seven original validation/configuration
identities, the 472-byte ARM binary identity
`187b9ef735363c4ca9c17ce302b995b6d76571c1591f7120421267194fb56b14`, recovered
helper/quotient mode, comparison/manifest agreement and successful completion log.
`write_cases` and `write_pair_cases` regenerate the complete private/synthetic
consumer fixtures. Every generated file must be byte-identical to the reused
unit fixture, including both TSVs. All 1,770 lookup and 236 pair observations
must match the regenerated inputs, expected result, original result and rebuilt
result in order, with complete fixture totals and no duplicate observations.

The reused unit is `local/validation/table-abi-20261008/unit`. Its existing
5,775 ARM comparisons remain the original execution evidence. This package
does not rerun ARM/Ghidra or imply that native execution itself observes the
original instructions. The original entries are `0x002883E8` and `0x001A0EA4`.
The reuse report records the current exact hashes of observations, manifest,
binary, comparison report/log and regenerated fixtures. Historical manifests
are unchanged. These are local reproducibility checks, not signed attestations.

## Native mapping and results

The unchanged adapter and quotient compile with the existing MSVC x64 C11
research build helper. Compiler/linker/setup identities, command and log are
recorded locally. The original pointer-based source is unchanged; this still
executes six adapted address contracts plus the compiled original-source
quotient, as documented in the host boundary report.

The complete admitted table maps as one backing object at `0x00800000` and then
`0xFFFF0000`. A separate 1,072-byte synthetic registry maps at `0x0049382C`;
its resource-1 loaded-address field points at that table. Other fields retain
the existing synthetic sentinel pattern. Native pointers remain only in the
adapter descriptors. Each call owns stable backing and a 100,000-read budget.
Both mappings fit u32 without wrap. All table and registry bytes remain unchanged.

| Check | Result | Evidence under `local/validation/` |
| --- | --- | --- |
| Private section-2 queries | 1,239 indices at two placements: all 1,201 records, out-of-range/high-width probes and deterministic random indices agree | `nkm-host-reference-20261008/host-results.json` |
| Private section-3 queries | 45 keys at two placements agree, including missing/full-width keys and zero fallback | Same observations |
| Synthetic first-match boundary | 12 duplicate and 12 zero-first queries at two placements agree with original/GCC observations; distinct from private admission | Same observations |
| Private bridge total | 2,616 successful calls: 2,568 private and 48 synthetic | `nkm-host-reference-20261008/COMPLETE.json` |
| Synthetic admission negatives | Nine rejected: wrong size/hash/magic, directory count, out-of-file section, oversized payload, zero stride, count drift and unaligned headers | `nkm-host-reference-20261008/admission-negatives.json` |
| Default synthetic host regression | All 3,192 checks; four compiled adapter faults rejected; result bytes equal the previous default run | `nkm-host-reference-20261008-synthetic/COMPLETE.json` |
| Public tests | All 110 pass from a source export without private inputs; nine new tests cover admission and evidence completeness/value checks | `nkm-host-reference-20261008-audit/public-tests.json` |
| Identity and tampering audit | Reuse corruption is rejected; prior ABI evidence and unchanged recovered/adapter sources checked | `nkm-host-reference-20261008-audit/COMPLETE.json` |

Structural negative inputs are entirely synthetic, with their own declared
identities so that structure checks can be reached. The private command always
uses the pinned game identity. Missing-section and partial-record admission,
missing/duplicate/reordered observations and wrong original/rebuilt results are
also covered by public tests. Existing default host faults retain their distinct
status/result-sentinel and bounded-memory evidence; no default behavior changed.

## Reproduction and limits

From `SMT4-decomp`, with fresh ignored output directories:

```powershell
python tools/check_nkm_host_reference.py --unit local/validation/table-abi-20261008/unit --output local/validation/NEW-HOST-REFERENCE
python tools/check_nkm_host_boundary.py --output local/validation/NEW-HOST-SYNTHETIC
python -m unittest discover -s tests
```

To recreate a missing ARM artifact, run the existing
`python tools/check_nkm_lookup.py --recover-pairs --output local/validation/NEW-ARM`
with the saved authoritative Ghidra project closed, then pass that directory as
`--unit`. Run Ghidra jobs sequentially. This package needed no Ghidra job.

No game bytes are added to public sources/tests. All fixture copies, DLLs, TSVs,
observations, logs and input-derived summaries stay ignored. Project-authored
research reuses existing project tools; no external implementation was copied.
No licensing or redistribution permission is inferred. The seven original table
contracts and total 43 entry contracts plus two adapted regions are unchanged.

The registry is supplied, not loaded by recovered lifecycle/I/O. Allocation,
ownership, async publication, concurrent mutation, release and stale handles
remain outside this stable-snapshot check. The second mapping tests addressing,
not host lifetime policy. Section-3 private coverage is sampled, not exhaustive
over all u32 keys. Original compiler/full ABI/runtime provenance and matching,
reviewed transfer/licensing and deferred live G1/G2 agreement remain unresolved.
This is not the native demonstration or G3 completion.

## Next independent package

Select **A09 bounded independent NCCH/RomFS table extraction research**. Follow
[reference-eu](../reference-eu.md), [preparation evidence](reference-repeat.md),
[decoder limits](code-decoder.md), `config/reference-eu.json` and
`tools/prepare_reference.py`. Start from preserved
`local/reference-eu/base/content.0000.00000000`, verify its existing inventory
identity and executable metadata, and independently locate/read the RomFS path
`battle/NKMSortIndex.tbb` into a fresh ignored directory. Use a bounded read-only
metadata reader with explicit format/provenance references, then compare every
table byte and its pinned hash to the existing extracted file and run this host
bridge against the established evidence as appropriate. Cover synthetic bounds,
offset arithmetic, directory cycles and malformed names before accepting paths.
Do not implement general extraction or port services merely to read this file.
Distinguish independently checked NCCH extents/RomFS traversal from unvalidated
CIA decoding, IVFC authenticity/integrity and complete filesystem coverage.

This directly extends the validated table dependency toward its preserved
container and addresses the remaining independent extraction uncertainty. It
does not repeat the completed executable expansion or preparation. Broader
compiler attribution and optional allocator integration remain independent;
deferred live gates stay open without blocking this work.
