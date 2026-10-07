# NKMSortIndex host address/registry boundary

2026-10-07, A08 build/interface research. This package defines and exercises a
bounded 64-bit host address adapter for the existing seven-contract table unit.
It adds **no recovered game entry points**, performs no source transfer, and
does not implement the PC runtime. G1/G2/G3 remain open.

## Selection and result

Reviewing the linked consumer/helper sources shows
that the combined lookup unit has no allocator, loader, synchronization, file,
or kernel calls. Its only external symbol is registry data. Supplying stable
synthetic registry/table bytes therefore resolves a useful A08 boundary without
recovering more heap internals. Configuration integration remains independent.

The old handoff's three positive evidence manifests and ten negative manifests
were checked against the package index hashes, rather than re-running unrelated
heap tests. Details: `local/validation/nkm-host-20261007-audit/previous-handoff.json`.
The initial decomp and port working trees were clean.

The candidate dependency inventory is machine-readable in
[`config/nkm-host-contract.json`](../../config/nkm-host-contract.json).
The host adapter is [`tools/host/nkm_address_space.c`](../../tools/host/nkm_address_space.c),
with its explicit interface in [the header](../../tools/host/nkm_address_space.h).
This is research code under tools/, distinct from original recovery under src/.

## Exact recovered source set

Reviewed decomp source revision: `540231316901f771ae18f9b59a6dc53e7a03591c`.
All eight files below are unchanged from that revision. The contract records
each Git blob ID, last-change revision, and SHA-256 of the actual working file
bytes (including checkout line endings). The new adapter is uncommitted work,
identified by file hashes in its COMPLETE.json, **not** a revision-pinned import.

| Source | Original ARM entry / role |
| --- | --- |
| `src/nkm_sort_index.c` | `0x002883E8..0x00288424`: section-2 lookup |
| `src/nkm_section3.c` | `0x001A0EA4..0x001A0F1C`: section-3 pair scan |
| `src/tbcr_access.c` | `0x002AC358`, `0x002C0EF0`, `0x002C0EA0`, `0x002C0F18`: four helpers |
| `src/unsigned_quotient.c` | `0x002C6C64`: consumed nonzero-divisor quotient |
| `src/nkm_sort_index.h` | Two consumer declarations and supported-memory contracts |
| `src/tbcr_access.h` | Four helper declarations |
| `src/unsigned_quotient.h` | Quotient declaration; divisor must be nonzero |
| `src/resource_lifecycle.h` | Registry extern declaration; no lifecycle source is needed |

The quotient includes the dispatch targets `0x002C62B8`, `0x002C6294`,
`0x002C6270`, `0x002C623C`, `0x002C620C` and normalized subtract region
`0x002C61E4..0x002C62D4`; see [its instruction evidence](unsigned-quotient.md).
The exact original ranges/contracts are owned by
[lookup](nkm-sort-index.md), [pair lookup](nkm-section3.md), and
[table helpers](tbcr-access.md). They remain bounded behavioral recoveries,
not binary matching, a full division ABI, or live agreement.

The ARM comparison compiles the four C sources and binds
`smt4_table_resource_registry=0x0049382C`. All rebuilt executable dependencies
are internal; no original instructions execute on the rebuilt path. The
472-byte unit links at harness address `0x00600000`, which is not an original
address or a native mapping. The original image and private table remain
comparison inputs, not dependencies of the synthetic host run.

## Original resource and address dependencies

Reference: EU base title `0004000000141C00`, version 0, expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
The eventual content input is base RomFS `battle/NKMSortIndex.tbb`, 50,400 bytes,
SHA-256 `194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4`.
Both consumed sections contain 1,201 four-byte records in this reference.
Game bytes remain local; the host check uses only generated synthetic data.

| Dependency | Exact boundary |
| --- | --- |
| Registry | Original base `0x0049382C`, 67 entries, 16 bytes per entry |
| Entry fields | LE u32 path address +0, loaded address +4, size/output +8; u8 policy +12; opaque bytes +13..15 |
| Consumer access | Resource 1; only the loaded-address word at `0x00493840` is read |
| Selection | TBCR magic, count at +8, header word +4, offset directory at +12; selected TBL1 magic |
| Payload/count | Payload is section+16 regardless of +12; count is unsigned word(+4)/word(+8), or zero for rejected section/zero divisor |
| Section 2 | Fixed stride 4; return LE u16; out-of-range index and zero count select the first halfword |
| Section 3 | Full u32 key versus u16 key; first matching u16 value, zero replaced with 50; missing/no match returns 50; count read again after each mismatch |

The [lifecycle trace](resource-lifecycle.md) identifies initializer `0x003F05F0`
and policy-one bulk loading via `0x0033C8A0`; individual zero-policy loading is
not the original NKMSortIndex initialization path. Those routines are **not
required to evaluate a stable loaded snapshot**. The host fixture supplies that
snapshot explicitly; it neither recovers their scheduling nor substitutes a
service claiming successful original I/O. Registry path/size/policy/opaque bytes
remain original-width bytes and are not reinterpreted as native pointers.

Original helpers support specified modular u32 additions and index shifts.
Actual header/registry words must be readable and aligned. Consumers additionally
require each accessed halfword within its payload backing object without address
wrap. Rejected/missing sections are safe for the pair scan but outside the
section-2 lookup's memory contract. File-format validation and loaded-memory
evaluation are separate interfaces: use the existing safe parser for eventual
content admission, not these permissive original helpers.

## Exercised host interface

`smt4_host_eval(space, operation, arg0, arg1, &value, &reads)` evaluates one of
six adapted helper/consumer contracts. Operation/input/result/address values are
u32. The space contains up to 64 non-overlapping regions, an explicit u32
registry address, and a caller-supplied u32 logical-read budget. Each region
has a u32 original address and extent plus a native pointer to its backing bytes.
Native pointers occur only in adapter descriptors, never in serialized data.

The caller owns stable descriptors and readable bytes of at least the declared
extent, and keeps them unchanged throughout a call. Output pointers must be
valid and must not alias each other, the descriptors, or mapped bytes. No native
pointer validity can be inferred from a raw caller-supplied pointer. This is an
in-process trusted-buffer interface, not a sandbox for arbitrary native pointers.
Regions define backing objects; even adjacent mappings do not allow a consumer
to walk from one object into the next. Region order is not semantically relevant.

The adapter validates map overlaps/lengths/wrap before evaluation and resolves
each actual aligned load against its region extent. It preserves selector u32
modular arithmetic and helper payload+16 wrap, including successful null helper
results. It rejects unsupported consumer/header wrapping, unmapped/truncated
reads and unaligned loads. Every successful logical word/halfword load consumes
one budget unit, including repeated count loads. Budget exhaustion terminates
the adapter call; it is not an original game timeout or return value.

Status is separate from `value`: OK yields the original-width result/address;
BAD_MAP, UNMAPPED, ALIGNMENT, ADDRESS_WRAP, BUDGET or BAD_OPERATION leave `value`
untouched. A diagnostic does not invent game behavior for unsupported memory.
Pair scan on a null registry slot succeeds with 50; section-2 lookup on the same
slot fails with UNMAPPED rather than being assigned zero or 50.

The prototype compiles **only** the new host adapter and unchanged
`src/unsigned_quotient.c`. Its six address-oriented functions adapt the documented
logic, explicitly replacing original pointer dereferences. It does not compile
the original six functions unchanged, remove their 32-bit assertion, replace the
existing ARM modes, implement a loader, or decide the eventual port API. Helper
call timing/ARM instructions/register effects are not reproduced by native code.
Stable ordinary memory only; MMIO, concurrent mutation, ownership transitions,
async completion, allocation/free and stale-handle generations remain outside it.

## Reproduction and evidence

From SMT4-decomp, use fresh local output directories:

```powershell
python tools/check_nkm_host_boundary.py --output local/validation/NEW-HOST
python tools/check_nkm_lookup.py --recover-pairs --output local/validation/NEW-ARM
python -m unittest discover -s tests
```

The host command needs 64-bit Python and installed Visual C++ x64 build tools;
it discovers vcvarsall through vswhere or accepts `--vcvarsall PATH`. It changes
only the child-process build environment. Here it used MSVC 19.29.30159 for x64,
C11, `/O2 /W4 /WX /LD`, the installed 14.29.30133 tools and Windows SDK. The
compiler/linker/setup hashes and Python version are in `toolchain.json`; exact
arguments/logs and generated binaries remain local. This records the actual
research toolchain, not an original-compiler fingerprint or a port tool choice.
Other native compilers/architectures are untested. The ARM command retains its
pinned GCC/Ghidra requirements and sequential project access.

| Validation | Result / evidence under `local/validation/` |
| --- | --- |
| Native synthetic evaluation | 3,192 passes: 1,154 helper, 1,770 section-2, 239 pair cases and 29 boundary cases; `nkm-host-20261007-final-r2/COMPLETE.json` |
| Compiled adapter faults | Wrong registry field, narrowed key, cached count, accepted overlap all rejected; `nkm-host-20261007-final-r2/negatives.json` |
| Fresh original/rebuilt ARM comparison | 1,154 helper, 1,770 lookup, 236 pair and 2,615 quotient cases; binary hash and complete comparison object unchanged from `pairs-20261006`; `nkm-host-20261007-arm-regression/COMPLETE.json` |
| Shared evidence bridge | Identical fixture bytes and TSV expectations for 1,154 helper + 531 lookup + 191 pair synthetic cases across host and fresh ARM runs; `nkm-host-20261007-audit/shared-synthetic.json` |
| Public suite | All 64 existing tests pass; `nkm-host-20261007-audit/public-tests.json` and `.log` |
| Identity/handoff audit | Source/script hashes, clean recovered-source revision and 13 prior handoff manifests checked; `nkm-host-20261007-audit/COMPLETE.json` |

The native suite reuses the existing generators/oracles. Their `reference` and
`pair_reference` names in the native fixtures denote synthetic 1,201-record
stand-ins, not game assets. Thus native pair probes total 239 instead of the
ARM reference corpus's 236. The 1,876 shared synthetic cases are the direct
evidence bridge; the private reference probes were **not run on the host**.
Native results are not independent original instruction execution; the separate
ARM comparison validates the shared expectations against original behavior.

Boundary checks cover addresses above 2 GiB and near 4 GiB, null versus absent
registry data, invalid/high resource IDs without reads, minimal magic backing,
unreadable payloads, truncated/split words and payloads, object crossings,
overlaps, null backing, zero-length/too-many mapping descriptors, alignment, arithmetic wrap,
zero budget, and count re-reads. All mapped bytes remain unchanged; every fault
preserves a sentinel output. Zero count still reads the first lookup halfword.
Duplicate/zero-first behavior, full-width inputs, unsigned halfwords, fixed
stride and nondivisible sizes are retained in the reused fixture corpus.

Earlier local attempts are retained: `nkm-host-20261007-initial` exposed duplicate
PATH casing in the inherited Windows environment; normalizing the child
environment fixed discovery. `nkm-host-20261007-check` passed the native suite.
`nkm-host-20261007-final` passed positive cases and three mutants, but its fourth
mutant was rejected at compilation due to constant-condition warnings. It was
rewritten into a compiling faulty condition; final-r2 records all four behavioral
rejections. No failed attempt has a package success marker. No original source
or existing comparison mode was modified to accommodate these checks.

## Provenance review and open handoff gates

The eight recovered files were reviewed against their source comments and the
instruction-derived reports. They are project reconstructions from the pinned
local EU image; no external implementation was copied into this package. The
adapter/checker are new project-authored research, with reused project fixtures.
Original runtime-library identity remains unresolved, including the quotient's
library provenance; only its consumed behavior is claimed. No project-wide
license has been selected. This factual provenance review does not grant
redistribution rights or complete a legal/licensing review.

GCC/binutils/Ghidra/JDK remain pinned local analysis dependencies with their
existing notices; the installed proprietary Microsoft tools and SDK are used
only for this host build and are not vendored. No game data, SDK binary, generated
binary, log, database, or full pseudocode was added to tracked source.

Future handoff prerequisites remain:

- **G1:** reproducible gameplay checkpoint, current content/settings and isolated
  profile evidence, then gate review. Live work remains deferred by instruction.
- **G2:** loaded-table/live consumer agreement and gate review; synthetic/native
  and ARM comparisons do not close the live requirement.
- **G3:** required G1/G2 evidence; original compiler/full ABI investigation and
  matching decision; fresh complete preparation with selected-hash comparison
  and outstanding independent decoder evidence; reviewed source revisions,
  transfer mechanism, provenance/licensing disposition and reproducibility review.
- **Port demonstration:** eventual validated local-content admission and host
  lifetime/error policy, a reviewed native adaptation/import, and an asset-backed
  demonstration under the separate roadmap. None was started here.

Repository baselines exist (decomp base noted above; port
`5869acd0a910a92270d5ba5d3baa4ad6281c63e3`), but identifying them does not authorize
transfer or review the new adapter as a port dependency. The existing seven
contracts are unchanged, and all other recovered/model boundaries remain as
recorded in their own reports.

The next independent work is A09's clean preparation
reproducibility check: follow `docs/reference-eu.md` and run
`python tools/prepare_reference.py --output local/reference-eu-g3-NEW` into a
fresh ignored root, compare the selected
input/executable/ExHeader/table hashes, and document exactly which decoder paths
are independent. Do not repeat G0 intake, change original inputs, start live
gameplay, or select/transfer a port import merely because this package passed.
