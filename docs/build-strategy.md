# Recovered-unit build strategy

The comparison toolchain produces bounded ARM units for original/rebuilt
behavior checks. It does not identify the original compiler, produce a full
3DS application or establish binary matching. Detailed package results live in their recovery reports.

## Pinned tools and execution

Use the existing xPack GNU Arm Embedded GCC **15.2.1-1.1** distribution, compiler
**15.2.1 20251203**. The original download/archive pin is under `gdb` in
`config/analysis-tools.json`; executable fingerprints for comparison builds are
in `config/recovery-tools.json`. GCC/binutils licenses stay with the ignored
distribution. No installation or system PATH change is needed.

Public tests need only Python and synthetic fixtures:

```powershell
python -m unittest discover -s tests -v
```

Private comparison wrappers additionally need the pinned Ghidra/JDK, authoritative
saved EU import and local executable/table extraction from [analysis setup](analysis-setup.md).
Run Ghidra jobs sequentially and give each run a fresh ignored output directory.
The selected checker source and recovery report define its actual build inputs,
flags, models and domain.

The initial lookup unit uses C11,
`-O2 -march=armv6 -marm -mfloat-abi=soft -ffreestanding`, no builtins or unwind
tables, `-nostdlib`, and warnings as errors. It links at harness-only address
`0x00600000`. Units using CLREX require `-march=armv6k`; retain the explicit
LDREX/STREX/CLREX instructions rather than assuming portable C atomics.
Some integrations use function sections and linker garbage collection to omit
unexercised functions. These are comparison builds without startup code, a C
library, SDK, OS or host game runtime.

## Consumer comparison modes

Run from the repository root, replacing NEW-NAME with a fresh directory:

```powershell
python tools/check_nkm_lookup.py --recover-pairs --output local/validation/NEW-NAME
```

Earlier modes remain available and retain their own evidence boundaries:

| Mode | Recorded ARM unit size | Consumed executable dependencies |
| --- | ---: | --- |
| Default original-helper mode | 80 bytes | Original table helpers and quotient |
| `--recover-helpers` | 296 bytes | Original quotient; four table helpers rebuilt |
| `--recover-quotient` | 352 bytes | No original code on the rebuilt path |
| `--recover-pairs` | 472 bytes | No original code on the rebuilt path; adds section-3 consumer |

All of these modes use original-address registry data supplied by the harness.
This table describes their recorded builds, not a total recovered-source size.
See [lookup](recovery/nkm-sort-index.md), [table helpers](recovery/tbcr-access.md),
[quotient](recovery/unsigned-quotient.md) and [section-3](recovery/nkm-section3.md)
for contracts, corpora, negative checks and exact evidence.

The original-helper build resolves three helpers with `--defsym`. The recovered-
helper build replaces the table-helper bindings with
`smt4_unsigned_quotient=0x002C6C64` and
`smt4_table_resource_registry=0x0049382C`; execution of original table helpers is
rejected on that rebuilt path. Quotient recovery leaves only the registry-data
binding. No C library or compiler division routine is silently substituted.
The source models original little-endian loads and 32-bit addresses; a compile-
time assertion confines the original-address helper implementation to 32-bit targets.

## Connected recovery and its limits

The [resource order](recovery/resource-order.md),
[synchronous chain](recovery/resource-chain.md),
[signal/lock chain](recovery/resource-chain-signal.md),
[arbitration](recovery/resource-arbitration.md),
[chain through SVC](recovery/resource-chain-svc.md), and
[registry chain](recovery/resource-registry-chain.md) reports record progressively
larger linked comparisons. The [asynchronous request](recovery/resource-request.md),
[registry completion/release](recovery/resource-registry-request-release.md),
[continuous worker](recovery/resource-worker-connected.md), and
[registry reuse](recovery/resource-registry-reuse.md) reports describe retained
state across submission, traversal and completion. The latest allocation and
conversion builds are in [allocation integration](recovery/resource-registry-allocation.md)
and [release conversion](recovery/resource-release-convert.md).

These reports own the historical byte counts, tested instruction addresses and
interceptions for each command. An optional recovered dependency does not change
an older default mode. Scheduled exclusive outcomes, bounded pending prefixes,
modeled SVC/kernel operations and lower file/allocator calls must stay explicit.
For example, the default signal/lock mode binds and intercepts arbitration at
`0x002A88FC`, keeping handle data at `0x00471B58`. Its `--recover-arbitration`
mode links the recovered wrapper and intercepts SVC instead; neither mode
implements kernel behavior.

## Original ABI, matching and native handoff

The initial lookup's 80-byte GCC output differs from the original 60-byte routine
in instruction ordering, byte loads and relocated branch encodings. That result
supports bounded behavior reconstruction; it neither selects GCC as a matching
toolchain nor rules out future matching. Full original ABI/compiler identity,
language of origin, runtime-library provenance and broader struct layouts remain
open.

Consumed quotient behavior does not establish a complete division ABI. The
[remainder interface](recovery/resource-order.md) adapts original r1 to C r0;
full signed/zero-divisor behavior and state seeding remain unclaimed. ARM exclusive
instructions need a reviewed native synchronization boundary. Original 32-bit
addresses/registry layouts need an explicit host adaptation before 64-bit use.

Before G3 closes, complete its required G1/G2 evidence, define a useful recovered
unit and its dependencies, investigate compiler fingerprints, repeat preparation
into a fresh ignored directory, and establish reviewed repository baseline
commits. Independent compiler/host-boundary research can continue while live
checks are deferred. No revision-pinned port handoff exists yet. Keep repository
histories separate and choose the transfer mechanism from the actual source
boundary and provenance/license decisions.
