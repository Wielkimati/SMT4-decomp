# Table-unit compiler/runtime and bounded ABI research

2026-10-08, A08. Research against EU base v0 expanded code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
All original addresses below are ARM virtual addresses. This package changes
validation tools, not recovered source, entry-point totals or port code.

## Selection and acceptance

The decoder package was complete: 24 prior evidence/source files were checked
against its audit, and the eight table-unit source identities still match
`config/nkm-host-contract.json`. A08 compiler/ABI investigation was the recorded
next dependency. Heap configuration integration does not block evaluating a
stable table snapshot. Repeating extraction or descending into division-by-zero
handling would not advance the consumed table contract.

Acceptance: bind static observations to the pinned image; distinguish compiler
identity from calling-convention compatibility; build and regress the existing
unit; exercise arguments, results, preserved registers and stack boundaries at
the quotient and its count caller; reject relevant faults; state matching and
provenance limits. This is a bounded A08 milestone, not the complete G3 gate.

## Observed instructions and build artifacts

| Boundary | Confirmed observation |
| --- | --- |
| `0x002C6C64..0x002C6C94` | Dividend r0, nonzero divisor r1; dispatch uses r2 accumulator and r3 scratch |
| `0x002C61E4..0x002C62D4` | Shared shift/subtract worker; final instructions form remainder in r1 and quotient in r0; `BX LR` returns |
| `0x002C0EA0..0x002C0ED4` | Count caller checks null, TBL1 magic and divisor +8; loads dividend +4 into r0 and tail-branches to quotient with LR unchanged |
| `0x002C0ED4` | TBL1 magic literal, not an instruction or part of the adjacent function |
| Rebuilt quotient `0x006001A0..0x006001D8` | 56-byte loop; pushes r4/LR, returns quotient in r0, leaves divisor in r1 and residual in r2; pops r4/PC |
| Rebuilt count `0x0060014C` | Performs equivalent guards and tail-branches to rebuilt quotient |

The original nonzero quotient path and count caller use no stack or data writes.
Their reviewed instructions touch r0-r3 and condition flags; r4-r12, SP and LR
are preserved. The GCC quotient uses eight stack bytes, r4, LR and r12 as scratch,
then restores the required saved state and returns. LR's register value after
the GCC return is not promised; the saved return address is loaded into PC.
Neither matching scratch registers nor matching stack traffic is a requirement
of the consumed C interface.

GNU objdump independently decodes the original byte ranges; Ghidra exports
`abi-listing.txt`. The original image is a flat expanded segment allocation,
not an ELF file with compiler attributes or an import symbol table. The new
GCC ELF *does* report EABI version 5, soft-float ABI, ARMv6, 8-byte alignment
requirements, wchar_t size 4 and small enums. These are facts about the comparison
artifact only; they do not establish original float, enum, wchar_t or C++ ABI.

## Fingerprint and provenance assessment

`fingerprint.json` records the exact case-insensitive patterns and every hit
over printable ASCII runs of length at least five. Compiler-related markers
(`compiler`, `ARM Ltd`, `ARM C`, `GCC:`, `RVCT`, `armcc`, `Metrowerks`, `Microsoft`)
and runtime-name markers (`__aeabi`, `__rt_`) have no hits. The middleware pattern
finds `NW4C_Tga Ver1.0` at `0x004094DC`, `nw4c_txd` at `0x004094EC`, `nw4c_tfm`
at `0x0040952C` and `nw4c_end` at `0x00409548`. These are data-format clues, not
compiler/version or whole-library attribution. This narrow search does not cover
UTF-16 strings, stripped symbols, every possible vendor spelling or code modules.

**Candidate:** the observed integer call boundary is compatible with the relevant
base AAPCS32/RTABI32 conventions. Arm's [AAPCS32, 2025Q1](https://github.com/ARM-software/abi-aa/blob/2025Q1/aapcs32/aapcs32.rst)
describes core argument/result registers, saved registers, platform-dependent r9
and stack alignment. Its [RTABI32, 2025Q1](https://github.com/ARM-software/abi-aa/blob/2025Q1/rtabi32/rtabi32.rst)
specifies numerator/denominator ordering and quotient/remainder results in r0/r1.
Compatibility does not identify this entry as a named `__aeabi_*` implementation,
the compiler vendor or an exact runtime release. These later specifications are
comparison references, not proof of the historical toolchain.

**Unresolved:** original compiler/vendor/version/options, exact runtime-library
origin, signed and zero-divisor ABI, floating-point and aggregate conventions,
interworking callers, wider register/platform policy and original-target linkage.
The positive-domain signed-entry remainder recovery in
[resource-order](resource-order.md) retains its original, narrower scope.

The downloaded standards are hash-pinned in
`local/validation/table-abi-20261008-research/sources.json`, under their stated
CC-BY-SA-4.0 plus patent-license terms, for reference only. No external
implementation or standard text was copied into recovered code. Research tools
reuse project harness patterns. No project source license or redistribution
permission is established by these observations.

## Controlled comparisons

Reproduce from `SMT4-decomp`, with the authoritative Ghidra project closed:

```powershell
python tools/check_table_abi.py --output local/validation/NEW-TABLE-ABI
python -m unittest discover -s tests
```

The wrapper runs the unchanged `check_nkm_lookup.py --recover-pairs` build and
complete regression, then runs the new ABI job sequentially on the same saved
project. `--unit local/validation/EXISTING/unit` can reuse a completed pair-mode
artifact after checking source, validation-tool and binary identities. Generated
game listings, fixtures, binaries, observations and logs stay ignored under local/.

The 2,615 existing division pairs cover high-bit operands, every quotient bit,
dispatch/normalization boundaries, exact/inexact results and deterministic random
inputs. Each runs through original/rebuilt direct quotient and count calls with
two distinct unused-core-register/condition-flag seeds and two separated
8-byte-aligned stacks.
Null, bad-magic and zero-divisor headers exercise the caller's bypasses. This is
20,932 single-path calls, not 20,932 paired comparisons or new recovered contracts.

The harness enforces original/rebuilt execution separation, nonzero division,
exact arguments and tail-call LR, r4-r11/SP preservation, original r12/LR
preservation, word alignment throughout and eight-byte alignment at quotient
entry, initialized bounded loads, stack-only stores, surrounding stack guards,
512-instruction budget and return sentinel. Original remainder is independently
checked using integer modulo. Python checks every emitted observation's identity,
completeness, quotient, direct remainder and stack depth. Flags, timing and arbitrary
stack bytes are not compared for equivalence. Address visitation does not prove
all predication outcomes, all uint32 pairs or a complete ABI.

The original remainder and rebuilt r1 differ on every direct observation because
the rebuilt artifact leaves the nonzero divisor there, while remainder is smaller.
This explicitly demonstrates why the quotient C implementation is suitable for
the count caller but is not a drop-in replacement for a dual-result division ABI.
No new remainder interface or source recovery is claimed.

Final evidence: `local/validation/table-abi-20261008-final/COMPLETE.json`.
The unit regression is `local/validation/table-abi-20261008/unit/COMPLETE.json`:
5,775 comparisons, unchanged 472-byte binary. The final ABI evidence records
20,932 calls and three rejected instruction mutants: wrong remainder, failure to
restore r4, and a write at the incoming SP outside the frame. All 101 public tests
pass from a source export without private inputs, including six new evidence
validation tests. The audit index is
`local/validation/table-abi-20261008-audit/COMPLETE.json`.

| Path | Calls | Maximum instructions | Maximum stack depth |
| --- | ---: | ---: | ---: |
| Original quotient | 5,230 | 124 | 0 |
| GCC quotient | 5,230 | 262 | 8 |
| Original count | 5,236 | 135 | 0 |
| GCC count | 5,236 | 274 | 8 |

The original paths visit 85 distinct instruction addresses: 72 in the division
ranges and 13 in the count caller. These maxima describe the bounded direct/caller
ABI run, not the much longer section-3 consumer regression.

The first development run passed all positive calls and rejected two mutants;
the third correctly raised a wrapped stack-boundary exception which the negative
runner did not recognize. It has no success marker. The final run fixes only
that exception handling and uses the already validated unit, without repeating
the consumer regression. Original memory and on-disk source/binary are never
patched; fault injection affects disposable emulator memory only.

## Matching disposition and next independent task

For this unit, retain pinned GCC as a behavioral comparison toolchain. Its
quotient algorithm, scratch-register results, stack frame and bytes differ from
the original, beyond relocation alone. No original matching compiler is selected;
matching feasibility remains unresolved, and no matching work is required for
the present host research. This records a bounded build decision, not a decision
to abandon possible future matching or a claim of a reconstructed 3DS application.

Next: **A08 private NKMSortIndex file-to-memory host evidence bridge**. Read
[the host boundary report](nkm-host-boundary.md), `config/nkm-host-contract.json`,
`tools/check_nkm_host_boundary.py`, `tools/tbcr.py`, and the pair/lookup fixtures.
Add a separate opt-in decomp research checker which hash-checks and parses the
pinned 50,400-byte `battle/NKMSortIndex.tbb`, maps it plus a synthetic stable
registry through the existing native address adapter, and compares both consumed
sections against the existing private original/GCC fixture results. Reuse
`write_cases`/`write_pair_cases` and a validated `--recover-pairs` artifact; verify
exact reference/source/artifact/fixture identities before reusing observations.
Exercise reference indices, first-match/zero-fallback behavior and admission
failures with synthetic mutations. Keep the default host command synthetic-only,
all game bytes local, service/lifetime semantics explicit, and no port import or
runtime implementation. This resolves an evidence gap between file validation,
original ARM behavior and the already exercised host address boundary; it is not
a request for a native game demonstration or live verification.

G1/G2 live evidence remains deferred. G3 still needs its prerequisite gates,
broader compiler/ABI investigation, reviewed transfer revision/mechanism,
provenance/licensing disposition and final review. Independent container/filesystem
decoding remains unvalidated; native lifetime/service policy remains downstream.
