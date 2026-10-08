# Default worker locale callback and code mapping

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project names describe observed contracts, not original symbols. This A07 package
follows [path conversion](resource-worker-path.md).

## Selection and acceptance

This replaces
a concrete callback dependency in the worker's measurement/conversion/open path.
Optional
extraction/compiler work, live gameplay and port work remain outside this package.
Before edits, all 32 primary artifact identities from the path handoff were checked
in `local/validation/worker-locale-20261008-audit/handoff-check.json`.

Acceptance: instruction-backed byte/state and 16-bit mapping contracts; a
warning-clean ARM build; direct single-byte, lead/trail, invalid, incomplete,
resumption and mapping-boundary comparisons; connected worker conversion/open
with the original hash-bound locale/mapping data; retained affected older modes
and meaningful compiled-fault rejection. Locale bootstrap remains a separate
contract, not an implicit prerequisite or a recovered part of fixture binding.

## Recovered source

`src/resource_worker_locale.c` and `.h` add two original contracts:

| Original body (Thumb, end exclusive) | Source contract | Compiled bytes |
| --- | --- | ---: |
| `[0x00100F9C,0x00100FC8)` | `smt4_worker_locale_map` | 92 |
| `[0x00100FC8,0x00101064)` | `smt4_worker_locale_decode` | 344 |

Neither routine has a saved Ghidra function object. The comparison job establishes
contiguous Thumb instructions in these exact ranges in its read-only project
transaction, verifies the end before the shared literal pool, and discards its
listing changes. GNU disassembly independently covers the same bodies. Source
is derived from instructions; no absent-function decompiler output is assumed.

The callback always reads state word zero. With initial state zero, bytes
`0x81..0x9F` and `0xE0..0xEF` become the pending lead and return `0xFFFFFFFE`.
Bytes `0x80`, `0xA0` and values at least `0xF0` return `0xFFFFFFFF`, preserving
state and output. Other bytes complete with result 1: `0x5C` maps to `0x00A5`,
`0x7E` to `0x203E`, `0xA1..0xDF` to `byte + 0xFEC0`, and remaining accepted
bytes to themselves. Byte zero writes unit zero but still returns 1; the outer
conversion loop converts that completion into a zero byte-count result.

With nonzero state, only trails `0x40..0x7E` and `0x80..0xFC` are accepted.
The row is `lead - (lead < 0xE0 ? 0x81 : 0xC1)`; its modular 32-bit product
by 188 plus `trail - (trail < 0x80 ? 0x40 : 0x41)` is truncated and sign-extended
from 16 bits before mapping. A rejected trail or mapped `0xFFFF` preserves both
output and the pending state. Success stores the halfword, clears state word
zero, and returns 1. State word one and error storage are untouched by this
callback. The wrapper, separately recovered earlier, stores error 4 on invalid.
Arbitrary nonzero state words follow this arithmetic; they are not silently
normalized to valid lead bytes.

The mapping helper compares its incoming full signed 32-bit index. Values in
`[0x2F0,0x582)` return `0xFFFF`. Values at least `0x582` subtract `0x292`, then
truncate/sign-extend from 16 bits. An unsigned bound check rejects adjusted
indices at least 7,150, including negatives. Remaining indices read a halfword
from `0x0041CAA0`. The source expresses sign extension without signed overflow
or implementation-defined narrowing. Wide positive indices can wrap back into
the accepted range; the direct corpus checks this behavior.

## Private data and integration boundary

The 14,300-byte mapping (7,150 halfwords) has SHA-256
`49c21ead0aaa288dd04a9eaaf0e424dd2fd49300602a6a0ec7ca30df4392bcae`.
The checker obtains it from the hash-checked original program. No mapping bytes
are added to tracked source. Its 271 `0xFFFF` cells are rejection values; it has
no zero or surrogate cells. The rebuilt source requires these private original
data bytes but executes no original application helper.

New `--recover-locale` implies `--recover-path`. The fixture binds context+4 to
the original table `0x0042A04D`, verifies selector 1 and the relative Thumb target
`0x00100FC9`, and patches only the rebuilt fixture's relative callback word to
the compiled ARM callback. Both sides use the same hash-bound mapping. This is
a relocation and initialization fixture, not recovered bootstrap source.

Connected inputs include a bounded `r:` prefix, single-byte special mappings,
halfwidth values, and valid two-byte characters. Actual recovered measurement,
conversion, callback/map, open, read and cleanup code execute in 2,304 worker
pairs. The source compiler inlines the mapping helper into the callback; direct
mapping probes also exercise its exported entry. The recorded 25,344 connected
mapping-entry hits are original calls (the sum across both paths, with zero
rebuilt exported-entry hits due to inlining), not a count of rebuilt calls.
There are 250,368 executed callback-entry hits across both paths.

Older direct path probes intentionally retain their scripted callbacks, including
non-default ARM/Thumb targets. The inherited `locale_callbacks_modeled: true`
field describes those probes; `connected_locale_callback_modeled: false`
describes the new default-locale mode. Earlier checker options retain their
original boundaries. No source edit to the existing path loop is required.
The new builder mode, relocated fixture, optional path-fixture hooks and checker
are supporting integration work, separate from the two recovered routines.

## Controlled validation

Primary evidence: `local/validation/worker-locale-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K image is **3,452 bytes**, adding **436
compiled bytes**. All **99** new original instruction addresses were visited
(22 mapping and 77 callback), for 773 across the combined comparison. GCC is a
behavioral toolchain; this is not binary matching or a rebuilt full application.

The direct mapping corpus checks all 7,150 private cells, the complete skipped
index gap, adjacent bounds, negative/full-register extremes and wraparound.
Callback probes cover all byte values for initial state and selected lead rows
at discontinuities, every valid lead with trail boundaries, and representative
noncanonical state/full-register inputs. Wrapper probes exercise explicit and
default state, output suppression, null input, byte limits, invalid and
incomplete results. Five persistent sequences retain storage through lead,
invalid trail, successful retry and zero completion, testing that successful
retry does not clear a prior error. Counts are 7,824 mapping pairs and 3,432
callback/wrapper pairs; the older 1,353 direct path probes are also retained.

Every new direct pair checks exact return, guarded output/state, unchanged
second state word, context/error/default-state bytes, immutable input/private
data, stack restoration/guards and callee-saved registers against an independent
fixture oracle and original/rebuilt transcripts. Connected comparisons retain
the earlier allocation/I/O/open/cleanup checks and inherited direct probes.
Instruction visitation does not establish exhaustive path coverage.

Audit: `local/validation/worker-locale-20261008-audit/COMPLETE.json`.
Four compiled faults are rejected: excluding the first valid post-gap mapping,
accepting trail `0x7F`, retaining the lead after successful completion, and
omitting the yen mapping. Exact assertions and artifact hashes are in
`negative-checks.json`. The first proposed gap fault exposed only an existing
`0xFFFF` table cell and was behaviorally equivalent; its full surviving run is
retained in `equivalent-mutation.json` and is not counted as a rejected fault.
The corrected fault targets the valid `0x582 -> 0x4E9C` mapping. Final validation
was rerun after the fault correction and header-comment clarification; its
binary and complete comparison object are identical to the development run.

All three affected representative regressions preserve identical binaries and
complete comparison objects: prior path, cleanup and legacy I/O. The path mode
also runs the inherited allocation/adapter/position/read/open/cleanup direct
checks; unrelated completion/registry builders were not changed. Exact baseline
identities are in `regressions.json`. All 134 public tests pass. The final nine
commands, exit codes and timings are in `validation-final-jobs.json`; the
initial equivalent-fault run and its nonzero runner exit remain separately
recorded. `static-audit.json` verifies every final primary artifact identity,
the warning-clean build and unchanged pinned original code hash. All launched
Ghidra/build/validation jobs completed.

Run from `SMT4-decomp`, with fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-locale --output local/validation/NEW-LOCALE
python tools/check_resource_worker_io.py --recover-locale --mutant locale-reset --output local/validation/NEW-LOCALE-NEGATIVE
python tools/check_resource_worker_io.py --recover-path --output local/validation/NEW-PATH-REGRESSION
python -m unittest discover -s tests
```

This evidence requires valid mapped, nonaliasing input/output/state and private
data, with aligned halfword output and word state storage. Connected paths decode successfully; direct failures do not establish safe
worker handling of negative conversion byte counts. Backend open/close, OS
read/size, diagnostics, allocator ownership/release, raw storage/registration,
clearing and locks remain modeled or open. Prefix registry initialization and
locale initialization/configuration remain unrecovered. Live G1/G2, full ABI,
matching and provenance/transfer gates remain open or deferred; no port work.

## Next independent milestone

Follow-on: [bootstrap and selectors](resource-worker-locale-bootstrap.md) now
recover the target below in a separate mode. This report retains its original
fixture-initialization boundary.

Recover locale bootstrap ARM `0x0010236C` and the two ARM selectors
`0x00138208` / `0x0014D908`, replacing the direct context fixture with executed
initialization. Their evidenced nonempty-name dependency is ARM `0x002AA858`.
Inspect/recover that comparison contract with alignment, byte order and exact
32-bit return behavior explicit; do not assume ordinary `strcmp` return values.
The bootstrap/selector saved bodies and exports are in the preceding path audit's
`next-decoder-ghidra.txt` and `next-function-*.c`. Bootstrap is
`[0x0010236C,0x001023B8)`, selectors are `[0x00138208,0x00138248)` and
`[0x0014D908,0x0014D948)`. The GNU comparison range is
`[0x002AA858,0x002AA910)`, followed by literal `0x01010101`.

This audit's `next-bootstrap-literals.json` records selector name addresses
`0x0042A040` (`SJIS`) and `0x0042A160` (`C`), and table results `0x0042A04C` /
`0x0042A168`. `next-name-compare-disassembly.log` shows the aligned word and
unaligned byte branches. These are static continuation findings, not additional
recovered routines. Bootstrap publishes first result plus one at context+4 and
second result at context+0xC. Next compare null/empty/matching/mismatching names,
context guards and initialization-to-conversion/open with private data. Broader
configuration `0x002C6B46`/`0x002C6BAA` can remain separate unless an observed
initialization dependency requires it.
