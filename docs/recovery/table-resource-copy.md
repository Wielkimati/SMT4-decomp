# Table-resource copy and shared aligned dependency

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; no external source reused.

## Strategy review and acceptance

The previous reload manifest's source/tool and binary
hashes matched before editing; evidence is
`local/validation/table-copy-20261013-probe/prior-handoff-check.json`.
The earlier deadline-limited package really saved static findings only:
`local/validation/table-copy-20261013-static/STATIC.json` and `membership.txt`
confirm both complete ARM bodies and 63 instruction words against the reference.
Its unaligned-load question remained open; its deadline is no longer a blocker.

Acceptance declared before implementation: warning-clean source for the copy
entry and its aligned dependency, controlled original/rebuilt byte effects and
ordered access widths across alignment and loop/tail boundaries, guarded memory
and ABI checks, concrete reload integration, meaningful fault rejection and
affected regressions. Nonoverlapping ordinary memory is the new comparison
domain. File/release services and live G1/G2 remain separate boundaries.

Cross-checking the diagnostic report revealed that **the aligned dependency was
already recovered** as `smt4_diagnostic_copy`. The earlier copy handoff omitted
that fact. The final package reuses its unchanged body rather than counting or
retaining another implementation. A preliminary duplicate implementation passed
development checks but was superseded; only the shared-source evidence below is
the accepted final build. This is one new entry contract, not two.

## Source contracts and models removed

`src/table_resource_copy.c` / `.h` recover ARM **`0x002C6048..0x002C60D0`** as
`smt4_table_reload_copy(destination, source, size)`, consuming three u32 words.
Reload ignores the result, so this interface is void; it does not promise the
standard C memcpy return value. The new entry compiles to **428 bytes**.

The existing ARM **`0x002BCFAC..0x002BD020`** body moves unchanged from
`src/resource_worker_diagnostic.c` to `src/resource_aligned_copy.c`, with its
declaration in `src/resource_aligned_copy.h`. Its existing name and destination-end
return contract are retained. It still compiles to **328 bytes**. Reassembling
the old diagnostic source from the remaining file and the extracted body
reproduces the prior manifest's source hash; see the audit's
`source-extraction-check.json`. Diagnostic source includes the shared declaration.
This extraction and build wiring are reuse/integration, not new decompilation.

`tools/check_table_resource_reload.py --recover-copy` removes **one active copy
model** from equal-size reload. It links the new entry and shared aligned body;
neither is intercepted or supplied by original code on the rebuilt path.
The default checker retains its historical copy model. Load `0x002C3344` and
release `0x002C43B4` remain models in both modes. Their source already exists in
other packages; this report does not claim it executes in reload.

## Instruction-derived behavior

- Counts 0..3 use byte loads followed by byte stores. Zero accesses no payload,
  including the retained loaded-zero-size reload with null replacement source.
- For larger counts, destination residue 1/2/3 consumes a prefix of 3/2/1 bytes.
  Residue 1 orders read 0, read 1, write 0, read 2, write 1, write 2. Residue 2
  orders both reads before both writes; residue 3 uses one read/write pair.
  Size decreases by the prefix length using u32 arithmetic.
- Source alignment is checked after that prefix. An aligned source reaches the
  shared aligned copy; both pointers are now word aligned. Each 32-byte block
  loads eight words before storing any. Remaining 16-, 8- and 4-byte groups use
  the same load-before-store structure. A final halfword and/or byte is loaded
  before the final stores. Its destination-end result remains checked directly.
- The other path loads two unaligned words before storing two aligned words per
  eight-byte iteration, optionally copies four bytes, then uses the byte tail.
  The original subtract/flag loop's wrapped residual low bits are represented
  by unsigned loop tests and fragment bits. No signed-size interpretation is added.

Volatile accesses preserve payload widths/order. The unaligned load uses explicit
ARM `LDR` inline assembly with a memory clobber, avoiding an unaligned C word
lvalue or a compiler-generated sequence of byte loads. A probe executes the
original `0x002C608C` with source residues 1, 2 and 3 and distinct input bytes.
Ghidra reads four consecutive bytes in each case; its generated p-code contains
an ordinary four-byte LOAD without alignment masking/rotation. The probe also
records the two PLD p-code operations:
`local/validation/table-copy-20261013-probe/probe.txt` and `probe-retry.log`.
The initial local probe failed Java dependency resolution and produced no result;
the retry used a local copy of the existing machine base and completed.

In comparisons, the two pinned original PLD instructions are handled as cache
hints with no architectural payload access. Source omits those hints. This does
not establish live alignment-control state, cache effects, timing, fault behavior,
MMIO suitability, overlapping generic-copy behavior, huge/wrapping spans or
concurrency. Unaligned byte-effect claims are conditional on the tested execution
semantics. Explicit LDR retains the instruction rather than inventing a portable
native implementation. Earlier diagnostic overlap evidence keeps its own scope.

## Validation

Primary: `local/validation/table-copy-20261013-shared-final/COMPLETE.json`.
Audit: `local/validation/table-copy-20261013-shared-audit/COMPLETE.json`.

- Warning-clean freestanding C11 ARMv6 build: **1,680 bytes**, including the
  retained 924-byte reload/initializer unit, new 428-byte entry and reused
  328-byte aligned body. No whole-game build or binary-matching claim.
- **624 generic-copy pairs** and **35 direct aligned pairs** check independent
  byte effects and the exact read/write address, width and grouping schedule.
  Sizes: 0..9, 15..17, 23..25, 31..33, 47..49, 63..65, 95..97, 127..129,
  255..257 and 1024. The main corpus crosses all 16 pointer residue combinations.
  A second layout reverses allocation order at high-bit addresses for sizes
  3, 33, 65 and 257. Whole source/destination guards, saved registers, SP,
  ARM return mode and stack guards are checked.
- Retained **289 reload pairs**, **14 state-accessor pairs** and **10 gate pairs**
  pass with constructed registry state. Equal-size cases make **98 concrete copy
  invocations across both paths**. All existing gate/read/service/publication,
  state normalization/restoration and payload assertions remain active.
- All **115 original sites** execute: 52 retained reload/accessor sites,
  34 new generic-copy sites and 29 reused aligned-copy sites. Saved function
  membership and ARM mode are rechecked in `copy-membership.txt`; case records
  are `copy-results.tsv` and `results.tsv`. Coverage is not exhaustive predication.
- Three compiled faults are rejected by runtime assertions, with no success
  markers: wrong alignment-prefix subtraction, interleaving aligned batch reads
  and writes, and replacing the aligned halfword load with a byte. The batch
  fault preserves disjoint final bytes, so access-order checks are material.
  Exact diagnostics are in the audit's `negative-checks.json`.
- The retained default reload **924-byte binary and entire comparison object
  are identical** to `table-reload-20261013-final`.
- The affected diagnostic-wait regression passes **3,170 pairs**, retaining its
  existing 140 aligned-copy cases including overlap. Its complete comparison,
  diagnostic and diagnostic-wait objects match `diagnostic-wait-20261011-final-checked`.
  The current **6,136-byte binary differs** from that older 6,104-byte build;
  no diagnostic binary-stability claim is made. Evidence:
  `local/validation/table-copy-20261013-diagnostic-regression/COMPLETE.json`.
- All **134 public tests** pass. Audit records hashes, syntax, JSON, source
  extraction identity and whitespace checks separately from behavior evidence.

```powershell
python tools/check_table_resource_reload.py --recover-copy --output local/validation/NEW-COPY
python tools/check_table_resource_reload.py --recover-copy --mutant copy-group --output local/validation/NEW-COPY-NEGATIVE
python tools/check_table_resource_reload.py --output local/validation/NEW-RETAINED-RELOAD
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --output local/validation/NEW-DIAGNOSTIC-REGRESSION
python -m unittest discover -s tests
```

All Ghidra jobs ran sequentially and read-only. No commit, live session or detached job was started.

## Next independent source milestone

Recover the still-modeled **path-prefix predicate `0x002B0674`** consumed by
synchronous orchestration `0x002C5E90` and asynchronous orchestration
`0x002AE72C`. Confirm the complete body and exact scan/return semantics first;
`resource-sync.md` records the eight-character colon-scan lead, not recovered
source. Replace `smt4_resource_path_has_prefix` declared in `src/resource_sync.h`
with source and add explicit concrete-prefix modes to the existing sync/request
checkers. Batch direct termination/boundary cases with both caller integrations;
retain mode-byte short-circuit checks and formatting/descriptor/service models.
Read `resource-sync.md`, `resource-request.md`, `tools/check_resource_sync.py`
and `tools/check_resource_request.py`. Do not claim formatting recovered.

This selects another evidenced source model shared by two callers. It does not
pretend the predicate blocks reload: reload sets the mode byte to one and the
synchronous caller consequently skips this predicate. Reload's load/release
integration, actual allocation lifetime, live I/O/full startup, G1/G2 and live
alignment-control evidence remain open independently.
