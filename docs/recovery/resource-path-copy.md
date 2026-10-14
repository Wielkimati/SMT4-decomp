# Descriptor path copy and concrete constructor strings

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; no external implementation reused.

## Strategic review and acceptance

Both preceding prefix manifests'
source/tool and binary hashes match the workspace at session start:
`local/validation/path-copy-20261013-inspect/prior-handoff-check.json`.
The target removes an active constructor dependency and advances A07's continuing
source recovery. Optional extraction, compiler research and deferred G1/G2 live
work are not prerequisites. No reprioritization was needed.

Acceptance declared before implementation: recover ARM `0x002BF8C0` with exact
NUL-inclusive writes, alignment-dependent read/write widths and order, destination
return and guards; reuse full-length source `0x002C32E4`; execute both inside
constructor `0x002B0494` and the existing synchronous chain. Require warning-clean
ARM builds, controlled original/rebuilt comparisons, caller state/order checks,
compiled fault rejection and retained regressions. Allocation, synchronization,
formatting and kernel behavior remain explicit models.

## Recovered source and model removal

`src/resource_path_copy.c` recovers **one new entry contract**:
`char *smt4_file_path_copy(char *destination, const char *source)` at ARM
**`0x002BF8C0..0x002BF924`**, exclusive end. It compiles to **168 bytes**.

- If both pointers are four-byte aligned, read one source word. If every byte is
  nonzero, write one destination word and repeat. For the first word containing
  zero, write its little-endian bytes individually through the first NUL.
- Otherwise read and write one byte at a time through the first NUL. This branch
  never switches to word accesses, even if advancing pointers become aligned.
- Return the original destination. There are no pointer, capacity or overlap
  checks. The aligned branch reads through the end of the word containing NUL,
  but never writes beyond NUL.

Volatile accesses and an aligned may-alias word type preserve the original
payload access sequence in the comparison compiler. The C lane checks replace
UQSUB8 zero detection without changing reads or stores. No libc implementation
or native replacement is used.

Full length **`0x002C32E4..0x002C3340`** already exists as
`smt4_worker_service_name_length` in `src/resource_worker_service_acquire.c`.
It is reused unchanged via the comparison link alias `smt4_file_path_length`;
it is **not another recovered contract**. Function-section collection discards
unrelated acquisition/name-copy code. The source's 108-byte length body first
reads bytes to alignment, then words through the first NUL-containing word.

Saved Ghidra function membership agrees with both exact ranges. The read-only
inspection under `local/validation/path-copy-20261013-inspect/exports/` records
membership, instructions, references and private pseudocode. Each concrete
checker also reasserts membership and saves independent GNU disassembly.

New `--recover-strings` modes in `check_resource_create.py` and
`check_resource_chain.py` remove both copy and length models. They check the same
call-entry snapshots and arguments, then execute the selected original or
rebuilt instructions through their real return. No model writes copy output;
the original side runs original instructions and the rebuilt side runs source.
Existing constructor source is unchanged. Default modes retain their historical
string models and comparison boundaries.

The shared Java helper and builder changes support this source contract; they
are not additional recovered game code. `resource_create.h` documents the copy
contract; the original 32-bit layout and signatures are retained.

## Comparison domain and limitations

The constructor unit includes **352 direct copy pairs** and **88 direct length
pairs**, covering all 16 source/destination alignment combinations for copy,
all four length alignments, lengths 0..17/31/63/127/255, all NUL lanes, word-loop
boundaries and deterministic nonzero bytes including high-bit values. Source and
destination begin with dirty guards; every final byte and the exact return are
checked. `string-results.tsv` records dimensions and interleaved access traces.

An independent byte oracle specifies every source read and destination write,
including width and relative order. Only stack accesses below the call-entry SP
and the two original address literals are exempt. This checks byte and word
paths, trailing word reads, first-zero termination, and NUL writes even when the
constructor's destination was already zeroed. SP, r4-r11, permitted instruction
regions and initialized reads are checked. Direct copy reaches 255 bytes;
constructor fixtures also include 255-byte prefixed paths. Chain strings remain
within their existing 256-byte scratch and descriptor path buffers.

The original copy's UQSUB8 at `0x002BF8DC` is supported by unsigned saturated
subtraction independently per byte after asserting opcode `0xE66CEFF3`.
Reused length uses the existing algorithm at `0x002C330C`, opcode `0xE6621FF1`.
These are host instruction implementations, not routine-return models or live
hardware evidence. All other original instructions execute in Ghidra normally.

Caller comparisons retain all constructor/list modes, handle/error results,
release rereads, descriptor snapshots, state changes, guarded bytes and external
store multiplicities. Chain comparisons retain synchronous/wrapper selection,
configuration, wait polling, scheduled completion, cleanup and bounded pending
prefixes. Their outer instruction counters exclude the nested string execution;
`max_string_steps` separately bounds each concrete string call.

This is stable, disjoint, valid NUL-terminated ordinary RAM with enough readable
trailing word bytes. Overlap, invalid pointers, missing terminators, huge/wrapping
lengths, concurrency, faults, MMIO, timing and live behavior are unverified.
Allocation, clear, synchronization, result handling and formatting remain
models; chain also models its outer prefix predicate, signal and sleep.
Already recovered code in other modes does not silently change this boundary.
There is no actual file I/O, allocation lifetime, complete startup, binary
matching, reconstructed 3DS application or native-port claim. G1/G2 stay open.

## Validation

Primary evidence:

- `local/validation/path-copy-20261013-create-accepted/COMPLETE.json`
- `local/validation/path-copy-20261013-chain-accepted/COMPLETE.json`
- `local/validation/path-copy-20261013-audit/COMPLETE.json`

Both freestanding ARMv6 C11 builds pass `-Wall -Wextra -Werror`.

| Comparison | Constructor unit | Connected chain |
| --- | ---: | ---: |
| Compiled image bytes | 664 | 1,144 |
| Direct copy / reused length pairs | 352 / 88 | Covered by constructor unit |
| Retained caller pairs | 10,080 | 3,888, including 229 pending |
| Original sites visited, entire unit | 151 | 250 |
| Original copy / length sites | 25 / 23 | 16 / 19 (aligned callers) |
| Copy calls, both machines, including direct | 15,344 | 4,320 |
| Length calls, both machines, including direct | 20,336 | 7,776 |
| Host UQSUB8 instruction executions | 166,301 | 72,144 |
| Maximum instructions per string call | 2,306 | 2,306 |

Site coverage includes predicated instructions; this is bounded comparison,
not exhaustive proof over all inputs. The integration runs check each string
trace against the independent oracle; the direct corpus additionally compares
original/rebuilt traces explicitly.

Three compiled faults are rejected: omitting NUL writes (`String incomplete
access trace`), forcing byte copying on aligned pointers (`String access
width/order`), and returning destination plus one (`String exact return`).
`negative-checks.json` and `jobs.json` in the audit directory identify the exact
commands, exits and assertions. All three compiled successfully and no negative
run produced a success marker.

Both retained default checkers pass. Their entire comparison objects and binaries
are identical to `create-20261006` (388 bytes) and `chain-20261006-final`
(868 bytes). The latter's 3,888 pairs include 229 bounded pending prefixes,
not 229 additional cases. Evidence is in
`local/validation/path-copy-20261013-{create,chain}-retained/COMPLETE.json` and
audit `retained-checks.json`. All **134 public tests pass** in `public-tests.log`.
Final manifest source/tool and binary hashes, unchanged reused source/header,
Python syntax, symbol JSON and changed-file whitespace are checked in
`close-check.json` and `reused-source-check.json`.

Development `create-dev1` passed before stricter payload access guards were
added. `chain-dev1` passed behavioral comparisons but its Python marker was
withheld because the predicted added-site count was 33 rather than 35. The
aligned path actually visits 16 copy and 19 length sites; the final checker
explicitly requires those sites. No behavior mismatch was waived. The accepted
runs above validate the final source/tools. All started commands finished;
Ghidra jobs ran sequentially and read-only. No commits were made.

## Reproduction

Run from `SMT4-decomp` with fresh ignored output directories. Ghidra jobs must
remain sequential on the saved authoritative project:

```powershell
python tools/check_resource_create.py --recover-strings --output local/validation/NEW-STRINGS-CREATE
python tools/check_resource_chain.py --recover-strings --output local/validation/NEW-STRINGS-CHAIN
python tools/check_resource_create.py --recover-strings --mutant copy-nul --output local/validation/NEW-STRINGS-NEGATIVE
python tools/check_resource_create.py --output local/validation/NEW-CREATE-RETAINED
python tools/check_resource_chain.py --output local/validation/NEW-CHAIN-RETAINED
python -m unittest discover -s tests
```

The other fault choices are `copy-alignment` and `copy-return`. Mutated source
stays local. Rejection requires successful compilation, the intended comparison
assertion, a failing driver and no `COMPLETE.json`.

## Next independent source milestone

Recover the constructor's synchronization/result boundary as one related package:
ARM acquire wrapper **`0x002C4350..0x002C4374`**, release wrapper
**`0x002C54A4..0x002C54BC`**, and result dispatcher
**`0x002C54BC..0x002C5524`** (exclusive ends; confirm saved memberships).
They remain active `smt4_file_acquire`, `smt4_file_release` and
`smt4_file_check_result` models in `src/resource_create.c` and both checkers.
GNU evidence is already in the accepted constructor's
`original-002c4350-disassembly.log` and `original-002c54a4-disassembly.log`.

The wrappers marshal SVC `0x25`/`0x16` and unconditionally publish returned r1.
The result dispatcher reads byte `0x1FF80014` and signed byte `0x0044E7A8`,
classifies signed high result bits, and may call/tail-call diagnostic
`0x001284A8` or the already recovered break entry `0x002BCE9C`. Read
`resource-create.md` and `resource-break.md`; preserve caller-address and r2
transport explicitly. Keep kernel results, the diagnostic body and any returning
break policy modeled unless evidence justifies reusing existing break source.
Batch direct result-class/flag cases with constructor/chain synchronization
integration; test output publication on failure, timeout/register marshalling,
callee-saved registers, release handle rereads, ordered diagnostic branches and
remaining models. This is a source milestone, not a live OS or formatting task.
