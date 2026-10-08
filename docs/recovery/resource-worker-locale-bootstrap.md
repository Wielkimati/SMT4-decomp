# Worker locale bootstrap, selectors and name comparison

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project names describe observed contracts, not original symbols.

## Selection and acceptance

The original allocator
objective is complete; optional extraction/compiler work, live gameplay and port
implementation remain outside this package. Before edits, 34 prior source/tool
identities and the prior compiled image were verified in
`local/validation/worker-bootstrap-20261008-audit/handoff-check.json`.

Acceptance: instruction-backed bootstrap, selector and exact name-comparison
contracts; warning-clean ARM build; direct name/alignment/termination and guarded
context-store comparisons; executed bootstrap before connected conversion/open;
meaningful compiled-fault rejection; retained affected older modes and public
checks. Bootstrap is distinct from broader locale configuration.

## Recovered contracts

`src/resource_worker_locale_bootstrap.c` and `.h` contain four ARM contracts:

| Original body (end exclusive) | Source contract |
| --- | --- |
| `[0x0010236C,0x001023B8)` | `smt4_worker_locale_bootstrap` |
| `[0x00138208,0x00138248)` | `smt4_worker_locale_select_bytes` |
| `[0x0014D908,0x0014D948)` | `smt4_worker_locale_select_other` |
| `[0x002AA858,0x002AA910)` | `smt4_worker_locale_name_compare` |

The selectors ignore r0, accept a name in r1, and return their fixed data address
for null, empty, or matching names. Every other name returns zero. The comparison
is case-sensitive and uses unsigned bytes. The byte selector compares `SJIS` at
`0x0042A040`, returning `0x0042A04C`; the other compares `C` at `0x0042A160`,
returning `0x0042A168`. These names and table bytes stay in the private reference;
the build resolves their addresses without copying game data into tracked source.

Bootstrap calls the recovered context accessor `0x002C6C48`, then selects both
defaults with null names. It writes the first result plus one to context+4,
then the second result to context+0xC. Other context, error and state bytes are
preserved. Its interface is void; incidental return-register contents are not
claimed. The disassembly's preliminary r0/r1 assignments have no observable
effect through the recovered fixed context accessor.

Name comparison has an alignment-sensitive exact result. If either pointer is
unaligned, the first unequal pair or first zero left byte returns unsigned-left
minus unsigned-right, modulo 32 bits. If both are word-aligned, each entire
four-byte word pair is loaded before testing its bytes. Equal nonzero words
continue; the first differing byte determines the result, and an equal zero
terminates successfully regardless of following bytes. For differing bytes
`x=left` and `y=right`, the exact result is
`(((y-x) << 24) >> 1) | (y>x ? 0x80000000 : 0)` using unsigned 32-bit arithmetic.
This preserves the original shifted SUBS and RRX carry, rather than substituting
ordinary strcmp magnitudes. For example, aligned `A` versus `B` returns
`0x80800000`, while unaligned inputs return `0xFFFFFFFF`.

Reconstructed aligned reads use explicit volatile byte loads to assemble each
little-endian word without host alignment or aliasing assumptions. This is a
single-threaded, mapped-memory contract; no atomicity or concurrent modification
claim is made. Original disassembly and the Ghidra instruction listing are retained
with the validation evidence.

## Integration and limits

New `--recover-locale-bootstrap` implies `--recover-locale`. Its connected fixture
poisons both locale slots, executes original/rebuilt bootstrap, and checks the
two stores and all surrounding context bytes before the worker begins. The
original relative Thumb callback word is relocated to the rebuilt ARM callback
in the private table as in the earlier locale mode. That data relocation remains
a fixture; context publication now executes recovered code. GCC inlines the
constant default selector paths, while separate direct probes execute both
exported selector contracts.

Earlier direct path probes retain scripted callbacks and earlier direct locale
probes retain their initialization fixtures. Older options keep their historical
boundaries. Inherited metadata describing those probes does not claim bootstrap
was recovered in the older modes. Builder and comparison changes support these
four source contracts; they are not additional recovered game code.

Inputs must be mapped, NUL-terminated byte strings. Aligned strings require the
whole terminating/differing word to be readable. The compared domain excludes
concurrent mutation, invalid pointers, arbitrary aliasing and live gameplay.
Connected paths decode successfully; direct error tests do not establish safe
worker handling of negative conversion lengths. Broader locale configuration,
backend open/close, OS size/read, diagnostics, allocator ownership/release,
raw storage/registration, clearing, locks and prefix initialization remain open
or modeled. G1/G2 live checks, full ABI, matching and provenance/transfer gates
remain open or deferred. No port implementation was changed.

## Validation

Primary evidence: `local/validation/worker-bootstrap-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K image is **3,844 bytes**, adding **392
compiled bytes** (comparison 212, each selector 72, bootstrap 36, including their
literal pools). All **97** new original instruction addresses were visited: 19
bootstrap, 16 per selector and 46 comparison instructions, for 870 in the combined
comparison. GCC is the behavioral toolchain, not an identified matching compiler.

Direct checks include 5,728 name-comparison pairs: every alignment combination,
equality/termination and unequal bytes at positions 0 through 17, high-bit and
wraparound differences, zero/one borrow-mask patterns, and every byte value
against representative boundaries. Each comparison verifies exact r0 and the
set of bytes read, including the entire final aligned word and absence of reads
past the required word/byte. Selector checks cover 384 combinations of null,
empty, exact, prefix-only, extended, case-changed and high-byte names, all name
alignments and ignored-r0 extremes. Three initial-slot patterns run bootstrap
twice on the same storage on each side, checking ordered writes and idempotence.

The 2,304 connected worker pairs execute bootstrap 4,608 times across original
and rebuilt paths, starting from poisoned slots. All inherited locale, path,
cleanup, open, read, position, method and allocation direct probes remain active.
Guarded context/error/state, names/private data, output, stack and callee-saved
registers are checked. Visited instructions do not establish exhaustive branch
or live coverage.

The first development run passed new direct checks but failed at the connected
fixture's register snapshot: Ghidra exposes registers 13/14 as `sp`/`lr`, not
`r13`/`r14`. That harness-only defect was corrected. The second development run
passed the complete corpus. The final run adds read-footprint and repeated-state
checks and clarifies the effective initialization metadata. The source image is
unchanged from the successful development run.

Audit: `local/validation/worker-bootstrap-20261008-audit/COMPLETE.json`.
Three compiled faults are rejected: writing the second table to context+8
instead of +0xC (forbidden store), comparing an empty byte-locale name instead
of accepting it (wrong zero return), and shifting the aligned difference by two
instead of one (wrong exact r0). Their source/binary hashes and exact assertion
failures are in `negative-checks.json`. Retained locale, path and legacy I/O
regressions have identical binaries and complete comparison objects to their
accepted baselines, as recorded in `regressions.json`. All 134 public tests pass.
Final artifact hashes and the unchanged original executable identity pass the
static audit. All launched build, Ghidra, validation and test jobs finished.
The runner records every final command, exit status and elapsed time in
`validation-jobs.json`; the two development runs remain separately preserved.

Run from `SMT4-decomp` with fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-locale-bootstrap --output local/validation/NEW-BOOTSTRAP
python tools/check_resource_worker_io.py --recover-locale-bootstrap --mutant bootstrap-compare --output local/validation/NEW-BOOTSTRAP-NEGATIVE
python tools/check_resource_worker_io.py --recover-locale --output local/validation/NEW-LOCALE-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Follow-up: the three category contracts below now have source and controlled
comparison evidence in [configuration recovery](resource-worker-locale-config.md).
The findings below retain this bootstrap package's original selection evidence.

Inspect/recover locale category configuration at Thumb `0x002C6B46` and
`0x002C6BAA`, with the required query/serialization dependency `0x002C6AA8`.
This is separate from default bootstrap. Static continuation evidence is retained
in this package's audit: `next-config-ghidra.txt`, the three `next-function-*.c`
exports, and `next-config-disassembly.log`. Saved bodies end at `0x002C6B46`,
`0x002C6BAA` and `0x002C6C3E`, respectively for query, dispatch and ordinary-name
configuration. The only observed executable dependencies are the now-recovered
context accessor and selectors. These are static findings, not recovered source.

The dispatcher rejects category masks zero or at least 32; null names query,
ordinary names configure, and a leading `*` restores five encoded words before
querying. It consumes exactly eight bytes per word with unchecked byte arithmetic.
The ordinary setter visits categories in order 2, 1, 4, 8, 16 and can leave earlier
writes visible if a later selector fails. Query serializes all five context words
for a multi-bit mask, while singleton queries resolve names from masked pointers
and relative words; zero pointers return the private `C` literal at `0x002C6C40`.

Next acceptance should include these ordering/partial-failure and exact encoded
byte rules, guarded output and context, mask and pointer-low-bit boundaries,
configuration/query round trips and configuration-to-conversion/open. Inspect
original instructions rather than trusting the exported setter's misleading void
prototype. Use valid mapped name pointers where singleton query dereferences;
do not turn the original unchecked restoration into a validating host parser.
