# Worker path byte conversion and runtime accessors

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project descriptions below are not original symbol names. This package follows
[file cleanup](resource-worker-file-cleanup.md) under A07; it does not repeat the
completed allocator or cleanup milestones.

## Selected contract and acceptance

Recover the worker's initial-state predicate, measurement wrapper, conversion
loop and byte decoder, plus their evidenced fixed context/state/error accessors.
Acceptance requires instruction-backed source, a warning-clean ARM build,
original/rebuilt/oracle agreement on byte counts, output, state and errors,
connected conversion-to-open execution, meaningful fault rejection and retained
older-mode results. Locale initialization and callback implementation remain
explicit dependencies; no synthetic fixture identifies the game's encoding.

The preceding handoff's 29 primary artifact identities were checked before edits
in `local/validation/worker-path-20261008-audit/handoff-check.json`. New inspection
of `0x002C6C48` established a fixed context return, allowing that dependency and
the other accessors to be included without speculative adjacent recovery.
Starting instructions and decompilation remain in the preceding cleanup audit;
the new audit records the additional context/accessor inspection.

## Recovered behavior

`src/resource_worker_path.c` and its header implement eight original contracts:

| Original address / mode | Contract |
| --- | --- |
| `0x002B9486` Thumb | Return 1 for null state or zero first state word, otherwise 0; no writes |
| `0x002B9468` Thumb | Measure with null output; select default state slot 4 only if explicit state is absent |
| `0x002C63DC` Thumb | Consume bytes until one code unit completes, input is invalid, or the supplied byte limit is exhausted |
| `0x001008C8` Thumb | Decode one byte through the locale table or its relative callback |
| `0x002C6936` Thumb | Ignore first argument; return `0x004EFCE4 + 8 * slot` with 32-bit wrapping arithmetic |
| `0x002C6894` ARM | Return the error-word address `0x004EFCE0` |
| `0x002C6C48` ARM | Return context address `0x004EFCA0` |
| `0x002C6C94` ARM | Return context plus four, containing the locale-table pointer |

The historical `smt4_worker_path_reset` name was incorrect. The worker still
initializes both state words itself and ignores the predicate's result; it now
calls `smt4_worker_path_is_initial`. All three builders that consume the caller
use the corrected symbol and record the shared header. Those interface changes
are integration work, not additional recovered routines.

The conversion loop selects default slot 5 if its state argument is null. A null
input pointer forces a single zero input byte and disables output, regardless
of the supplied limit. An ordinary zero limit consumes no bytes and returns
`0xFFFFFFFE` (incomplete). The decoder sees each byte zero-extended to a word.
Each `0xFFFFFFFE` callback result continues, retaining callback state changes.
Result `0xFFFFFFFF` stops, stores **4** through the error accessor, preserves
caller output, and returns invalid. Every other decoder result is completion,
including zero and large positive values. Completion publishes the callback's
16-bit unit when output is nonnull, returning zero for unit zero or the number
of bytes consumed for a nonzero unit. Measurement performs the same decoding
and state changes; it is not a read-only lookahead.

The byte decoder loads the table pointer from context+4. Only selector byte
`table[0x101] == 1` dispatches the callback. Other selector values use a byte
acceptance table: a nonzero entry writes the byte as a 16-bit unit and returns
1; a zero entry returns invalid without writing output or error storage. The
callback target is `table + 0x103 + little_endian_word(table + 0x103)`, including
its ARM/Thumb bit. Reconstructed C reads the packed word as bytes to avoid C
alignment undefined behavior. The decoder forwards state unchanged, including
null; only the outer conversion wrappers select default states.

## Validation boundary

The optional `--recover-path` mode implies cleanup/open/read/position/method and
allocation recovery. Connected worker fixtures use actual bounded, terminated
byte paths and a synthetic acceptance table. They execute the predicate,
measurement, byte loop, decoder and context accessors through open and cleanup.
They replace all three connected path-call models in this mode. Backend open
and close, resource release, OS read/size, diagnostics, raw allocation,
registration, clearing and locks retain their documented models.

Direct probes cover all 256 byte values, accepted/rejected table entries,
selectors 0/2/255, all four table-address residues, explicit/default state,
null input/output, zero/ordinary/high-bit/all-ones state words and byte limits,
and modular state-slot arithmetic. Scripted ARM and Thumb callbacks check
byte/state/output arguments, output units including zero and surrogate values,
state changes on completion/invalid/incomplete results, multiple incomplete
bytes, and preservation of caller output on errors/exhaustion. The callbacks
write their local output even for failure, checking that the loop does not
publish it. Nonnegative callback results are not assumed to equal byte counts.

Each direct pair checks exact return, guarded output, complete explicit/default
state and error/context storage, input/table immutability, stack restoration,
callee-saved registers and dependency transcripts. Callback models clobber
volatile registers and condition flags and preserve the actual return mode.
Older comparison modes keep their historical synthetic path models and counts;
new direct recovery does not broaden those evidence boundaries.

The comparison uses valid mapped storage, valid callback targets, and callbacks
that initialize the output unit on completion. It does not establish arbitrary
aliasing, unsupported memory, concurrency, actual locale initialization, a
character encoding, or real multibyte callback behavior. Packed loads are
instruction-emulator evidence, not a new hardware/live alignment claim.
Connected worker cases use successful table decoding; direct invalid/incomplete
comparisons do **not** establish safe worker handling of negative byte counts.
The original worker's nonzero checks and pointer arithmetic remain unchanged.

The first development run completed all 2,304 connected cases, then exposed an
incorrect null-state assumption in the callback fixture: the direct byte decoder
forwards null. The fixture was corrected without changing recovered C, and direct
checks now run before connected comparisons to expose such failures sooner.

## Commands and results

Run from `SMT4-decomp`, with fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-path --output local/validation/NEW-PATH
python tools/check_resource_worker_io.py --recover-path --mutant path-slot --output local/validation/NEW-PATH-NEGATIVE
python tools/check_resource_worker_io.py --recover-file-cleanup --output local/validation/NEW-CLEANUP-REGRESSION
python -m unittest discover -s tests
```

Primary evidence: `local/validation/worker-path-20261008-dev2/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K build is **3,016 bytes**, adding
**492 compiled source bytes** across eight contracts. The reconstructed path
executes no original application helper; GCC remains a behavioral comparison
toolchain, not an original-compiler or matching claim.

| Evidence | Result |
| --- | ---: |
| Connected original/rebuilt/oracle worker cases | 2,304 |
| Direct path/accessor pairs | 1,353 |
| Executed connected path calls, both paths | 204,288 |
| Scripted locale callback calls, both paths | 608 |
| New original instruction addresses visited | 118 / 118 |
| Total original instruction addresses visited | 674 |
| Maximum instructions per direct path invocation | 160 |
| New compiled source bytes | 492 |

The inherited direct allocation, adapter, position, read, open and cleanup
comparisons also pass, including their existing persistent/diagnostic probes.
State-slot/error accessors are exercised by direct conversion/accessor probes;
the successful connected byte-table domain does not reach error/default-state
branches. Instruction visitation is not exhaustive path coverage.

Audit: `local/validation/worker-path-20261008-audit/COMPLETE.json`. All six compiled
faults are rejected: wrong state word and ignored byte limit at exact-result
assertions, wrong error value at guarded context/error bytes, wrong measurement
slot at callback ABI, callback status substituted for byte count at exact result,
and broadened locale selector at unexpected callback dispatch. Exact source/
binary identities and messages are in `negative-checks.json`.

All **nine affected regressions retain identical binaries and complete comparison
objects**: cleanup/open/read/position/method/allocation/legacy I/O modes, the
completion chain and the default registry chain. `regressions.json` records
the exact baselines and verifies binary files against their manifests. The
registry baseline is the newer `heap-retained-20261007-default-regression`:
the original registry-final record predates five added zero/false observation
fields. No fields were dropped to obtain equality. All **134 public tests pass**;
`validation-jobs.json` records the 16 successful fault/regression/public commands,
exit codes and timings, and `public-tests.log` retains the actual unittest output.
The primary build's 32 artifact identities are verified in `static-audit.json`.
No started Ghidra/build/validation job remains running.

## Subsequent default-locale recovery

The [locale package](resource-worker-locale.md) now recovers `0x00100FC8` and
`0x00100F9C` in optional `--recover-locale`, with private hash-bound tables.
This report's earlier path-only/scripted-callback evidence remains unchanged.

## Next independent milestone

Recover the selected default locale's **Thumb byte callback `0x00100FC8` and
mapping helper `0x00100F9C`**, replacing the scripted callback boundary in a new
connected mode. This is supported by bootstrap `0x0010236C`: it calls selector
`0x00138208` with null arguments, then publishes the returned pointer plus one
at context+4. The selector's null-name branch returns `0x0042A04C`, yielding
table `0x0042A04D`. Its selector byte is 1 and its relative callback resolves to
`0x00100FC9`, including the Thumb bit. Both original image and mapped Ghidra
memory confirm this binding. The other bootstrap selector is `0x0014D908`.

Static continuation evidence is in the audit's `next-locale-references.txt`,
`next-locale-literals.json`, `next-decoder-ghidra.txt`, `next-function-*.c`,
`next-byte-callback-disassembly.log` and `next-code-map-disassembly.log`.
**Neither target currently has a saved Ghidra function object.** The GNU-decoded
Thumb bodies are `[0x00100FC8,0x00101064)` and `[0x00100F9C,0x00100FC8)`;
their shared literal pool follows. Establish those boundaries/modes before
using decompiler output. Exported pseudocode covers the bootstrap/selectors,
not these absent function objects. These are static findings, not additional
source recovery.

The mapping helper reads 7,150 halfwords starting at `0x0041CAA0` after its
index checks/adjustment. The 14,300-byte private region has SHA-256
`49c21ead0aaa288dd04a9eaaf0e424dd2fd49300602a6a0ec7ca30df4392bcae`.
Keep those mapping bytes local and hash-bound. Next compare lead/trail and
single-byte boundaries, special output values, incomplete/resumed state,
invalid preservation, and rejected/gapped mapping indices, then connect
measurement/conversion/open using the actual locale data. Fixture binding of
the table is distinct from recovered bootstrap/configuration; do not claim a
runtime initialization path from the binding alone. Broader locale configuration
at `0x002C6B46`/`0x002C6BAA` is not needed before this bounded decoder recovery.

Live G1/G2 evidence, compiler/full ABI, binary matching, provenance/transfer
gates and PC-port implementation remain open or deferred.
