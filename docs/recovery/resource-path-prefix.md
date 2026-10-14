# Resource path-prefix predicate and loader integration

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; no external source reused.

## Strategy review and acceptance

The copy manifest's source/tool hashes and binary
were checked against the workspace; the record is
`local/validation/path-prefix-20261013-audit/prior-handoff-check.json`.
This package advances A07's continuing original-source recovery by removing
one shared predicate model from two callers. It neither repeats reload-copy
nor treats optional extraction or the deferred live gates as prerequisites.

Acceptance declared before implementation: faithful source and warning-clean
ARM build, original/rebuilt exact returns and termination/read boundaries,
synchronous `0x002C5E90` and asynchronous `0x002AE72C` caller integration,
mode-byte short-circuit checks, meaningful compiled fault rejection and retained
regressions. Formatting, descriptors and service models stay explicit.

Inspection corrected the abbreviated historical scan description: the predicate
first calls **full string length `0x002C32E4`**. That routine already exists in
`src/resource_worker_service_acquire.c`; it is reused unchanged, not counted as
new recovery. Its prior source/header hashes agree in `reused-source-check.json`
under the audit directory. No additional callee recovery was necessary.

## Source contract and model removal

`src/resource_path_prefix.c` implements `smt4_resource_path_has_prefix(uint32_t)`
at ARM **`0x002B0674..0x002B0700`**, exclusive end. Its declaration moves out of
the unrecovered-boundary section of `src/resource_sync.h`. This is **one new
source contract**, compiling to **72 bytes** with the pinned compiler.

1. Call the existing full-length routine before reading any colon. Its source
   preserves byte reads until aligned, then aligned four-byte reads through the
   word containing the first NUL. Mapped bytes after the terminator may be read.
2. Compare the returned length as signed. Values greater than eight select eight;
   zero and high-bit-set results select no scan and return zero.
3. Read at most the selected number of bytes in increasing address order. Return
   exactly one at the first colon, otherwise zero. The original odd-byte prefix
   and two-byte loop have the same ordered byte accesses as the recovered loop.
   Colon at offset seven qualifies; offset eight does not. No URI syntax checks
   or path rewriting occur here.

The reused length body is ARM **`0x002C32E4..0x002C3340`**, with its literal at
`0x002C3340`; it compiles to **108 bytes**. Both original function memberships
are checked in the saved project. GNU disassembly for both original ranges and
the rebuilt unit is retained in each concrete comparison directory. Original
listing/pseudocode leads remain in `local/analysis/sync-20261006/exports/`.

`--recover-prefix` in both existing checkers executes the predicate and length
source. It removes the prefix interception in each caller; length was previously
hidden inside that model. The rebuilt path executes no original instructions.
The length translation unit is linked with function sections and garbage
collection, retaining the existing harness entry points explicitly. Unrelated
service acquisition/copy bodies are discarded, not newly validated or modeled.
Source reuse, checker changes and symbol metadata are supporting integration.

Default modes retain their older predicate models and evidence boundaries.
Synchronous clearing, formatting, descriptor construction and wait are modeled.
Asynchronous clearing, formatting, packet allocation, descriptor construction,
user callback and release are modeled. Existing descriptor helpers, callback
constructor and completion source still execute as in the older request mode.

## Validation domain and instruction support

The same 440 direct predicate pairs run in each concrete unit. Fixtures cover
all four input alignments; lengths 0..10, 15, 31, 63 and 247; colons at every
applicable offset 0..9 and absent; non-ASCII bytes; and a colon immediately after
NUL. Every source read is checked against an independent byte oracle and an
expected address/width/order trace, including the complete length pass before
the colon pass. `prefix-results.tsv` records fixture dimensions and exact traces.
Input preservation, allowed stores, initialized reads, PC ranges, instruction
budget, SP and r4-r11 preservation are checked.

The synchronous corpus retains its flags, state, ownership, output, wrapper and
parameter cases. In concrete mode its three synthetic predicate returns become
actual paths with a colon at offset eight, seven or zero. The asynchronous
corpus retains six actual paths, including empty and 250-byte strings. Both
checkers retain mode bytes 0/1/255. Nonzero modes must neither enter the predicate
nor read path bytes through it. Each concrete predicate return is checked before
formatting. Existing call ordering, descriptor/packet writes and guards remain
checked; formatting itself still supplies a modeled output.

Ghidra's undefined UQSUB8 userop needs the same bounded instruction support used
by the [service acquisition package](resource-worker-service-acquire.md).
Only original PC `0x002C330C`, after asserting opcode `0xE6621FF1`, is handled:
independent unsigned saturated subtraction per byte computes r1 from r2/r1.
No routine return is intercepted. The original scan and all other instructions
execute normally; rebuilt source uses ordinary shifts and comparisons.
This support is not hardware evidence. Its execution count is explicit in
`prefix-comparison.json`. All 35 new predicate and 23 reused length sites execute.

Stable, disjoint, NUL-terminated ordinary RAM with sufficient mapped trailing
word bytes is the compared domain. Direct paths reach 247 bytes and integrated
paths 250. The source's high-bit length guard is instruction-derived; genuinely
multi-gigabyte strings and address wrap were not executed. Invalid pointers,
unterminated strings, concurrent mutation, MMIO, faults, timing, format directives
and live gameplay remain unverified. Clearing, allocation lifetime, file I/O and
full startup are not established by these comparisons. G1/G2 remain open.

## Accepted evidence and regressions

Primary evidence:

- `local/validation/path-prefix-20261013-sync-accepted/COMPLETE.json`
- `local/validation/path-prefix-20261013-request-accepted/COMPLETE.json`
- `local/validation/path-prefix-20261013-audit/COMPLETE.json`

Both freestanding ARMv6 C11 builds pass `-Wall -Wextra -Werror`.

| Comparison | Sync unit | Request unit |
| --- | ---: | ---: |
| Compiled image bytes | 540 | 744 |
| Direct prefix pairs (same corpus in each build) | 440 | 440 |
| Existing orchestration pairs | 2,520 | 2,016 |
| Existing direct helper / callback-constructor pairs | 768 | 48 |
| Existing completion pairs | N/A | 1,728 |
| Integrated predicate invocations, both machines combined | 1,680 | 1,344 |
| Original instruction sites visited | 150 | 197 |
| UQSUB8 host instruction executions | 6,426 | 13,202 |
| Maximum executed instructions per call | 2,292 | 2,399 |

Three compiled faults are rejected: ninth-byte scanning (`Prefix read
boundary/order`), returning all ones instead of one (`Prefix exact result`),
and looking for a leading colon before computing length (`Prefix read
boundary/order`). All lack success markers. `negative-checks.json` and
`jobs.json` in the audit directory record exact assertions, commands and exits.

The retained default synchronous, request and connected-chain checkers pass.
Their entire comparison objects and binaries are identical to respectively
`sync-20261006` (360 bytes), `request-20261006` (564 bytes) and
`chain-20261006-final` (868 bytes). The chain retains its 3,888 complete cases and
229 bounded pending-prefix cases; it still models path strings. Evidence is in
`local/validation/path-prefix-20261013-retained-{sync,request,chain}/COMPLETE.json`
and audit `retained-checks.json`. All **134 public tests pass** in
`public-tests.log`. Accepted source/tool and binary hashes were rechecked by
the audit. The reused service-acquisition source/header were not edited.

Development records are retained honestly: `sync-dev1` failed before execution
because section collection discarded the uncalled wrapper; all comparison entry
points are now retained explicitly. `sync-dev2` reached the old 512-instruction
budget on long concrete length scans. The new concrete mode uses 4,096 while
the default retains 512. `sync-dev3` and `request-final` passed development
comparisons but predate final evidence metadata/direct-case logging. The
`*-accepted` directories above own final acceptance. No original/rebuilt
behavior mismatch was bypassed. All started commands finished; Ghidra jobs
were sequential and read-only.

## Reproduction

Run from `SMT4-decomp`, using fresh ignored output directories and sequential
Ghidra jobs on the authoritative saved project:

```powershell
python tools/check_resource_sync.py --recover-prefix --output local/validation/NEW-PREFIX-SYNC
python tools/check_resource_request.py --recover-prefix --output local/validation/NEW-PREFIX-REQUEST
python tools/check_resource_sync.py --recover-prefix --mutant prefix-limit --output local/validation/NEW-PREFIX-NEGATIVE
python tools/check_resource_sync.py --output local/validation/NEW-RETAINED-SYNC
python tools/check_resource_request.py --output local/validation/NEW-RETAINED-REQUEST
python tools/check_resource_chain.py --output local/validation/NEW-RETAINED-CHAIN
python -m unittest discover -s tests
```

The other fault choices are `prefix-return` and `prefix-order`. Mutant source
stays local; a rejected fault must fail after compilation at its expected
comparison assertion and must not produce `COMPLETE.json`.

## Next independent source milestone

Recover descriptor path copy **`0x002BF8C0`**, replacing
`smt4_file_path_copy` in constructor **`0x002B0494`**. Read
[descriptor creation](resource-create.md), `src/resource_create.c` / `.h`,
`tools/check_resource_create.py` and `tools/check_resource_chain.py`.
The existing constructor report and linker bind this active model to the entry.
A bounded GNU look in audit `next-copy-disassembly.log` confirms a no-call ARM
body through `0x002BF924` (exclusive),
followed by a literal; verify complete saved membership before implementation.
The aligned branch uses UQSUB8 at `0x002BF8DC`; the other branch copies bytes.
Determine exact source read extent, NUL-inclusive writes and consumed return.

Reuse the already recovered length routine rather than reconstructing it again.
Batch copy source with explicit constructor/chain concrete-string modes where
fixtures permit; check alignment, NUL lanes, destination guards, return and caller
state/order, with formatting/allocation/synchronization models retained. This
selects a new evidenced source dependency, not a tooling or full-loader milestone.
Reload load/release integration, actual allocation lifetime and live gates remain
independent open work.
