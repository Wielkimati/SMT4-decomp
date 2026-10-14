# Constructor synchronization and result dispatch

2026-10-13. Project-authored instruction recovery against EU base v0 expanded
executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
No external implementation reused. Names describe observed contracts.

## Strategic review and acceptance

Both preceding
create/chain manifests' source/tool and binary hashes match the initial workspace:
`local/validation/create-sync-20261013-audit/prior-handoff-check.json`.
The target advances A07 source recovery under the G2 comparison criteria; it
does not depend on optional extraction, compiler research or deferred live gates.
No reprioritization was needed.

Acceptance declared before implementation: confirm original memberships, recover
acquire/release SVC marshalling and unconditional output publication, result
classification and flag branches, caller LR and diagnostic-returned r2 transport;
require warning-clean ARM builds, direct original/rebuilt comparisons, connected
constructor/chain state and order checks, ABI preservation, compiled fault
rejection and affected regressions. Kernel outcomes, diagnostic delivery and
returning break policy remain explicit models.

## Recovered contracts and model removal

`src/resource_create_sync.c` supplies three new original entry contracts:

| Original ARM interval, exclusive end | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x002C4350..0x002C4374` | `smt4_file_acquire` | 28 |
| `0x002C54A4..0x002C54BC` | `smt4_file_release` | 20 |
| `0x002C54BC..0x002C5524` | `smt4_file_check_result` | 160 |

The saved Ghidra memberships match all three intervals. The accepted constructor
directory contains `sync-membership.txt` and independent GNU disassemblies
`original-002c4350-disassembly.log` / `original-002c54a4-disassembly.log`.

Acquire receives an output pointer, handles pointer, count, wait-all word and
64-bit stack timeout. It issues SVC `0x25` with timeout low in r0, handles in r1,
count in r2, wait-all in r3 and timeout high in r4. It stores returned r1 through
the original output pointer regardless of the sign of returned r0, restores r4
and returns r0. Release issues SVC `0x16` with the output pointer in r0 and handle
in r1; it likewise always publishes returned r1 and returns r0.

The result dispatcher ignores its nominal second argument. It reads byte
`0x1FF80014`, then signed byte `0x0044E7A8`. Enable state is the OR of the first
byte's bit zero and the sign-extended second byte. Classification is the signed
five-bit value in result bits 31..27:

| Enable state | Class | Observable dispatch |
| --- | --- | --- |
| Nonzero | -7 or 1 | Return original result without a call |
| Nonzero | Every other class | Diagnostic `(result, 0, caller_LR)`, return its r0 |
| Zero | -1 | Diagnostic `(result, 0, caller_LR)`, then break with diagnostic-returned r2 |
| Zero | Every other class | Break with r2 zero |

Break here denotes entry `0x002BCE9C`, whose already recovered consumed contract
ignores incoming r0/r1, forces reason zero and consumes r2. This package models
that entry returning r0; it does not execute or recount `resource_break.c`.
Diagnostic entry `0x001284A8` remains modeled. On both diagnostic branches, the
site word is this dispatcher's incoming LR, not its own diagnostic-call address.

A 16-byte assembly ABI adapter collects diagnostic r0/r2 into a standard 64-bit
C return pair. It has no original address and is not a fourth recovered contract.
The adapter makes the compiler recognize a real call and maintain eight-byte
stack alignment. The three routines total 208 bytes; the adapter accounts for
the remaining 16 bytes of image growth. No constructor source behavior changed;
its header now declares the dispatcher's observed r0 return, which callers ignore.

Both create/chain `--recover-sync` options remove the acquire, release and result
routine models. Checkpoints still inspect call arguments and caller snapshots,
then execute original instructions on the original side and rebuilt source on
the rebuilt side. The kernel model only supplies SVC registers: original and
rebuilt stores publish outputs themselves. No original instruction executes on
the rebuilt side. `--recover-strings` is independently composable and retains
its preceding source, read/write oracle and UQSUB8 instruction support.
The new helper, build support and checker edits are validation/integration work,
not additional recovered game contracts.

## Compared domain and remaining models

The direct corpus has 72 acquire and 72 release pairs: six timeout patterns
(including different high/low words and signed extremes), four SVC results
(zero, positive and two high-bit errors), and three output words. Count/wait-all
and handle words vary independently across fixtures. These are register
marshalling cases, not actual kernel waits or validation of huge handle arrays.
Dirty output/input guards and incoming stack argument words must survive except
for the single required output word. The SVC fixture clobbers caller scratch
registers and, for acquire, r4, requiring its restoration.

The 1,024 dispatcher pairs cover every five-bit class at both low-bit endpoints,
four kernel flag bytes (0/1/2/255), four debug bytes (0/1/128/255), and three ARM
caller addresses. Reads must occur as two one-byte accesses in the original order.
Diagnostic arguments, call order, break payload, r0 return, SP and r4-r11 are
checked independently against expected behavior. Ordered normalized direct traces
must also match between original and rebuilt machines. All 41 original sites
execute, including predicated sites; this is not exhaustive input proof.

Constructor checks retain list insertion, descriptor bytes/store multiplicity,
path guards and modes, high-bit error handling, and handle rereads after a model
changes the global following acquisition. Chain checks retain outer loader,
configuration, polling, scheduled completion, cleanup and bounded pending prefixes.
Nested synchronization steps have a separate 128-instruction budget.

Both accepted modes keep allocation, clear and formatting modeled. Allocation
and clear have separate recovered implementations; they are not newly recovered
here and are not silently integrated. The chain additionally keeps outer prefix,
signal and timing models. SVC outcomes, diagnostic delivery and returning break
policy are controlled fixtures. Nonreturning diagnostics/breaks, real kernel
scheduling, allocation/I/O lifetime, concurrent mutation, invalid/overlapping
buffers, faults/MMIO/timing and Thumb callers are outside the compared domain.
Original diagnostic tail calls and the rebuilt ABI adapter use different internal
return locations; the explicitly transported caller site is checked. Incidental
caller-scratch values beyond consumed r2 are not a public ABI guarantee.
Live G1/G2, complete startup, binary matching, a reconstructed 3DS application
and native-port implementation remain open and unclaimed.

## Validation

Constructor evidence:
`local/validation/create-sync-20261013-create-accepted/COMPLETE.json`.
The warning-clean 888-byte build passes 1,168 direct synchronization pairs,
352 copy / 88 reused length pairs and all 10,080 constructor pairs. All 192
original sites execute: 103 constructor, 48 strings and 41 synchronization.
It executes 20,304 acquire, 20,304 release and 18,176 result-dispatch calls across
both machines and direct/caller fixtures. Maximum nested synchronization length
is 30 instructions. These counts describe this bounded corpus, not decompilation
coverage percentages.

The warning-clean 1,368-byte chain passes all 3,888 pairs, including 229 bounded
pending prefixes, with 290 original sites (40 synchronization sites; the direct
corpus supplies the enabled skip-return site). It executes 7,776 acquire, 7,776
release and 6,218 result-dispatch calls across both machines. Evidence:
`local/validation/create-sync-20261013-chain-accepted/COMPLETE.json`.

Three compiled source faults are rejected: skipped output publication on a failed
acquire (`Sync output publication`), using timeout low for high (`SVC
timeout/count/mode marshalling`), and losing diagnostic-returned r2 (`Break r2
transport`). All build successfully, exit with a failed comparison and have no
`COMPLETE.json`. Audit `negative-checks.json` / `jobs.json` record the exact
commands and assertions; sources and failure logs remain local.

All four affected retained checkers pass, with entire comparison objects and
binaries identical to their baselines:

| Retained mode | Comparisons | Bytes | Historical baseline |
| --- | ---: | ---: | --- |
| Default constructor | 10,080 | 388 | `create-20261006` |
| Default chain | 3,888, including 229 pending | 868 | `chain-20261006-final` |
| Worker step | 3,472 plus 160 original state-0 probes | 708 | `worker-step-20261007` |
| Worker loop | 3,456 | 232 | `worker-loop-20261007-final` |

The worker checks cover the shared return-type declaration change; their modeled
synchronization boundaries remain intact. Fresh evidence is under
`local/validation/create-sync-20261013-{create,chain,worker,worker-loop}-retained/`.
All **134 public tests pass**, with process exit zero in `public-tests.json` and
`public-tests-accepted.log`. An earlier PowerShell-redirection wrapper reported
exit one while its test log said `OK`; the accepted run uses an explicit Python
subprocess capture to remove that shell-status ambiguity.

Audit `local/validation/create-sync-20261013-audit/COMPLETE.json` records final
manifest/binary identity, reused source identity, syntax/metadata/whitespace and
retained comparisons. All started commands finished; Ghidra jobs ran sequentially
and read-only. No commit was made.

Development `create-dev1` rejected the first inline diagnostic BL because the
compiler created a four-byte-aligned leaf frame. The source now uses the explicit
ABI adapter; `create-dev2` passed. The accepted run additionally checks incoming
stack arguments and acquire's saved r4 against a clobbering SVC fixture. No
behavioral check was weakened to accept the source.

## Reproduction

Run from `SMT4-decomp`, with fresh ignored output directories and sequential
Ghidra jobs on the authoritative saved project:

```powershell
python tools/check_resource_create.py --recover-sync --recover-strings --output local/validation/NEW-SYNC-CREATE
python tools/check_resource_chain.py --recover-sync --recover-strings --output local/validation/NEW-SYNC-CHAIN
python tools/check_resource_create.py --recover-sync --mutant sync-publication --output local/validation/NEW-SYNC-NEGATIVE
python tools/check_resource_create.py --output local/validation/NEW-CREATE-RETAINED
python tools/check_resource_chain.py --output local/validation/NEW-CHAIN-RETAINED
python tools/check_resource_worker.py --output local/validation/NEW-WORKER-RETAINED
python tools/check_resource_worker_loop.py --output local/validation/NEW-LOOP-RETAINED
python -m unittest discover -s tests
```

Other compiled faults are `sync-timeout` and `sync-payload`. They must build,
fail the intended comparison assertion and leave no success marker. Mutants
remain local; `run-jobs.py` and `jobs.json` under the audit directory record
the exact sequential validation commands and outcomes.

## Next independent source milestone

2026-10-13 continuation: this producer milestone is now completed by
[result diagnostic recovery](resource-result-diagnostic.md). Its new optional
mode removes the producer model while retaining delivery's explicit r0/r2
outcome boundary. The original task
selection and evidence below remain historical.

Recover diagnostic record producer **ARM `0x001284A8..0x001284D8`** (candidate
exclusive end, confirm saved membership), removing the remaining diagnostic
model from result dispatcher `0x002C54BC`. Independent instructions are saved in
`local/validation/create-sync-20261013-audit/next-diagnostic-disassembly.log`.
The entry writes global record `0x004D4200` in order: byte +1 zero, byte +0 low
r1, halfword +2 `0xBCA3`, word +8 incoming r2, word +4 incoming r0; it then tail
branches to existing delivery `0x002AD7E8`. This differs from the already recovered
worker record producer `0x002BBD70` in both the type argument and store order.

Read `resource-worker-diagnostic.md`, `resource-break.md`, this report and
`src/resource_worker_diagnostic.c` / `.h`. Reuse the existing 128-byte record
layout and delivery code only where its consumed contract is established. The
dispatcher consumes diagnostic-returned r2 on its disabled class -1 branch;
preserve that transport explicitly, or retain delivery's r0/r2 outcome as an
honest model rather than assuming ordinary C preserves scratch registers.
Batch direct record/type-width/unknown-byte/order/ABI checks with dispatcher and
create/chain integration. If concrete delivery reuse is practical, retain explicit
kernel, locking, wait and break boundaries and do not recount old contracts.
This is new source recovery; clear/allocation integration alone is not its goal.
