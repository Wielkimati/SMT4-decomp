# Result diagnostic record producer

2026-10-13. Project-authored EU base v0 instruction recovery against expanded
executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
No external code reused. Names describe observed contracts.

2026-10-13 extension: [delivery consumed return recovery](resource-delivery-return.md)
extends `0x002AD7E8` to preserve r0/r2 and removes its model from create/chain
`--recover-result-diagnostic`. Lower lock/wait outcomes remain explicit; this
report's earlier source counts and ordinary-return evidence keep their historical
scope. The wait source's consumed r2 remains the next independent extension.

## Strategic review and acceptance

The completed constructor synchronization milestone's create/chain manifests,
source/tool hashes and binary hashes match the initial workspace. Evidence:
`local/validation/result-diagnostic-20261013-audit/prior-handoff-check.json`.
This advances A07 original-game source
recovery under the G2 bounded-comparison criteria; no extraction, compiler
research, live gameplay or port implementation is needed. No reprioritization
was warranted.

Acceptance declared before implementation: confirm original ARM membership;
recover exact record store order/widths, type-byte narrowing, result/site words,
preserved unknown bytes and delivery's returned r0/r2; require warning-clean
source builds, direct and dispatcher comparisons, constructor/chain integration,
guarded state and ABI checks, compiled fault rejection and affected regressions.
Delivery `0x002AD7E8` remains a controlled r0/r2 outcome boundary. Its earlier
C recovery establishes the ordinary r0 return, not the scratch r2 consumed by
this caller. Reusing that source without extending its contract would hide a
real dependency; it is not silently treated as a complete replacement here.

## New source and model removal

One original contract, **ARM `0x001284A8..0x001284D8`**, is implemented by
`src/resource_result_diagnostic.c`. Saved Ghidra membership is exactly
`[001284a8,001284d7]`; the independent GNU disassembly includes both trailing
literals at `0x001284D8` and `0x001284DC`. These are data, not extra instructions.

The entry takes result in r0, type in r1 and site in r2. At global record
`0x004D4200`, it writes, in this order:

| Offset | Width | Value |
| --- | --- | --- |
| +1 | byte | zero |
| +0 | byte | low eight bits of incoming r1 |
| +2 | halfword | `0xBCA3` |
| +8 | word | incoming r2 |
| +4 | word | incoming r0 |

All other bytes of the 128-byte record survive. The entry then tail branches to
delivery `0x002AD7E8` with the record pointer in r0, its incoming LR/SP restored,
and its callee-saved registers intact. Whatever r0/r2 delivery returns therefore
reaches the original caller unchanged. The result dispatcher uses returned r2
as break payload on its disabled class -1 branch. The producer's site value is
opaque: no alignment or address validation is added.

The existing record layout is reused from `resource_worker_diagnostic.h` with
size/offset assertions. This is a distinct producer from worker `0x002BBD70`:
that routine ignores incoming r2, forces type zero and has a different store
order. Neither that producer nor delivery is newly recovered by this package.

A C helper performs the ordered volatile stores and returns the record pointer.
A 16-byte ARM entry bridge calls this helper, restores entry LR/SP and tail
branches to delivery. It prevents an ordinary C return/epilogue from losing the
nonstandard returned-r2 contract. The helper and bridge implement **one**
original routine, not two game contracts. The C body occupies 52 compiled bytes;
with the 16-byte bridge the image grows by 68 bytes. The earlier result-dispatch ABI
adapter remains unchanged.

Both create/chain checkers add `--recover-result-diagnostic`, which implies
`--recover-sync` and composes with `--recover-strings`. It removes the producer
model at `0x001284A8`; original instructions execute there on the original side,
and rebuilt source executes on the rebuilt side. The new model is only at
delivery `0x002AD7E8`. Earlier modes keep their prior source/model boundaries.
Builder/oracle/metadata edits are supporting integration, not recovered code.

## Compared domain and limits

The direct producer corpus contains 120 pairs: ten type words (including
0/1/2/5/255/256/257 and high-bit words), four result words and three opaque
site words, including unaligned/all-ones values. Four r0 outcomes and four
independent r2 payloads rotate through the corpus. Three aligned ARM return
addresses are used. Dirty 128-byte records have 16-byte guards on both sides.

Every actual record store is checked against an independent offset/width/value
sequence. Whole-record equality at delivery proves unknown/process bytes and
guards survive. The delivery model then mutates process and an unknown byte;
their survival checks that the producer does not restore an old record after
delivery. Tail LR/SP, alignment, r4-r11, return r0/r2, and ordered normalized
traces are checked. All 12 original instruction sites must execute.

The existing 1,168 synchronization pairs retain their complete class/flag,
SVC/output, caller-LR and break-payload checks. Their diagnostic branches now
execute this producer. Constructor and chain fixtures retain all earlier
descriptor/list/handle-reread/path/order checks and bounded pending prefixes.
The producer has a separate 64-instruction budget; no original instruction is
executed on the rebuilt path.

Delivery results/mutations are fixtures, not recovered delivery behavior in
this mode. Kernel synchronization, break outcomes, allocation, clear and
formatting remain modeled; chain also retains outer-prefix and timing models.
Other callers' r1/r3/r12 scratch values are not a public ABI guarantee. Delivery
consumes the record pointer, not these scratch values. Nonreturning delivery,
concurrency/reentrancy, invalid storage, faults/MMIO/timing, Thumb callers,
real allocation/I/O lifetime and full startup remain outside this domain.
Live G1/G2, matching and a reconstructed 3DS application remain unclaimed.

## Validation

Primary constructor evidence:
`local/validation/result-diagnostic-20261013-create-accepted/COMPLETE.json`.
The warning-clean **956-byte** build passes 120 direct producer pairs,
1,168 synchronization pairs, retained 352 copy / 88 length pairs and all
10,080 constructor pairs. All 204 original sites execute, including the 12
producer sites. There are 17,112 producer executions across both paths,
including direct fixtures. The maximum producer execution is 15 instructions.

Primary chain evidence:
`local/validation/result-diagnostic-20261013-chain-accepted/COMPLETE.json`.
The warning-clean **1,436-byte** build passes all 3,888 pairs, including 229
bounded pending prefixes, with 302 original sites and 6,218 producer executions
across both paths. These are bounded-corpus observations, not overall
coverage or liveness claims. The reused source is unchanged.

Three compiled producer faults build and fail the intended assertions, with no
success markers: swapped flags/type stores (`Diagnostic store width/order`),
storing type bits 15..8 (`Diagnostic store value/type narrowing`), and replacing
the tail branch with a returning wrapper that loses r2 (`Diagnostic tail LR/SP`,
rejected before its later r2 corruption). Exact commands, exits and failure
messages are retained in the audit's `jobs.json`, `negative-checks.json` and
individual logs. Fault sources stay local.

The retained `--recover-sync --recover-strings` constructor and chain runs pass;
their 888/1,368-byte binaries and complete comparison/synchronization/string
objects are identical to the prior synchronization milestone. Evidence:
`local/validation/result-diagnostic-20261013-audit/retained-sync-checks.json`.
Both default-mode regressions also pass: the 388-byte constructor and 868-byte
chain binaries and complete comparison objects are identical to the previous
milestone's retained defaults. All four checks are summarized in
`retained-checks.json`. All **134 public tests pass**, with subprocess exit zero
and the full suite result in `public-tests.log` / `jobs.json`.

Audit: `local/validation/result-diagnostic-20261013-audit/COMPLETE.json`.
It checks final manifest/source/tool and binary identity, reused source identity,
reference hash, metadata, Python syntax and changed-file whitespace. All started
commands finished; Ghidra jobs ran sequentially and read-only. No commits or live emulator sessions were made.

```powershell
python tools/check_resource_create.py --recover-result-diagnostic --recover-strings --output local/validation/NEW-RESULT-DIAGNOSTIC-CREATE
python tools/check_resource_chain.py --recover-result-diagnostic --recover-strings --output local/validation/NEW-RESULT-DIAGNOSTIC-CHAIN
python tools/check_resource_create.py --recover-result-diagnostic --mutant diagnostic-order --output local/validation/NEW-RESULT-DIAGNOSTIC-NEGATIVE
python tools/check_resource_create.py --recover-sync --recover-strings --output local/validation/NEW-SYNC-CREATE-RETAINED
python tools/check_resource_chain.py --recover-sync --recover-strings --output local/validation/NEW-SYNC-CHAIN-RETAINED
python tools/check_resource_create.py --output local/validation/NEW-CREATE-RETAINED
python tools/check_resource_chain.py --output local/validation/NEW-CHAIN-RETAINED
python -m unittest discover -s tests
```

Other producer faults are `diagnostic-type` and `diagnostic-tail`. The audit's
`run-jobs.py` records the sequential validation commands. The primary
`original-001284a8-disassembly.log` and `result-diagnostic-membership.txt`
record original instruction/membership evidence; `compiled-sizes.log` separates
the 52-byte C body and 16-byte entry bridge from the unchanged dispatcher adapter.

## Next independent source milestone

Extend the consumed **r0/r2 return contract of diagnostic delivery
`0x002AD7E8..0x002AD8F0`**, then replace this package's delivery model in
`--recover-result-diagnostic`. This is an extension to existing source, not
another claim to recover the five historical diagnostic contracts.

The original instructions at `0x002AD88C..0x002AD8C8` establish a precise split:
record types two/five retain final lock release `0x002C3A78`'s returned r2;
other returning types retain wait `0x002C367C`'s returned r2. The final epilogue
does not overwrite it. Static lead:
`local/validation/result-diagnostic-20261013-audit/next-delivery-disassembly.log`.
The existing C delivery signature returns only r0. Read
`resource-worker-diagnostic.md`, `resource-diagnostic-wait.md`,
`src/resource_worker_diagnostic.c` and `src/resource_diagnostic_wait.c` before
changing this contract. Keep lower release/wait r0/r2 outcomes explicit where
their consumed contract is not yet recovered; do not assume C preserves r2.

Reuse existing delivery/process/request/copy/connect/delay source and the
diagnostic fixtures. Batch direct type-two/five and type-zero outcomes, finite
retry and mutation cases, and producer/dispatcher integration. Retain IPC,
failure-publication, handle reload and record order checks. Then exercise
create/chain `--recover-result-diagnostic --recover-strings` and the affected
worker diagnostic regression. Kernel, locks, wait, break and live policies
must retain honest boundaries. This is the next target after completing this
package, not extra implementation included here.
