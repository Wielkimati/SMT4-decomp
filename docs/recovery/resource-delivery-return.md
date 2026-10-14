# Diagnostic delivery consumed return registers

2026-10-13 update: [wait consumed-return extension](resource-wait-return.md)
establishes wait/arbitration r0/r2 and replaces wait/initializer models in
create/chain `--recover-result-diagnostic`. Earlier evidence below retains its
historical boundaries; lower locks and kernel outcomes remain modeled.

2026-10-13. Project-authored EU base v0 instruction recovery against expanded
executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
No external code reused. Names describe observed contracts.

## Strategic review and acceptance

The
prior create/chain manifests' source/tool and binary hashes match the opening
workspace; see `local/validation/delivery-return-20261013-audit/prior-handoff-check.json`.
No reprioritization, extraction, compiler research, live gameplay or port work
was needed. The earlier ordinary-C delivery return did not establish the r2
that result dispatch consumes as a break payload.

Acceptance declared before implementation: confirm original ARM membership;
extend delivery's type-dependent r0/r2 return; preserve record, retry, IPC,
handle and call ordering; validate guarded state, caller transport and ABI;
build warning-clean source; compare connected producer/dispatcher/create/chain
behavior; reject compiled return faults and run affected worker regressions.
Lower release/wait returned registers remain explicit modeled outcomes.

## Extended source contract and model removal

**One extended contract: ARM `0x002AD7E8..0x002AD8F0`**, implemented in
`src/resource_worker_diagnostic.c`. This does not recount the five historical
diagnostic contracts, the existing producer or wait recovery. Original GNU
instruction evidence is retained in
`local/validation/result-diagnostic-20261013-audit/next-delivery-disassembly.log`;
new saved membership is in each accepted comparison's `delivery-membership.txt`.

The original final release call at `0x002AD88C` is followed by a fresh record
byte load. Types two/five return that byte in r0 while preserving release's r2.
All other returning types initialize the two-word wait object and call wait at
`0x002AD8C0`, forwarding both returned r0 and r2. The epilogue changes neither.
Retry release at `0x002AD8E0` is not the final release and its return is discarded.

The C body now represents the two returned words as a standard 64-bit result.
Two 16-byte ABI adapters capture release/wait r2 immediately into the high word;
a 16-byte delivery entry bridge moves that high word back to original r2.
These are implementation bridges for one extended routine, not new game
contracts or recovered lower lock/wait semantics. Ordinary C callers still
consume r0 through the existing declaration; the producer's assembly tail
preserves both words to the result dispatcher.

Create/chain `--recover-result-diagnostic` now link this delivery instead of
intercepting it. Process, request, aligned copy, port connect and delay execute
existing source (including compiler inlining), without being counted again.
Producer record stores, its tail LR/SP checks and the dispatcher adapter are
retained. The supporting builder and bounded execution helper make this source
extension reviewable; they are not additional decompilation.

## Compared domain and remaining models

The 120 direct producer-to-delivery pairs reuse type narrowing, result/site,
guards and ABI fixtures. Ten delivery scenarios exercise cached handles,
success/failure connection, two finite failed retries, a failed connection's
published nonzero handle, post-release type changes in both routing directions,
and process/request handle mutations. Independent release r2 values vary by
iteration and differ from wait r2; the final return is checked against the
fixture-derived expected type/result/payload. Arbitrary unknown record bytes
and guards survive except for the explicitly scheduled process/release writes.

The harness executes actual process/request/connect wrappers, the 128-byte copy,
and the consumed delay branch. It checks exact port bytes, process output,
IPC command and entire payload, close's reloaded handle, failure publication,
final handle, zeroed wait object, finite retry counts, stack alignment/restoration
and r4-r11. Original/rebuilt normalized byte-store and lower-event traces agree.
PLD cache hints and TLS reads use explicit host instruction support; neither
models a game routine. The earlier worker corpus separately retains its wider
copy lengths/overlap, all retry-status bit flips, result signs and terminal waits.

Lower recursive acquire/release, wait initialization/wait, TLS, kernel replies,
sleep and returning-break policy remain models in these create/chain modes.
Release and wait r0/r2 outcomes are independently supplied. This does **not**
establish the provenance of an incoming scratch r2 that a nonfinal recursive
release can preserve. Existing lock/wait source cannot simply be linked under
these stronger caller assumptions without another consumed-register review.
Allocation, clear and formatting remain modeled; chain retains outer-prefix
and timing models. The worker wait mode still proves its historical ordinary-r0
contract, not the newly consumed wait r2 contract. Nonreturning policy, physical
concurrency, invalid storage, faults/MMIO/timing, actual service/allocation
lifetime, full startup, live G1/G2, binary matching and native playability remain
unclaimed. Original inputs, saves and repository boundaries are preserved.

## Validation

Primary constructor evidence:
`local/validation/delivery-return-20261013-create-accepted/COMPLETE.json`.
The warning-clean **1,704-byte** ARM build passes 120 producer-to-delivery pairs,
all 1,168 synchronization and 440 string pairs, and all **10,080 constructor
pairs**. Its 17,112 delivery executions across both paths include 96 direct
returns, 17,016 returning waits and 32 retry iterations. All **66 delivery
instruction sites** execute; the helper records 120 sites including reused
supporting routines, separately from the caller's unchanged 204-site count.

Primary chain evidence:
`local/validation/delivery-return-20261013-chain-accepted/COMPLETE.json`.
The warning-clean **2,136-byte** build passes all **3,888 pairs**, including
229 bounded pending prefixes. All 6,218 delivery executions take the initialized
wait route; 47 delivery sites and 90 delivery/support sites execute, separately
from the caller's unchanged 302-site count. This deliberately narrower chain
corpus does not claim the direct corpus's retry/type coverage.

The extended delivery has a **304-byte C body and 48 bytes of ABI bridges**
in the constructor build. Its C body includes inlined reused process/request
behavior. This is one extended contract, not 352 bytes of newly discovered game
behavior. `compiled-sizes.log` and both rebuilt disassemblies record the sizes.

Two compiled faults (using release's low word in place of its r2 high word,
and truncating wait's 64-bit pair) build and fail `Delivery returned r0/r2`.
Neither produces a success marker. Commands, exits and assertion checks are in
`jobs.json`, `negative-checks.json` and their individual logs under the audit.

Worker diagnostic and diagnostic-wait regressions pass **3,077 / 3,170 pairs**
in 5,600 / 6,184-byte images. Complete diagnostic and wait evidence objects
match their recorded baselines; comparison objects differ only in maximum
instruction count (1,001 to 1,025 and 1,087 to 1,111) due to the ABI calls.
The diagnostic baseline predates the shared-copy extraction; the wait baseline
is the newer table-copy regression. See `worker-checks.json` for exact bases
and differences. Neither worker mode claims a recovered lower wait r2.

Retained create/chain `--recover-sync --recover-strings` binaries (888 / 1,368
bytes) and entire comparison/synchronization/string objects are identical to
the preceding milestone. All **134 public tests pass**. Audit:
`local/validation/delivery-return-20261013-audit/COMPLETE.json`, with source/tool
and binary hash checks, retained comparisons, negative checks, public test log,
Python syntax and changed-file whitespace evidence. Default modes were not
rerun; their disabled-delivery paths are unchanged.

Development dev1 used the old delivery interception after a path error in the
editing command and failed `Diagnostic PC 2c3afc`; no game assertion was weakened.
Dev2 passed the full constructor corpus. Final acceptance adds per-iteration
release payloads and an explicit final-handle check. Only final accepted files
establish the current source/tool identity; dev2 is developmental evidence.
All commands finished, with Ghidra jobs sequential and read-only.

```powershell
python tools/check_resource_create.py --recover-result-diagnostic --recover-strings --output local/validation/NEW-DELIVERY-CREATE
python tools/check_resource_chain.py --recover-result-diagnostic --recover-strings --output local/validation/NEW-DELIVERY-CHAIN
python tools/check_resource_create.py --recover-result-diagnostic --mutant delivery-release-r2 --output local/validation/NEW-DELIVERY-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-diagnostic --output local/validation/NEW-DELIVERY-WORKER
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --output local/validation/NEW-DELIVERY-WAIT
python -m unittest discover -s tests
```

The other return fault is `delivery-wait-r2`; the retained-mode commands and
all exact sequential invocations are in the audit's `run-jobs.py` / `jobs.json`.

## Next independent source milestone

Extend **wait `0x002C367C..0x002C373C` and arbitration wrapper
`0x002A88FC..0x002A8914`** to establish their consumed r0/r2 return. Replace the
wait and initializer models in create/chain `--recover-result-diagnostic` by
reusing initializer `0x002C5470..0x002C54A4` and base initializer `0x00138F44`.
Read `resource-diagnostic-wait.md`, `resource-arbitration.md`, the existing
`src/resource_diagnostic_wait.c` / `src/resource_arbitration.c`, and
`local/validation/delivery-return-20261013-audit/next-wait-disassembly.log`.

Static evidence: immediate state one preserves incoming r2; successful zero
exchange leaves zero in r2; direct -2 arbitration returns the wrapper's r2;
generic arbitration/reload loops carry its r2 until overwritten by an exclusive
load or another arbitration. Inspect the SVC wrapper independently before
choosing its stronger entry ABI; `next-arbitration-disassembly.log` confirms
that the wrapper pops only r4/r5 after SVC 0x22 and preserves returned r2. Reuse the worker's exclusive/interference
fixtures for direct return, retries, CLREX and bounded pending prefixes; connect
the initialized -2 delivery path to producer/dispatcher/create/chain comparisons.
Keep kernel arbitration and locks explicit; do not recount old wait/initializer
contracts or start another extraction/port milestone.
