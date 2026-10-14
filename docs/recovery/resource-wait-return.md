# Diagnostic wait consumed return registers

2026-10-13. Project-authored EU base v0 recovery against expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
No external code reused. These are original ARM contracts, not native services.

## Strategic review and acceptance

Both preceding
create/chain manifests' source/tool hashes match the opening workspace; see
`local/validation/wait-return-20261013-audit/prior-handoff-check.json`.
A07/G2 support removing these active game dependencies; no reprioritization,
extraction, speculative compiler work, live gameplay or port implementation is
needed. The deferred live gates remain open.

Acceptance declared before implementation: confirm original instruction extents;
preserve incoming r2 on immediate state one, zero on successful zero exchange,
and SVC r2 on direct -2 and generic arbitration paths; retain exclusive retry,
CLREX, interference, handle reload and bounded pending-prefix behavior; build
warning-clean source, remove wait/init models in create/chain, compare guarded
state/ABI and caller break payloads, reject return faults and run affected regressions.

## Extended contracts and removed models

Two existing contracts are extended, with no newly discovered entry counted:

- ARM `0x002C367C..0x002C373C`, `src/resource_diagnostic_wait.c`: the entry
  captures incoming r2 explicitly; the C body carries a two-word return. State
  one returns r0=1 with the carried r2. Successful zero exchange returns both
  words zero. Direct -2 returns arbitration's r0/r2 without rereading state;
  generic arbitration carries its r2 into the next iteration. A later successful
  exchange overwrites that value with zero. Nonzero exclusive observations still
  CLREX and arbitrate, including observations of one and -2.
- ARM `0x002A88FC..0x002A8914`, `src/resource_arbitration.c`: the six-instruction
  assembly entry preserves SVC r0/r2 while saving/restoring r4/r5 and loading the
  two timeout words from the original ABI stack. This makes the previously
  ordinary-C return boundary explicit under independently varied SVC registers.

The wait C body is 144 bytes, its incoming/returned-register bridge 20 bytes,
and its wait-specific arbitration adapter 40 bytes. The wrapper is 24 bytes
(previously 20). Bridges are ABI implementation support, not new game contracts.
Initializer `0x002C5470` (64 bytes) and base initializer `0x00138F44` (24 bytes)
are reused unchanged. `compiled-sizes.log` records these sizes. No original
binary helpers execute on rebuilt paths.

Create/chain `--recover-result-diagnostic` now link wait, initialization, base
initialization and arbitration instead of intercepting wait/init. Exactly those
two active call models are removed. Existing delivery, producer, dispatcher,
process/request/copy/connect/delay source is reused, not counted as new recovery.
The shared builder adds ARMv6K only to diagnostic builds because wait uses CLREX.
The first development create build demonstrated this requirement by failing
under ARMv6. No comparison assertion was weakened.

## Bounded validation

Primary connected evidence:
`local/validation/wait-return-20261013-create-dev2/COMPLETE.json` and
`local/validation/wait-return-20261013-chain/COMPLETE.json`. Warning-clean
**2,020 / 2,452-byte** builds pass **10,080 constructor / 3,888 chain pairs**,
including **229 chain pending prefixes**, plus 120 producer/delivery, 1,168
synchronization and 440 string pairs. All 66 delivery sites remain visited in
the direct corpus. The helper separately records 162 / 132 visited supporting
sites; caller counts remain 204 / 302. Connected wait/init counts across both
paths are **17,016 / 6,218**, with **34,176 / 12,436** exclusive attempts.
These are exercised executions, not new contracts or progress percentages.

`local/validation/wait-return-20261013-worker-final/COMPLETE.json` records the
**6,208-byte** build and all **3,170 pairs**, including 45 direct initializers
and 48 direct waits. All 61 initializer/wait sites and twelve base/wrapper sites
execute. Existing 1,188 exclusive attempts, twelve CLREX operations, 490
arbitration boundaries and twelve pending exclusive prefixes remain covered.
The complete diagnostic evidence object and wait behavior fields equal the prior
delivery milestone; the comparison object differs only in maximum instructions
(1,111 to 1,129). The r2 oracle is additional, not a replacement for those checks.

`local/validation/wait-return-20261013-arbitration/COMPLETE.json` records all
**1,920 direct pairs**, 3,840 SVC boundaries and six wrapper sites in a 24-byte
image, now checking r2 explicitly. `wait-return-20261013-signal-lock/COMPLETE.json`
records all **7,556 pairs**, including **36 pending prefixes**, 37,182 arbitration
boundaries and 114,178 exclusive attempts. Kernel behavior remains intercepted.

Two compiled faults are rejected with `Wait returned r2 oracle`: zeroing the
carried payload on state one, and carrying arbitration's low word instead of r2
on a generic loop. Both have NEGATIVE.json and no COMPLETE.json. The existing
negative-test driver returns zero after proving rejection; the audit runner's
initial mistaken exit-code expectation was corrected without rerunning or
weakening the failed oracle. Exact commands/exits are in audit `jobs.json`.

Audit: `local/validation/wait-return-20261013-audit/COMPLETE.json`.
All recorded current source/tool and binary hashes match. Retained create/chain
`--recover-sync --recover-strings` modes have identical **888 / 1,368-byte**
binaries and entire comparison, synchronization and string objects to their
preceding delivery-milestone baselines. All **134 public tests pass** with raw
process exit zero. The suite was repeated once solely to resolve PowerShell's
stderr wrapper reporting exit one despite the first unittest run reporting OK;
both logs and the reason are retained. Python syntax and changed-file whitespace
checks pass. `artifact-checks.json`, `retained-checks.json`, `worker-checks.json`,
`negative-checks.json` and `public-tests.json` retain exact results.

All Ghidra jobs ran sequentially and read-only, and every started command finished.
The bounded milestone acceptance above is satisfied; whole-game recovery and
live gates are not complete.

Reproduce sequentially from the decomp repository:

```powershell
python tools/check_resource_create.py --recover-result-diagnostic --recover-strings --output local/validation/NEW-WAIT-CREATE
python tools/check_resource_chain.py --recover-result-diagnostic --recover-strings --output local/validation/NEW-WAIT-CHAIN
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --output local/validation/NEW-WAIT-WORKER
python tools/check_resource_arbitration.py --output local/validation/NEW-WAIT-ARBITRATION
python tools/check_resource_signal_lock.py --recover-arbitration --output local/validation/NEW-WAIT-SIGNAL-LOCK
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --mutant wait-r2-incoming --output local/validation/NEW-WAIT-NEGATIVE
python -m unittest discover -s tests
```

The second fault is `wait-r2-svc`; retained modes use `--recover-sync --recover-strings`.
The full sequential job list is in audit `run-jobs.py`.

The existing independent worker transition oracle now tracks the expected r2.
Direct fixtures vary incoming r2 with state/result; arbitration independently
supplies r2 as a function of the fixture and call index, distinct from r0.
Existing ordinary/exclusive access order, widths, scheduled competing writes,
failed stores, successful writes, CLREX, handle reloads, object guards, callee
saves, stack restoration and pending-prefix checks remain active. The direct
arbitration checker also asserts returned r2 after poisoning all SVC arguments.

The connected delivery helper executes initializer LDREX/STREX instructions and
supplies only exclusive-monitor success. It checks reservation/address, stored
sentinels and base-first order; fixtures include zero, one or two failed base
stores. Direct worker fixtures separately cover failed state stores and pending
exchanges. SVC 0x22 checks all six argument words, initialized {-2,1} storage,
cleared reservation and preserved caller registers after deliberately poisoned
r4/r5. Returned SVC r0/r2 propagate through delivery, producer and dispatcher;
all existing record/IPC/type/retry/caller comparisons remain active.

Create development dev2 tested the final behavior. A subsequent restoration of
explicit volatile handle reads and header comments compiled to exactly the same
constructor binary; `final-rebuild.json` records commands and byte identity.
Its primary COMPLETE manifest and the final rebuild together identify the final
source. The earlier worker output is development evidence; use worker-final.

## Remaining boundaries

Kernel arbitration/SVC outcomes, exclusive-monitor success and scheduled physical
interference remain explicit models. Recursive acquire/release and release r0/r2,
TLS, sleep, returning-break policy, allocation, clear and formatting remain
modeled in create/chain; chain also retains outer-prefix and timing models.
Wait's incoming-r2 contract is verified directly, but the connected initialized
-2 route always overwrites it via arbitration. This does not establish arbitrary
scratch-register provenance through delivery's nonfinal recursive releases.

Aligned mapped storage and finite schedules are the compared domain. Arbitrary
concurrency, liveness, faults/MMIO/cache/timing, nonreturning kernel policy, actual
I/O/allocation lifetime, full startup, binary matching, native playability and
live G1/G2 remain unclaimed.

## Next independent source milestone

Extend **base acquire `0x001464F8..0x001465D4`** for its consumed r2 and connect
it through existing recursive acquire `0x002C3AFC..0x002C3B34`. The original
initial fast path returns the lock address in r2 (entry MOV r2,r0); successful
slow paths return zero from STREX r2. Existing C `smt4_signal_lock_acquire`
does not expose this distinction. Recursive acquire preserves incoming r2 on
the already-owned path and otherwise forwards base r2, so this is a concrete
remaining source dependency, not a reason to recount the recursive wrapper.

Read `resource-lock.md`, `resource-recursive-lock.md`, `resource-pool-object-teardown.md`,
`src/resource_lock.c`, and audit `next-lock-acquire.log`. Reuse
`python tools/check_resource_recursive_lock.py --output local/validation/NEW`
and the signal/lock fixtures to assert r2 for fast, slow, interference and pending
paths, then a persistent recursive acquire/release lifetime. Keep TLS/kernel
outcomes explicit. The following delivery-lock integration must additionally
resolve caller scratch r2 on failed connect, skipped close and retry paths; see
`next-delivery-lock.log` and `resource-delivery-return.md`. Do not simply relink
locks under arbitrary compiler-generated incoming r2 or claim that provenance
already recovered. Do not restart the completed wait/delivery milestones.
