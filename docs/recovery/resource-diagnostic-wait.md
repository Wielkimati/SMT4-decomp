# Diagnostic wait initialization and waiting

2026-10-13 update: [wait consumed-return extension](resource-wait-return.md)
establishes wait/arbitration r0/r2 and replaces wait/initializer models in
create/chain `--recover-result-diagnostic`. Earlier evidence below retains its
historical boundaries; lower locks and kernel outcomes remain modeled.

2026-10-11. Project-authored instruction recovery against EU base v0 expanded
executable SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

2026-10-13 extension: [delivery consumed return recovery](resource-delivery-return.md)
extends `0x002AD7E8` to preserve r0/r2 and removes its model from create/chain
`--recover-result-diagnostic`. Lower lock/wait outcomes remain explicit; this
report's earlier source counts and ordinary-return evidence keep their historical
scope. The wait source's consumed r2 remains the next independent extension.

## Strategy review and acceptance

The completed diagnostic milestone was checked against its primary manifest:
all 39 recorded source/tool hashes matched before editing. See
`local/validation/diagnostic-wait-20261011-static/handoff-check.json`.
No reprioritization was necessary.

Acceptance selected before implementation: confirm ARM membership, build faithful
source with warnings as errors, and compare initialization order, exclusive retries,
-2/-1/zero/one/other states, CLREX, arbitration handle reload and all six argument
words, return values, bounded pending prefixes and connected startup/archive
failures. Kernel arbitration and physical concurrency remain modeled boundaries.
These bounded criteria are satisfied; G1/G2 and whole-game recovery remain open.

## Source contracts and dependencies removed

`src/resource_diagnostic_wait.c` adds two contracts, declared in the existing
`src/resource_worker_diagnostic.h`:

| Original ARM interval (exclusive end) | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x002C5470..0x002C54A4` | `smt4_diagnostic_wait_initialize` | 64 |
| `0x002C367C..0x002C373C` | `smt4_diagnostic_wait` | 184 |

The optional `--recover-diagnostic-wait` mode implies `--recover-diagnostic` and
removes **two active lower call models**. The new source totals **248 bytes**.
Existing base initialization `0x00138F44` (24 bytes) and arbitration wrapper
`0x002A88FC` (20 bytes) execute from their recovered source; they are not new
contracts. The linker also retains 292 unused companion bytes from pool
initialization, recursive initialization and quotient source. Thus the image
increases from 5,520 to **6,104 bytes**, not by 584 newly recovered bytes.
Exact symbol sizes are in the static directory's `compiled-sizes.log`.
No original binary helper executes on the rebuilt path. The builder/oracle,
metadata and header changes support these contracts and are not additional recovery.
Older checker modes retain their stated boundaries.

The initializer first calls the recovered base initializer on word +4, exclusively
exchanging it to one. Only after it succeeds does it exclusively exchange word +0
to -1 for mode zero or -2 for any nonzero mode. Both operations retry failed
stores without a barrier. Its r0 on return is the word loaded by the final +0
exclusive attempt, not the stored sentinel. The header now exposes that result;
diagnostic delivery still ignores it. No other object bytes are changed.

Wait loads word +0 at the start of each iteration:

- **-2:** load the current handle at `0x00471B58`, call arbitration, and return its
  r0 unchanged without reloading state after the call.
- **1:** return one without arbitration or exclusive operations.
- **0:** LDREX the state. If still zero, attempt STREX of -1 and retry failed
  stores. A successful store returns zero. If the exclusive load sees any nonzero
  value, CLREX clears the reservation and execution enters the generic arbitration
  path, even if that value is one or -2.
- **-1 or any other value:** call arbitration and repeat from the ordinary state
  load. The arbitration result is ignored on this path.

Each arbitration uses the freshly loaded global handle, state address, operation
one, count zero, and a zero 64-bit timeout. Its recovered wrapper marshals timeout
words to r4/r5 for SVC `0x22` and restores the caller's values. Wait never reads or
writes object word +4. The source preserves original ARM exclusive instructions
and does not claim portable C synchronization or add a native service policy.

## Evidence and bounded comparisons

Primary: `local/validation/diagnostic-wait-20261011-final-checked/COMPLETE.json`.
The freestanding C11 ARMv6K build uses `-Wall -Wextra -Werror` and produces the
6,104-byte image. **3,170 original/rebuilt pairs pass**, including **45 direct
initializers and 48 direct waits**. All **61 new original instruction sites**
and all twelve sites in the two reused dependencies are visited. Saved Ghidra
membership agrees with the intervals; independent GNU disassembly is retained.
Instruction visitation is not a claim of exhaustive predication or concurrency.

The independent transition oracle predicts ordered ordinary/exclusive reads,
attempted store values and outcomes, actual successful writes, CLREX and handle
loads. Both instruction streams execute their loads, stores and control flow;
only exclusive-monitor success and scheduled competing writes are supplied by
the harness. Whole guarded objects, memory snapshots at each external event,
callee-saved registers and stack restoration are checked. Pending exclusive
prefixes stop immediately before the next LDREX after the failed-store retry
branch, without claiming a return or liveness.

Direct cases cover zero/nonzero modes (including high-bit and all-ones words),
poisoned prior state, successful and failed exchange prefixes, last-loaded-word
return values, all wait-state categories, signed/arbitrary SVC results, changed
exclusive loads both initially and after failed stores, direct-return state
mutations, repeated pending arbitration and changing handles including zero.
The comparison observes **1,188 exclusive attempts, twelve CLREX operations,
490 arbitration boundaries and twelve pending exclusive prefixes** across both
paths. SVC argument checks include all r0-r5 words; the boundary poisons r4/r5 to
exercise wrapper restoration.

The inherited diagnostic/startup/archive/file corpus executes **394 recovered
wait entries across both paths**, including 194 from startup, sixteen from archive
teardown and ten from archive removal. Two persistent setup lifetimes and the
older ownership sequences remain active. Their stack objects are checked as zero
before initialization and {-2, 1} before waiting. Terminal fixtures now stop at
the kernel arbitration boundary, not at the original wait entry. Returning
fixtures supply explicit kernel results/changes and exercise the actual return
chain. They do not prove what the real kernel does for these diagnostic waits.

TLS/kernel replies, sleep and outer locks remain modeled. Manager/pool/registry
storage remains synthetic. Existing explicit UQSUB8 support and the two verified
ignored PLD cache hints are unchanged. Unaligned/unmapped objects, arbitrary
concurrency, exclusive-monitor hardware behavior, unbounded liveness, cache/timing
behavior, full startup/read integration and live G1/G2 remain open.

## Audit and regression

Audit: `local/validation/diagnostic-wait-20261011-audit/COMPLETE.json`.
Five compiled faults are rejected: treating only mode one as nonzero, returning
the stored sentinel instead of the loaded word, storing one instead of -1,
switching the direct-return sentinel to -1, and omitting CLREX.

The previous diagnostic mode passes all **3,077 pairs**, retains its 5,520-byte
size and all twelve compared size/behavior evidence fields. Its binary is not
byte-identical: changing the initializer declaration from void to uint32_t caused
GCC to swap `mov r0, sp` and `mov r1, #1` at rebuilt `0x006014AC` / `0x006014B0`.
The audit proves this exact two-instruction swap is the only binary difference;
the argument values, source behavior and all comparison evidence agree. This
interface-induced scheduling change is explicitly accepted, not hidden by a
weakened hash assertion. All **134 public tests pass**.

Development dev1 failed Java compilation due to a local listing-name collision;
dev2 passed 3,165 pairs. Five final risk probes produce the 3,170-pair corpus.
The first final metadata normalization accidentally renamed a wait-entry count
to `both`; the corrected final-checked run retains the exact binary, comparison
and wait evidence while naming it `recovered_waits_both`. The initial audit stopped
on the explained regression hash change; its successful continuation records
the exact swap. Exact commands/exits are in `jobs.json` and the static scripts.
All Ghidra jobs ran sequentially.

## Reproduction and next independent milestone

```powershell
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --output local/validation/NEW-DIAGNOSTIC-WAIT
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --mutant wait-clrex --output local/validation/NEW-WAIT-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-diagnostic --output local/validation/NEW-DIAGNOSTIC-REGRESSION
python -m unittest discover -s tests
```

Next recover the shared **break/callback dispatch** boundary: wrapper
`0x002BCE9C..0x002BCEA4`, dispatcher `0x002AD90C..0x002AD958`, and consumed SVC
wrapper `0x001526B4..0x001526BC`. The active model is named
`smt4_worker_file_preclose` in `src/resource_worker_file_cleanup.c`, and the same
address backs prefix diagnostics. Inspect the saved static `membership.txt`,
`next-preclose.log`, `next-diagnostic-entry.log` and `next-fatal-record.log`.
The SVC tail has no separate saved Ghidra function object; its two instructions
are present and independently decoded. The last filename is an exploratory label: the actual instructions are SVC 0x3C,
not diagnostic record construction.

The wrapper forces r0 to zero. The dispatcher captures/clears callback slot
`0x0044E450` before invoking it, then tail-calls SVC 0x3C with r1/r2 zero. Its
callback argument transport includes incoming r2 as the sixth stack argument;
inspect that register's caller provenance before selecting the source interface.
Use the existing file-cleanup/prefix oracle in `check_resource_worker_io.py`
(see `resource-worker-file-cleanup.md` and `resource-worker-prefix.md`) to replace
the model with bounded callback and kernel boundaries. Compare null/installed
callbacks, clear-before-call, callback slot mutation, register/stack transport,
returning/terminal SVC fixtures and affected cleanup/prefix paths. Do not count
reused diagnostic/wait or lock source as new recovery. Deferred live gates and
optional extraction/compiler work do not block this independent source target.
