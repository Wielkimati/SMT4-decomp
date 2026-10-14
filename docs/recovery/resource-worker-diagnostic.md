# Diagnostic record and delivery

2026-10-11. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

2026-10-13 extension: [delivery consumed return recovery](resource-delivery-return.md)
extends `0x002AD7E8` to preserve r0/r2 and removes its model from create/chain
`--recover-result-diagnostic`. Lower lock/wait outcomes remain explicit; this
report's earlier source counts and ordinary-return evidence keep their historical
scope. The wait source's consumed r2 remains the next independent extension.

## Strategy review and acceptance

The setup milestone is complete. Its primary manifest's source/tool hashes and
the pinned executable were verified before editing; results are in
`local/validation/diagnostic-20261011-static/handoff-check.json`. It replaces an active shared dependency in startup and archive
failure paths. Optional extraction, compiler research and live gameplay do not
unblock it, so no queue reprioritization was needed.

Acceptance selected before implementation: confirm ARM membership, build source
with warnings as errors, and compare record layout/order, IPC payload, failure
publication, captured/reloaded handles, type-dependent direct return or lower
wait, finite retry sequences, and connected startup/archive failures. Inspection
showed the consumed copy was a small self-contained routine; it was included
in the same package to execute the complete payload transport. Lower wait and
kernel behavior remain explicit boundaries. These bounded criteria pass; this
does not close G1/G2 or complete whole-game startup.

## Recovered contracts and model replacement

New `src/resource_worker_diagnostic.c` / `.h` provides five contracts:

| Original ARM range (exclusive end) | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x002BBD70..0x002BBD98` | `smt4_worker_diagnostic` | 48 |
| `0x002AD7E8..0x002AD8F0` | `smt4_diagnostic_deliver` | 300 |
| `0x00144900..0x00144918` | `smt4_diagnostic_process` | 20 |
| `0x00146964..0x0014699C` | `smt4_diagnostic_request` | 56 |
| `0x002BCFAC..0x002BD020` | `smt4_diagnostic_copy` | 328 |

2026-10-13 source sharing: the unchanged `smt4_diagnostic_copy` body now lives in
`src/resource_aligned_copy.c` / `.h`, reused by the new table-copy entry.
The diagnostic header includes its declaration and the diagnostic checker links
the shared unit. This does not add a recovered contract or alter this report's
historical scope. The affected diagnostic-wait regression passes 3,170 pairs,
with complete comparison/diagnostic/wait objects identical to its prior baseline;
the 6,136-byte binary differs. See [copy recovery](table-resource-copy.md) and
`local/validation/table-copy-20261013-diagnostic-regression/COMPLETE.json`.

The five contracts total **752 compiled bytes**. Four alignment bytes make the
image growth 756 bytes. Linker aliases bind the existing backend, startup and
pool-accessor diagnostic call names to the recovered two-argument wrapper;
startup's extra r2 is ignored by the original. Alias symbol sizes are not new
code sizes. `compiled-sizes.txt` and the rebuilt disassembly retain this distinction.

Optional `--recover-diagnostic` implies `--recover-setup` and removes **one active
diagnostic call model**, shared by those callers. Delivery, process, request and
copy were previously hidden behind it, not four additional intercepted calls.
Connect `0x001382CC` and delay `0x002BB4F0` are reused source. Builder/oracle,
header comments, metadata and documentation changes are supporting integration,
not additional recovered game contracts. Earlier modes retain their boundaries.

The wrapper writes global record `0x004D4200` in this order: byte +1 zero,
halfword +2 `0xBCA3`, byte +0 zero, site word +8, result word +4. Incoming r2
does not participate. Remaining bytes survive, except process word +12 when
delivery executes its process SVC wrapper. The wire record is 128 bytes.

Delivery locks `0x004D4280`, then checks handle `0x0044E608`. A nonzero handle
skips connection. Otherwise the recovered SVC 0x2D wrapper connects to `err:f`
at `0x004259A0`, publishing returned r1 even on failure. Constants at
`0x00407F9C` are process handle `0xFFFF8001`, reset word zero and that name pointer.
Any nonnegative connect status enters delivery, even with a zero returned handle.

SVC 0x35 receives the process output pointer and handle in r0/r1. Its wrapper
always stores returned r1, including when r0 is negative. Delivery ignores its
status, then captures the current diagnostic handle in a stack word. Request
writes command `0x00010800`, executes the recovered 128-byte copy into TLS+0x84,
loads the service word and issues SVC 0x32. A negative kernel result returns
directly; otherwise it returns command word one. Delivery ignores this result,
reloads the global handle and closes it via SVC 0x23 if nonzero. It then loads
the reset word from the constants and stores it to the global, regardless of
close status. It does not close the stale captured request handle.

Only exact connection status `0xD0401834` with record type two retries. Delay
5,000,000 occurs while the lock is held, followed by release and a new acquisition.
The next iteration reloads handle and record state; a nonzero handle published
by the failed connection can therefore bypass another connection. There is no
original retry limit. The fixtures exercise finite scripts, not unbounded liveness.

Other paths release the lock, then reload record type. Types two and five return
their type value directly. Other types zero a two-word stack object, call
`0x002C5470` with mode one, then call `0x002C367C` on that same object and retain
its result if it returns. The fixture models initialization as words `{-2, 1}`,
consistent with static initializer/base-lock evidence. Wait returns, mutations
and terminal stops are explicitly modeled at the lower wait boundary. The old
returning-diagnostic probes now reach this boundary through actual record,
connect, process, copy, request, close and routing instructions. They do not
prove real blocking/termination or kernel behavior.

The copy is not a memmove. It loads each 32-byte batch before storing it, then
handles 16-, 8- and 4-byte batches, followed by a two/one-byte tail whose loads
precede its stores. It returns the destination end, not the starting pointer.
Compared domains include word-aligned disjoint and overlapping ranges, lengths
0..160 selected around batch/tail boundaries, and the consumed 128-byte IPC copy.
Unaligned word accesses, wrapping extents, invalid pointers and concurrent memory
changes are outside the evidence.

## Validation evidence

Primary: `local/validation/diagnostic-20261011-final/COMPLETE.json`.
The freestanding C11 ARMv6K build uses `-Wall -Wextra -Werror` and produces a
**5,520-byte** image. All **3,077 original/rebuilt pairs** pass. New direct cases
comprise 8 record wrappers, 116 deliveries, 10 process wrappers, 10 requests and
140 copies. All **125 new original instruction sites** are visited. The generic
comparison's older `new_instruction_addresses=94` field still describes file
ownership; use `diagnostic.json` for this package's sites and modeled boundaries.

Checks preserve whole guarded records, globals and command buffers; compare
record store addresses, widths, values and order; validate boundary argument
words and memory before/after every model; and require callee-saved registers,
stack restoration and execution-domain guards. Cases exercise independent
status/output signs, absent IPC replies, zero/high handles, process/request/lock
mutations, post-release type changes, all single-bit changes to the retry status,
and multiple finite retry outcomes. Overlap cases expose batch staging rather
than accepting generic byte-copy behavior.

Connected inherited startup/archive/file lifetimes execute the recovered wrapper.
Across both paths there are 194 lower-wait entries from startup calls, 16 from
archive teardown, 10 from archive removal, 26 from file-open callers, 14 from
concrete backend file-open calls, 12 from file-handle accessors, four from
descriptor registration and ten from the service accessor. The two persistent
setup lifetimes and earlier persistent ownership sequences remain active; one
setup sequence includes registration failure and a modeled returning lower wait.
These are reused sequences, not new lifetime contracts. Direct and integrated
cases together execute 458 diagnostic IPC requests and 458 process SVCs across
both paths, plus 394 lower waits and ten retry sleeps.

Ghidra's `HintPreloadData` userop is unsupported. The harness ignores it only at
verified original PLD sites `0x002BCFBC` / `0x002BCFD4`, checking encoding
`0xF5D1F040`. The 1,369 hints have no modeled architectural data result; cache
and timing effects are not compared. Actual copy loads/stores/control flow
execute. Existing acquisition UQSUB8 host instruction support remains explicit.
No original binary helper executes on the rebuilt path.

Audit: `local/validation/diagnostic-20261011-audit/COMPLETE.json`.
Five compiled faults are rejected: wrong record magic, stale close handle,
wrong retry type, suppressing process output on failure, and a 124-byte payload.
The setup regression retains its exact **4,764-byte** binary and all twelve
compared binary/evidence fields. All **134 public tests pass**. Exact commands
and exits are in `jobs.json`; all Ghidra jobs run sequentially.

Development outputs are not acceptance records: dev1 exposed a Java local-name
collision; dev2/dev3 identified the unsupported PLD userop; dev4 passed all
3,077 pairs but failed aggregate request accounting because the new IPC category
was absent from the sum. The final check includes diagnostic requests and still
requires one TLS read per request. No source correction or weakened behavioral
assertion was needed for those harness failures.

TLS, kernel replies, sleep, locks and the two lower waits remain modeled. Manager,
pools, registry and backing memory are synthetic. Initial lock construction,
concurrency, real service interpretation, full startup/read integration, timing,
unbounded retries and live G1/G2 remain open.

## Reproduction and next independent milestone

```powershell
python tools/check_resource_worker_file_owner.py --recover-diagnostic --output local/validation/NEW-DIAGNOSTIC
python tools/check_resource_worker_file_owner.py --recover-diagnostic --mutant diagnostic-reload --output local/validation/NEW-DIAGNOSTIC-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-setup --output local/validation/NEW-SETUP-REGRESSION
python -m unittest discover -s tests
```

Next recover **diagnostic wait initialization and wait**:
`0x002C5470..0x002C54A4` and `0x002C367C..0x002C373C`. They are the remaining
active lower call models on type-zero diagnostic failures. Saved membership
and instruction leads are in `diagnostic-20261011-static/membership.txt`.
Reuse already recovered base-lock initialization `0x00138F44` from
`src/resource_pool_initialize.c` and arbitration wrapper `0x002A88FC` from
`src/resource_arbitration.c`; do not count those as new recovery. See
`docs/recovery/resource-pool-initialize.md` and `resource-arbitration.md`.

The initializer sets the +4 base lock to one and exclusively exchanges word zero
to -2 for nonzero mode, or -1 for zero mode. Wait distinguishes -2, -1, zero, one
and other values, uses arbitration handle storage `0x00471B58`, and executes
exclusive transitions/CLREX plus arbitration operation one with zero timeout.
For -2 it returns after arbitration; other pending paths may loop. Extend the
diagnostic fixture with an explicit mode that executes these routines, tests
bounded exclusive failures and arbitration state changes, and compares connected
type-zero startup/archive failure paths. Keep kernel arbitration and concurrency
modeled, and inspect return-register behavior before choosing the source signature.
This is a new source milestone; do not repeat diagnostic delivery or setup.
