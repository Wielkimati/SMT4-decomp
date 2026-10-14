# Resource-object teardown and pool return

2026-10-08. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategic review and acceptance

All 35
source/tool identities in the prior initializer manifest match at intake; see
`local/validation/pool-teardown-20261008-static/handoff-check.json`. Existing
uncommitted owner, request, initialization and clear work was preserved.

Initialization is complete. The recorded teardown target is the most direct next
source milestone: it replaces the remaining aggregate cleanup models and enables
real node return and reuse through the recovered owner. No reprioritization into
optional extraction, compiler research or port work was warranted. The helper
`0x002A458C` was added because both embedded pools consume it. File disposal,
file teardown, handle access, close IPC and locks were reused, not recovered anew.

Before implementation, acceptance required an ARM build and original/rebuilt
agreement for five ownership slots, cleanup order, failed initialization, pool
heads/counts and successful disposal followed by reuse. The bounded criteria
pass. Diagnostic and kernel behavior, backing storage and live gates remain
explicit limits. No project gate or reference fact changed.

## New recovered contracts

`src/resource_pool_object_teardown.c` adds three entry contracts:

| Original ARM entry and exclusive end | Contract | GCC bytes |
| --- | --- | ---: |
| `0x003567F0..0x00356840` | `smt4_resource_pool_object_dispose` | 88 |
| `0x00356844..0x003568C0` | `smt4_resource_pool_object_teardown` | 328 |
| `0x002A458C..0x002A45E8` | `smt4_resource_pool_base_teardown` | 136 |

These total 552 compiled bytes, including GCC's inlined helper body in the
object teardown. The linked image grows from 4,740 to 5,916 bytes; the remaining
growth is previously recovered file-ownership/service source. Header declarations,
checker hooks, fixtures, build options and symbol metadata support the recovery;
they are not additional recovered game contracts.

Disposal loads the receiver's vtable and calls +0x34, ignoring its return value.
Only after this call does it capture the pool pointer at global `0x0044E654`.
It acquires pool+0x30, writes the old free head into object+0, publishes the object
at pool+0x24, decrements pool+0x2C modulo 32 bits, and releases the same lock.
Zero counts underflow. There is no null check, duplicate-return check, explicit
backing-storage release or global pointer validation.

Teardown clears object+8, changes its vtable to `0x00420948`, then visits the
five words at +0x0C through +0x1C in ascending order. Each nonzero word supplies
a file receiver whose current vtable +0x2C is invoked. Later slots are reloaded
after earlier calls; **the five slot words are not cleared**. Repeated teardown
of an already disposed object is not a supported lifetime established here.

It then processes embedded pool +0xF4 followed by +0xB8. For each it writes
vtable `0x00420B00`, clears the free head at pool+0x24 only when nonzero, and
calls the base teardown. It uses the returned pool pointer to locate the next
pool and finally returns the original object. Other pool metadata, backing
bytes and lock fields are preserved except for the base helper's effects.

Base teardown captures pool+0x0C, writes vtable `0x00420BC0`, and calls diagnostic
`0x002BCE9C` if the captured value was nonzero. It then checks pool+0x10 and
calls the same diagnostic if nonzero. Under an explicitly returning diagnostic
model it reloads pool+0x10. If a list remains, it walks node+4, saving the next
pointer before clearing node+4 and then node+0. After the last node it clears
pool+0x10. An initially/reloaded empty list causes no head-clear store. It returns
the pool pointer. This detaches the list; it neither frees nodes nor releases
backing storage. Acyclic, mapped lists are the compared domain.

All three targets lack saved Ghidra function/instruction objects in the current
project. `static-ghidra.txt` records that absence honestly. Raw GNU decoding
establishes entry/return/literal extents, and the original p-code execution
visits all 74 instruction sites within those extents. Literal words are excluded.
Vtable `0x00420A3C` +0x30/+0x34 is checked against the reference bytes before
comparison. The saved Ghidra project was not annotated or rewritten.

## Integration and model removal

`python tools/check_resource_pool_owner.py --recover-teardown --output local/validation/NEW`
implies `--recover-initialize` and `--recover-request`. It replaces main-object
and file-disposal interception with concrete source and reuses
`smt4_worker_file_dispose` (`0x00356438`), file teardown (`0x00356578`), handle
access (`0x00239CD0`) and file-close IPC (`0x00356D5C`). These previously recovered
contracts are integration progress, not new source recovery. The linked file-open
functions are not executed or claimed by this corpus.

Concrete file disposal sends close IPC for a nonzero handle, reloads the current
vtable for teardown, executes SVC 0x23 for the remaining nonzero handle, clears
the handle and returns the file node to pool `0x004D4358` under recovered locks.
The main-object return follows all file and embedded-pool cleanup. Close kernel
and service errors do not stop disposal. The rebuilt virtual table entries are
relocated to rebuilt functions; their receiver and all memory effects must still
match the independent oracle. Original virtual tables are checked first.

Earlier modes retain their documented cleanup models. This option does not
broaden old evidence or establish complete read-service integration.

## Comparison evidence

Primary: `local/validation/pool-teardown-20261008-final/COMPLETE.json`.
The warning-clean ARMv6K C11 build is **5,916 bytes**. It passes **47 owner pairs
and 78 cleanup pairs**, including **16 direct base-helper pairs** and **four
persistent sequences**. All **74 new original instruction sites** execute.
This is instruction visitation, not a claim about every predication outcome.

Each machine must independently match the ordered-write/full-state oracle.
Expected final objects are not copied into either machine. Persistent sequences
seed once, then repeatedly create, fail or dispose, and create again from actual
returned nodes. The oracle retains output sentinels, returned free-list links,
pool counts and underlying backing bytes between operations. TLS is separately
initialized per top-level call and kernel responses remain scheduled.

The risk-selected corpus covers:

- Loaded and unloaded initialization through request/service failures, short
  header, insufficient capacity, and a negative result at every read position;
  file-pool exhaustion closes the acquired handle and returns the main node.
- All 32 ownership-slot masks, zero/nonzero file handles, all five signed query
  ownership buckets, pool free-head zero/nonzero conditions, and used-count
  values 0, 1, `UINT32_MAX` and `0x80000000` at main disposal.
- Successful return/reuse with restored main/file counts, nested outer locks,
  nested main/file-pool locks, poisoned surrounding bytes, low objects and
  objects at `0xF0000000`, and untouched slot/descriptor/backing data.
- File-close kernel failure, positive kernel status and negative service status;
  scripted service effects changing the current global pool, a later ownership
  slot or the file handle. An explicit alternate virtual teardown changes the
  current pool and returns an unrelated value, which disposal must ignore.
- Empty and one-to-three-node base-helper lists, nonzero active fields,
  diagnostics that leave or clear the list, high-address helpers, and populated
  lists reached through both embedded pools in a complete teardown.

There are 156 concrete file-close IPC executions and 154 concrete file-teardown
handle closes across both machines, plus 54 returning base-diagnostic calls.
The extra pool-exhaustion SVC executions use the inherited owner's checked
close boundary and are not included in the file-teardown close count.

Checks retain full guarded fixtures, preserved stack/input arguments and
callee-saved registers, exact cleanup boundary order/receivers, close command
and handle capture, TLS state, allowed original/built code extents, execution
budgets and exclusive reservation discipline. Initializer/request/query evidence
is additionally retained by unchanged regressions, rather than claiming that
this smaller lifetime corpus replaces their direct boundary coverage.

The first development comparison correctly failed because the new cleanup loop
applied eight-byte public-call stack alignment to an SVC instruction in GCC's
leaf file teardown. The existing file-ownership harness already distinguishes
these: SVC requires word alignment; public function entries require eight.
The integration now uses that established distinction. The failed log remains
local and is not accepted evidence. No recovered source correction was needed.

## Fault checks and regressions

Audit: `local/validation/pool-teardown-20261008-audit/COMPLETE.json`.
Four compiled semantic faults are rejected: skip the fifth ownership slot,
leave a detached link nonzero, increment rather than decrement the main pool
count, and hardcode the main pool instead of loading the current global pointer
after teardown. `negative-checks.json` records the exact assertions and binary
hashes. These faults exercise distinct lifetime, list and reload obligations.

Initializer, request and default-owner regressions preserve their entire
comparison objects and exact binary hashes: respectively 4,740, 3,696 and
3,536 bytes. The initializer retains 106 owner/106 direct initializer pairs;
request retains 132 owner/70 direct request/12 constructor pairs; default owner
retains 84 owner/12 constructor pairs. All 134 public tests pass. See
`regressions.json` and `public-tests.log`. Shared file/lock/clear source was
unchanged; their independent checkers were not repeated. All Ghidra jobs ran
sequentially and all commands finished before handoff.

## Remaining boundaries and next milestone

Virtual reads `0x003564A8`, returning diagnostics `0x002BBD70`/`0x002BCE9C`, and
the explicitly alternate test teardown remain modeled. TLS, SVC responses and
successful exclusives are scheduled. Main/file pools, outer locks, storage,
service globals and callback effects are synthetic. Diagnostic continuation
does not establish that the original diagnostic normally returns. List cycles,
duplicate owned-file aliases, invalid pointers, arbitrary fixture aliasing,
unbounded storage and real concurrency are outside this domain. Counts deliberately
exercise wrapping metadata rather than asserting all such synthetic states
represent valid live allocations. Backing-storage/global startup, live G1/G2,
full ABI/compiler identity, matching and source transfer remain open.

Next recover the **alternate resource caller `0x001270C4..0x00127218` and its
file-wrapper factory `0x003567A4..0x003567E4`**. Static leads are
`local/validation/pool-teardown-20261008-static/next-caller.log`, `vtable.json`,
and the prior initializer's `next-teardown.log` (which includes the factory).
Vtable `0x00420A3C` +0x3C resolves to that factory. The caller uses a distinct
request descriptor shape, invokes +0x3C to wrap the acquired handle, then reuses
the initializer and failure teardown recovered here. The factory's exhausted
pool path closes the handle and preserves caller output; inspect this against
the existing backend-file-open contract, which publishes null on exhaustion.
Batch these two new source contracts with their existing recovered dependency
chain. Extend the owner checker to compare request argument/layout transport,
factory publication/exhaustion, caller failure preservation and persistent reuse.
Do not repeat initialization or disposal as a new milestone.

```powershell
python tools/check_resource_pool_owner.py --recover-teardown --output local/validation/NEW-LIFETIME
python tools/check_resource_pool_owner.py --recover-teardown --mutant teardown-reload --output local/validation/NEW-LIFETIME-NEGATIVE
python tools/check_resource_pool_owner.py --recover-initialize --output local/validation/NEW-INIT-REGRESSION
python tools/check_resource_pool_owner.py --recover-request --output local/validation/NEW-REQUEST-REGRESSION
python tools/check_resource_pool_owner.py --output local/validation/NEW-OWNER-REGRESSION
python -m unittest discover -s tests
```

## Diagnostic register contract repair, 2026-10-13

This section supersedes the old diagnostic-model boundary above for the new
`--recover-teardown-break` mode. Earlier manifests remain historical evidence
for their own modes. This is original-game register-contract recovery, not a
native service replacement or a binary-matching claim.

### Selection and acceptance

The scheduled strategic review verified all 46 identities in the previous
break-dispatch primary manifest. A07 prioritizes faithful source and original/rebuilt comparison; neither deferred
G1/G2 nor optional extraction/compiler work blocks this repair. No completed
break-dispatch or ownership milestone was restarted as new recovery.

Before implementation, acceptance required the incoming/returned r2 contract at
`0x002A458C`, its `0x00356844`/`0x003567F0` callers, both diagnostic predicates,
file disposal and inter-pool transport, execution through the existing dispatcher,
callback payload and returning/terminal comparisons, warning-clean builds,
retained lifetime/alternate regressions and meaningful fault rejection. The
consumed file/lock contracts below were added after a concrete original/rebuilt
failure demonstrated their necessity, not as speculative adjacent recovery.

Static evidence is in `local/validation/pool-teardown-register-20261013-static/`:
`handoff-check.json`, `original-base.log`, `original-teardown.log`,
`original-file-dispose.log`, `original-file-teardown.log`, `original-file-close.log`,
`original-recursive-lock.log`, `original-lock-release.log`,
`original-lock-acquire.log`, `original-owner.log` and `original-alternate.log`.
The expanded executable remains bound to the hash at the top of this report.
The teardown function-object absence was already recorded by the retained
teardown checker; original p-code execution and independent raw ARM disassembly
establish these instruction intervals without modifying the Ghidra database.

### Extended source contracts

There are **nine extended existing contracts, zero newly counted functions**.
All changed bodies are register-sensitive ARM source in their existing C units.
This bounded assembly preserves scratch inputs/outputs that ordinary AAPCS C
returns and virtual-call expressions did not express. It contains named source
calls and reviewed mnemonics, not embedded original binary helpers. Existing
semantic recovery and the break dispatcher are reused.

| ARM interval, exclusive end | Extension |
| --- | --- |
| `0x002A458C..0x002A45E8` | Base teardown carries entry r2 into its first executed diagnostic, diagnostic-returned r2 into a later diagnostic, and returns the final detached node in r2 if it walks a list. |
| `0x00356844..0x003568C0` | Object teardown preserves r2 through slot/virtual-target lookup, consumes each owned-file return, and carries the +F4 helper return into +B8. |
| `0x003567F0..0x00356840` | Object disposal forwards entry r2 through virtual teardown before loading the current global pool. |
| `0x00356438..0x003564A4` | File disposal preserves close/teardown r2 through vtable lookup and node publication, then returns recursive-release r2. |
| `0x00356578..0x003565A0` | File teardown preserves entry r2 when the handle is zero; otherwise it returns SVC 0x23 scratch r2, preserving it while clearing the handle. |
| `0x00356D5C..0x00356D84` | File-close IPC returns kernel scratch r2 unchanged while selecting the kernel/service result in r0. |
| `0x002C3AFC..0x002C3B34` | Already-owned recursive acquisition preserves entry r2. Other paths carry the base-acquisition output and still reread TLS afterwards. |
| `0x002C3A78..0x002C3A98` | Nonfinal recursive release preserves entry r2; final release clears the owner and tail-calls base release. |
| `0x00138FC0..0x00139010` | Base release returns the negation of the successful exclusive load in r2, or arbitration-returned r2 when that signed negation exceeds one. |

The original base helper never sets r2 before either BLNE. Its first diagnostic
receives entry r2, and its second receives the first service's returned scratch
word when both execute. The existing zero-reason wrapper forwards that word as
callback argument six. The dispatcher zeroes r2 before SVC, but the service's
**returned** r2 is independently supplied and must not be assumed zero. The new
comparison checks that the reused compiled dispatcher returns it unchanged.

Each list iteration assigns the current node to r2 before loading its successor
and clearing +4 then +0. The last node therefore becomes the next pool's payload.
If callbacks leave an empty list, r2 remains the latest service return; if neither
diagnostic executes and no list exists, entry r2 survives. Callback-written heads
are reloaded, including replacement and clearing. Object slot words remain intact.

The first connected no-file build passed. The subsequent concrete-file probe
failed honestly at the rebuilt diagnostic: **expected r2=1, actual r2=0**.
`local/validation/pool-teardown-register-20261013-file-probe/comparison.log`
retains that failure. Original base release negates the uncontended held lock
`0xffffffff`, leaving one in r2; the former C build instead left the STREX status
zero there. Nested locks also exposed intervening register allocation in file
node publication and recursive wrappers. The source extensions above remove
those accidental dependencies. Kernel close scratch outputs are separately supplied (distinct high words for
SVC 0x32 and SVC 0x23), independently of the varied entry and break-service
words in the final comparison.

`compiled-sizes.log` records **652 bytes of instruction bodies** across the nine
extended entries, excluding their literal pools. This is the size of extended
existing source, not 652 bytes of newly discovered routines. The three teardown
bodies are 92/124/80 bytes. The final connected ARM image is **5,780 bytes**.
Header declarations, symbol metadata, build mode, oracle and mutation-anchor
updates are supporting integration/tooling, not extra recovered functions.

### Comparison and model removal

Primary: `local/validation/pool-teardown-register-20261013-final-checked/COMPLETE.json`.
The warning-clean pinned ARMv6K build passes **129 original/rebuilt pairs**,
with 308 callback invocations, 636 break SVC boundaries and 64 terminal outcomes
across both machines. All **97 instruction sites** in the three teardown entries
and the reused break chain execute. This is site visitation, not exhaustive
predication or concurrency coverage. `diagnostic-transport.tsv` records pool,
payload, scheduled service r2, callback and terminal boundary for each path;
`connected-results.tsv` and `visited.txt` record cases and instruction membership.

The new mode removes **one active original-address diagnostic model** at
`0x002BCE9C` for connected teardown. It executes the existing wrapper,
dispatcher and SVC wrapper. Callback bodies, kernel results, TLS and successful
exclusive outcomes remain modeled. Earlier owner modes retain their diagnostic
interception boundary; their evidence is not retroactively broadened.

The independent state/write oracle checks both machines separately. Cases cover
zero/nonzero active and list fields, no/one/two-node lists, high object and node
addresses, entry and service r2 varied independently, null/ARM/Thumb callbacks,
captured-slot clearing and replacement, and replacement -> clear -> absent
callback transitions across diagnostics without reseeding. Callback mutations
clear or replace the list. Terminal fixtures stop at the actual SVC boundary,
including after concrete owned-file disposal, with no false unwind claim.

Concrete file cases include first/fifth/all selected ownership slots, zero and
nonzero handles, failed close-kernel status, nonnegative kernel/negative service
status, handle clearing by service effects, same-TLS nested file-pool locks and
fresh uncontended locks. Other service effects change a later owned slot or the
main return pool. Full guarded fixtures, ordered writes, TLS, source PC bounds,
returned r0/r2 where applicable, stack guards/alignment and returning callee-saved
registers are checked. Retained lifetime cases additionally keep all 32 ownership
masks, count wrap, failure cleanup and persistent return/reuse.

### Caller boundary and remaining dependencies

The connected entry boundary is **explicit supplied r2 at base/object teardown
or object disposal**. Owned files then execute recovered close, teardown,
publication and locks; their observed returns are not replaced by a model.
Object-disposal r2 after its final pool return is not consumed by a callback in
this package and is not claimed as an independently verified result.

The unchanged owner `0x002ADCD8` and alternate owner `0x001270C4` pass their
retained initialization/failure/lifetime domains. Static instruction traces show
they preserve scratch r2 between the last callee and virtual disposal, but their
normal constructed/initialized embedded pools have zero +0C/+10 diagnostic
predicates. Thus that incoming word is dead on their retained cleanup paths.
This package does **not** claim their complete initializer/request scratch chain
for callbacks that corrupt/populate those fields before failure disposal. No
owner/alternate source or stack frame was changed; the alternate request's
self-pointer and actual exposed byte remain checked by its regression.

Connected file-pool locks start either unowned with recursion count zero or
already owned by the scheduled TLS with a nonzero nested count. In the former
case base acquisition's scratch output is overwritten by final base release;
in the latter the base acquisition is skipped. The full scratch-r2 contract of
base acquisition `0x001464F8` remains outside this domain, particularly inconsistent
owner/count states and acquisition contention. Its existing memory/lock behavior
is retained and regressed. No real concurrency, invalid pointer, cyclic list,
arbitrary alias, reentrant callback body, full startup/read integration, hardware
or live-game agreement is inferred. Registry/pool storage remains synthetic.
G1/G2 and downstream gates remain open.

### Validation closeout

Audit: `local/validation/pool-teardown-register-20261013-audit/COMPLETE.json`.
All seven retained comparison objects are identical to their accepted historical
baselines listed in `regressions.json`; no behavioral assertion was dropped.
The base/recursive lock comparisons additionally assert release r2 against the
independent lock oracle, including arbitration scratch output, and preserved r2
on wrapper paths that do not call the base lock.

| Regression suffix under `local/validation/pool-teardown-register-20261013-` | Current bytes | Retained evidence |
| --- | ---: | --- |
| `teardown/COMPLETE.json` | 5,676 | 47 owner + 78 cleanup pairs; 4 persistent sequences; 74 teardown sites |
| `alternate/COMPLETE.json` | 6,124 | 78 alternate-owner + 16 factory + 22 cleanup pairs; actual request-byte equality |
| `break/COMPLETE.json` | 5,204 | Complete connected worker, direct break and caller corpus; binary identical |
| `prefix/COMPLETE.json` | 5,100 | Complete retained prefix/worker corpus; binary identical |
| `wait/COMPLETE.json` | 6,136 | 3,170 retained file-owner/diagnostic-wait pairs |
| `recursive/COMPLETE.json` | 376 | 164 wrapper cases, 4 pending prefixes, 2 persistent sequences |
| `base-lock/COMPLETE.json` | 288 | 3,092 acquisition + 1,064 release cases, 28 pending prefixes |

Other changed binaries are not claimed byte-identical. The current primary
`final-checked/COMPLETE.json` reproduces the first final primary binary and its
entire comparison object. Its source/tool fingerprints match the current files.
A verified local snapshot of the earlier positive pool checker is retained in
the static directory: its only subsequent changes strengthen the negative
mutation selection/anchors, not the positive build or behavioral oracle. This
accounts for the earlier teardown/alternate manifest tool identities without
rewriting those manifests or rerunning unchanged positive source unnecessarily.

`negative-checks.json` records eleven **compiled behavioral rejections**: zero
entry r2, restoring stale entry r2 after the first returning diagnostic, skipping
the fifth slot, leaving a detached link, incrementing the return count, caching
the global destination pool, caching the file vtable, caching TLS, clearing the
owner after base release, saturating the recursive count, and treating positive
kernel status as failure in open/close IPC. Existing mutation semantics were
retained across the source representation change. The initial count mutant
matched both `#1` and `#184` and stopped at its anchor check; that run is excluded.
The narrowed instruction anchor passes compilation and is behaviorally rejected
in `count-checked/NEGATIVE.json`. Compile/launch failures are not counted.

`arm-consumers.json` records warning-clean compilation of **all 23 ARM C units**
whose dependency lists include any changed header. `final-python-checks.json`
and `public-tests-final.log` record Python compilation and **134 passing public
tests** after the final tool edits. These are build/integration support, not
additional source recovery. Every launched command finished; Ghidra jobs ran
sequentially.

Reproduction (choose fresh output directories):

```powershell
python tools/check_resource_pool_owner.py --recover-teardown-break --output local/validation/NEW-TEARDOWN-BREAK
python tools/check_resource_pool_owner.py --recover-teardown-break --mutant teardown-entry-r2 --output local/validation/NEW-ENTRY-R2-NEGATIVE
python tools/check_resource_pool_owner.py --recover-teardown-break --mutant teardown-return-r2 --output local/validation/NEW-RETURN-R2-NEGATIVE
python tools/check_resource_pool_owner.py --recover-teardown --output local/validation/NEW-TEARDOWN
python tools/check_resource_pool_owner.py --recover-alternate --output local/validation/NEW-ALTERNATE
python tools/check_resource_recursive_lock.py --output local/validation/NEW-RECURSIVE
python tools/check_resource_lock.py --output local/validation/NEW-BASE-LOCK
python tools/check_resource_worker_io.py --recover-break --output local/validation/NEW-BREAK
python tools/check_resource_worker_io.py --recover-prefix --output local/validation/NEW-PREFIX
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --output local/validation/NEW-WAIT
python -m unittest discover -s tests
```

### Next independent source milestone

Return to **prefix registry initialization**: Thumb helper
`0x002C5FAC..0x002C5FCE`, ARM record initializer `0x003561F0..0x00356204`, and
startup slice `0x003F3570..0x003F3584` within `0x003F3568`. Follow
[the planned registry milestone](resource-break.md#planned-milestone-after-the-teardown-repair)
and [prefix recovery](resource-worker-prefix.md). Extend the existing worker
`--recover-break` chain with an explicit initialization mode replacing its zero
key/backend fixture. Compare constructor/count/stride transport and order,
original-base return, preserved +12..+15 bytes and initialization feeding
register/open/remove/reuse. Broader startup pool/lock setup remains outside that
slice; do not repeat the completed break or teardown work.
