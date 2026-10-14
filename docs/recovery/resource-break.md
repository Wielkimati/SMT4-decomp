# Break callback dispatch

2026-10-11. Project-authored instruction recovery against EU base v0 expanded
executable SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategic review and acceptance

All 46 source/tool identities in that
wait manifest matched before this package. The older prefix manifest has seven
shared files changed by intervening recovery; a fresh pre-edit prefix baseline
is retained rather than treating that historical manifest as today's inputs.
See `local/validation/break-dispatch-20261011-static/handoff-check.json`.

This target removes a live game-code model shared by file cleanup and prefix
errors, meeting the A07 source/comparison priority. No reprioritization to
extraction, compiler research or port implementation is needed. G1/G2 live
requirements remain deferred and open.

Acceptance chosen before implementation: verify the three ARM intervals, recover
the callback slot capture and clear-before-call, all six callback words (including
incoming r2), callback-written slot changes, SVC r0/r1/r2, explicit returning and
terminal fixtures, and the cleanup/prefix/worker caller transports. Require a
warning-clean build, original/rebuilt comparisons with guarded state, meaningful
fault rejection and affected regressions. Callback bodies and kernel outcomes
remain models; no hardware or real termination policy is inferred.

## Contracts and caller provenance

| Original ARM interval, exclusive end | Source contract |
| --- | --- |
| `0x002BCE9C..0x002BCEA4` | `smt4_worker_file_preclose`, also named `smt4_worker_prefix_diagnostic` |
| `0x002AD90C..0x002AD958` | `smt4_break_dispatch` |
| `0x001526B4..0x001526BC` | `smt4_break_svc` |

The first entry forces r0 to zero and branches to the dispatcher. The dispatcher
captures callback word `0x0044E450` once. If nonnull, it first stores zero into
that slot, then calls the captured target with `{reason, 0, 0, 0, 0, incoming_r2}`.
Incoming r1 is ignored. After the callback, it retains any replacement written
to the slot, restores the reason and calls SVC `0x3C` with `{reason, 0, 0}`.
The SVC wrapper contains only SVC and BX LR; it has no separate saved Ghidra
function object. Its instruction bytes must be independently checked. Returned
r0 is passed through if the service returns; a nonreturning service is an explicit
fixture boundary, not a source `noreturn` assumption.

The recovered callers expose a register dependency hidden by the old declarations:

- Prefix registration `0x002B5E8C..0x002B5EAC` leaves the sign-extended eighth
  input byte in r2 before the overlong-name diagnostic.
- Prefix removal `0x002C405C..0x002C4084` leaves loop index eight in r2.
- Cleanup `0x002BB824..0x002BB83C` leaves entry r2 untouched before diagnostics.
  Its primary entry and deleting destructor likewise forward that word.
- Worker I/O `0x0011401C..0x00114044` leaves lock release's scratch r2 untouched.
  The source explicitly captures that register at the existing external call;
  this does not recover the lock implementation or infer its output value.

The C signatures carry the ignored second word and callback-visible third word.
The prefix helper keeps the distinct registration/removal payloads despite its
shared normalization implementation. These are extensions to existing recovered
contracts, separate from the three new routines. Builder modes retaining the
old diagnostic model retain that boundary.

The new source is **104 compiled bytes**: zero-reason wrapper 12, dispatcher 84
(including its address literal), and SVC wrapper 8. The prefix name is a linker
alias for the same zero-reason entry, not another recovered routine. Six existing
caller contracts are extended: the two cleanup entries, destructor, prefix
registration/removal, and adapted worker I/O region. Their compiled source and
shared normalization helper add another 48 bytes. The full image is **5,204
bytes**, versus 5,052 in the fresh prefix baseline; 16 bytes remain compiler
rodata. `compiled-sizes.log` and `size-changes.json` in the static directory
separate these changes. GCC is a behavioral toolchain, not a matching claim.

`--recover-break` implies the existing prefix chain. It replaces **one active
original-address call model**, exposed under the two historical preclose/prefix
names. Source executes through the callback dispatch and SVC wrapper. The
builder, comparison hooks, symbol records and transitive header fingerprints
support these contracts; they are not additional recovered game behavior.

## Bounded dependencies

Callback bodies and kernel results remain scripted models. Fixtures permit null,
ARM and Thumb callback targets, callback-slot replacement/clearing, and selected
cleanup-handle mutations. The actual BLX target and decoding mode are observed;
the callback body itself is not executed source. SVC is intercepted at its exact
instruction, with all three argument words checked. Returning fixtures supply
r0 and scratch clobbers, then execute BX LR. Terminal fixtures stop at that
boundary without a return or real kernel-termination claim. Instruction-site
visitation includes this modeled SVC boundary.

Worker lock release still supplies its scratch r2 through a model. Connected
checks vary that output; they do not establish the real release routine's full
register contract. The adapted I/O domain keeps the same object through close,
or lets the backend clear the descriptor's object pointer. Its final destructor
sees a cleared or tag-only handle, so its diagnostic payload is dead and the
typed call supplies zero. A callback replacing the descriptor with a different
tagged object would need the post-service scratch-register chain recovered;
that scenario is explicitly outside this region's retained domain. Direct
destructor probes cover selected full-width supplied r2 values and tagged handles.

Registry/pool storage remains synthetic; backend open/close/disposal, allocation,
locks, OS file services and other diagnostic addresses retain their inherited
modeled boundaries. Invalid callback pointers, unmapped/unaligned objects,
arbitrary callback reentrancy/concurrency, service timing, full startup/read
integration and live G1/G2 remain open. The break source adds no native service
replacement, full game build or port implementation.

## Validation

Primary: `local/validation/break-dispatch-20261011-final-checked/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K build passes **2,304 connected worker
pairs**, the complete inherited direct corpus, **72 direct break pairs**, nine
additional cleanup payload pairs and twelve additional prefix payload pairs.
One persistent three-call callback replacement/clear/no-callback sequence runs
on each implementation without resetting the slot between calls. All **23 new
original instruction sites** are visited (1,245 combined original addresses).

The oracle observes callback slot reads and writes, target/mode and all six
argument words, SVC argument words and returned r0, guarded slot/object/table
storage, stack restoration, callee-saved registers and ordered call snapshots.
Direct cases cover zero/one/high-bit/all-ones reasons and results, null and
installed callbacks, ARM/Thumb targets, callback replacement/self-reinstallation/
clearing, and explicit terminal service outcomes. Caller probes cover cleanup
payloads zero/high-bit/all-ones, prefix byte `0x7F/0x80/0xFF`, and removal's index
eight. Connected worker fixtures vary release r2 among zero, one, high bit and
all ones. Existing handle replacement, backend poison, close/clear/release order
and pre-publication prefix assertions remain active.

Across both instruction paths the checker observes **602 callback invocations,
684 SVC boundaries, 108 terminal paths and 534 integrated break calls**. The
integrated count includes worker, cleanup and prefix probes; it is not solely
the outer worker loop. Exact direct memberships and totals are in the primary
manifest, `break-caller-summary.json` and `original-break-ghidra.txt`. There is
no original binary helper execution on the rebuilt path.

Audit: `local/validation/break-dispatch-20261011-audit/COMPLETE.json`.
Five compiled faults are rejected at the intended assertions: failure to clear
the callback slot, altered callback word six, failure to force reason zero,
nonzero SVC word two, and the wrong removal payload. The audit records exact
failure reasons, binaries and commands; compile/launch errors are not accepted
as fault rejection. All **134 public tests pass** with captured subprocess exit
zero. The first PowerShell test command reported a shell error for stderr despite
the tests reporting OK; the directly captured subprocess run removes that ambiguity.

The retained prefix mode passes all 2,304 worker pairs and its complete direct
corpus in a **5,100-byte** image. Its comparison changes are limited to
the image size and cleanup maximum instruction count (27 to 28); all other
comparison fields agree exactly with the fresh pre-edit baseline. The old prefix
baseline itself reproduces the historical prefix binary and complete comparison
object exactly, despite intervening shared-file edits.

The retained completion/outer-loop regression passes **4,608 scenarios** and
all existing gates, including 20,736 worker-pass comparisons and 73,728 node
visits across both paths. The retained diagnostic-wait mode passes **3,170 pairs** in a
**6,136-byte** image, with unchanged diagnostic-wait evidence and retained
comparison gates. These interface-affected regression binaries are not claimed
byte-identical to their pre-change versions. Exact field comparisons are in
`regressions.json`; no behavioral gate or older model boundary was weakened.

Development dev1 exposed an incorrect CPSR-based Thumb-mode assertion; the
checker now reads Ghidra's decoding context. Dev2 passed all instruction
comparisons but its completion wrapper omitted the new 23 sites from the expected
total. Final passed the expanded corpus. The first clear-slot fault triggered
the intended store assertion, wrapped by Ghidra in `PcodeExecutionException`;
the result classifier required a case-context exception that was missing. The
checked rerun corrects that context, repeats the full corpus, and retains an
identical ARM binary and comparison object. These are checker corrections,
not recovered-source fixes. Failed development outputs remain local for audit.

All Ghidra jobs were sequential on the authoritative read-only project. All
started commands finished. No commit or publication was made.
That validation sequence and this handoff
were completed; no additional recovery target was started. The observation is
recorded in the static directory's `stop-observation.json`.

```powershell
python tools/check_resource_worker_io.py --recover-break --output local/validation/NEW-BREAK
python tools/check_resource_worker_io.py --recover-break --mutant break-clear --output local/validation/NEW-BREAK-NEGATIVE
python tools/check_resource_worker_io.py --recover-prefix --output local/validation/NEW-PREFIX-REGRESSION
python tools/check_resource_worker_completion.py --recover-loop --output local/validation/NEW-LOOP-REGRESSION
python tools/check_resource_worker_file_owner.py --recover-diagnostic-wait --output local/validation/NEW-WAIT-REGRESSION
python -m unittest discover -s tests
```

## Next task: pool teardown diagnostic register recovery

**Resolved within the documented domain on 2026-10-13.** See
[the register-contract repair](resource-pool-object-teardown.md#diagnostic-register-contract-repair-2026-10-13),
`local/validation/pool-teardown-register-20261013-final-checked/COMPLETE.json`
and `local/validation/pool-teardown-register-20261013-audit/COMPLETE.json`.
The following review is retained as historical motivation and acceptance criteria;
its broken-build statements describe the pre-repair state. Prefix registry
initialization below is again the next independent milestone.

The break package's
recorded comparisons above remain evidence for their stated domains. They did
not rerun the pool teardown/alternate-owner builds after changing the shared
diagnostic declaration. Those current builds are broken, and the missing caller
register contract is now the first task before registry initialization. This is
a source-recovery requirement, not permission to replace behavior with a model.

### Reproduced regression and evidence

`src/resource_pool_object_teardown.c` calls `smt4_worker_prefix_diagnostic()`
twice, but `resource_break.h` now declares three arguments. The header is reached
through the existing backend/prefix/file-open/I/O includes. The teardown source
and its comparison script still match their historical teardown manifest; the
shared declaration changed. The break audit covers prefix, completion/outer-loop
and diagnostic-wait regressions, omitting this consumer. The 134 public tests
pass but do not compile these ARM units.

Reproduction: `python tools/check_resource_pool_owner.py --recover-alternate
--output local/validation/NEW-TEARDOWN-REVIEW` currently fails during compilation
with two "too few arguments" errors. Existing evidence:

- `local/validation/review-20261011-pool-alternate/build.log` and
  `build-command.json`: failing full alternate-owner build.
- `local/validation/review-20261011-pool-alternate/source-syntax-checks.json`:
  17 of 18 changed C files pass; teardown is the sole failure.
- `local/validation/pool-teardown-20261008-final/original-pool-base-teardown.log`
  and `original-object-teardown.log`: instruction-level starting points.
- `local/validation/break-dispatch-20261011-final-checked/`:
  `original-break-zero-disassembly.log`, `original-break-dispatch-disassembly.log`
  and the existing dispatcher comparison evidence.

The local experiment under
`local/validation/review-20261011-teardown-investigation/` gave the old modeled
call a separate symbol and rebuilt both affected images. Its three teardown
routines are byte-identical to their historical versions, proving only that this
would restore the old bounded build. **The user rejected this workaround.** Its
`RESULT.json` and candidate source are investigation artifacts, not an accepted
fix, recovered callback contract, or renewed behavioral validation. Do not adopt
the alias or report this task complete on that basis.

### Instruction-backed starting point and scope

Use the pinned EU base hash at the top of this report and recheck these ARM
intervals against the original bytes. Base teardown `0x002A458C..0x002A45E8`
does not assign r2 before either conditional BL to `0x002BCE9C`, at `0x002A45A4`
and `0x002A45B0`. Therefore the first executed diagnostic receives the entry r2
unless an earlier diagnostic executed; a second diagnostic after a returning
first one receives its returned scratch r2. The zero-reason wrapper preserves
that payload, the dispatcher exposes it as callback word six, and the dispatcher
sets r2 to zero before SVC. The returned kernel r2 must not be assumed zero.

The base helper subsequently writes r2 with each current list-node address at
`0x002A45C4`. That return-register effect may feed the second embedded pool in
object teardown `0x00356844..0x003568C0`, which visits +0xF4 then +0xB8. Trace
empty-list, detached-list, skipped/returning diagnostic paths and intervening
virtual file disposal. Include disposal `0x003567F0..0x00356840` and the consumed
owner/alternate-creation callers wherever their scratch outputs are observable
by this callback. Record the precise supported entry boundary and provenance of
each value; a compiler's incidental register allocation is not evidence for it.

Reuse `src/resource_break.c` and the existing owner/lifetime source. Extend the
recovered caller/return contracts in C or narrowly scoped ARM assembly as the
instructions require. Do not guess extra C arguments, pass zero for an unknown
payload, cast away the declaration, suppress compiler checks, or introduce a
renamed modeled call to bypass recovery. Older checker modes can retain their
documented interception scope, but must build against the corrected source. Add
an explicit connected comparison mode if needed to execute the already recovered
dispatcher through the teardown callers; do not relabel older evidence as covering
that behavior. Callback bodies, kernel responses and genuine remaining external
boundaries stay explicit, with varied outputs rather than silently fixed values.

### Acceptance and return to the planned queue

Before closing this repair:

1. Bind changed source contracts to original addresses/instructions, including
   incoming r2, returned scratch r2 and list-walk effects consumed by later calls.
   Document residual dependencies and any bounded domain. Preserve the alternate
   request's self-reference and exposed byte when changing stack frames.
2. Execute original/rebuilt teardown through recovered break dispatch. Compare
   both diagnostic predicates, independently varied entry and post-service r2
   values, all six callback arguments, null/ARM/Thumb callbacks, callback slot
   replacement/clear behavior, returning and terminal outcomes, list mutation/
   reload and both embedded pools. Assert expected payloads from independent
   instruction evidence rather than copying the rebuilt state into the oracle.
3. Retain guarded state, cleanup order, owned-file disposal, list detachment,
   pool return/reuse, stack and callee-saved-register checks. Reject meaningful
   compiled faults such as zeroing entry payload or reusing the initial payload
   after a diagnostic return. Compile/launch failures are not fault rejection.
4. Rebuild and run retained `--recover-teardown` and `--recover-alternate` owner
   modes, the new connected mode, and affected break/prefix callers; select any
   additional regressions from actual interface dependencies. Run the public
   suite and an ARM compilation check covering all consumers of changed headers.
   A build-only check supports recovery and does not establish behavior coverage.

Once the repair is behavior-verified, return directly to **prefix registry
initialization** below. No
source repair, new recovered contract, passed behavioral gate, or commit is
claimed by this documentation update.

## Planned milestone after the teardown repair

Completed 2026-10-13 within the bounded slice below; see
[registry initialization](resource-registry-initialize.md) for source and
comparison evidence. The original plan follows.

Recover **prefix registry initialization**, replacing the zero key/backend
initialization fixture used before registration. Bounded source targets are
Thumb array initialization `0x002C5FAC..0x002C5FCE` and ARM record initializer
`0x003561F0..0x00356204`, with the consumed startup slice
`0x003F3570..0x003F3584` inside the broader constructor at `0x003F3568`.
The original startup loads record initializer `0x003561F0`, table `0x004D43E0`,
stride 16 and count 32, then BLX-calls the Thumb helper. The initializer clears
only record words +0/+4/+8, preserving flags and padding at +12..+15. The helper
returns the original base, skips a null constructor, and otherwise invokes it
count times while advancing by the supplied stride.

Static leads: `next-array-initialize.log`, `next-registry-record.log`,
`next-registry-startup.log` and `next-registry-literals.json` in
`local/validation/break-dispatch-20261011-static/`. These are next-task static
findings, not recovered contracts. The primary run's
`next-registry-membership.txt` confirms the saved Thumb helper interval and the
absence of separate saved startup/record function objects; verify their bounded
instruction membership/mode before source implementation. The full constructor includes
pool/lock initialization after this slice and is outside the proposed boundary.

Extend `python tools/check_resource_worker_io.py --recover-break --output
local/validation/NEW-REGISTRY-INIT` with an explicit initialization mode. Compare
zero/nonzero count, null/ARM/Thumb constructors, stride/base transport, callback
order, original-base return, preserved record tail bytes, and initialization
feeding register/open/remove/reuse on the same storage. Keep constructor bodies
modeled except for the recovered record initializer and retain deferred live
gates. Read the prefix report as well as this report. After closing the missing
teardown caller contract above, continue this registry milestone without
restarting completed break, diagnostic wait, diagnostic delivery or ownership
recovery.
