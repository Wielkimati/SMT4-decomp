# Connected service startup

2026-10-11. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategy review and acceptance

Before implementation,
acceptance required an ARM build and controlled original/rebuilt agreement for
early return, accepted/error statuses, returning/terminal diagnostics, global
reload/publication, exact IPC order, untouched memory and persistent registration.
Those bounded criteria pass; live G1/G2 and full startup remain open.

The initial review verified all 26 preceding initialization manifest hashes and
the pinned executable: `local/validation/service-startup-20261011-static/handoff-check.json`.
The symbol cross-check then corrected a stale assumption in the partial handoff:
`0x002BBD3C` was already recovered as `smt4_resource_pool_query_service` in
`src/resource_pool_query.c`, with evidence in
[pooled object initialization](resource-pool-object-initialize.md). The final
implementation reuses that unchanged source, rather than counting or retaining
a duplicate. This package adds **three new contracts**, and integrates one existing
accessor. No older intercepted game-call model is newly removed: these startup
entries were absent from the older file-owner modes.

## Recovered source and reused dependencies

New `src/resource_worker_service_startup.c` / `.h`:

| Original ARM range, exclusive end | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x0010F5B8..0x0010F664` | `smt4_worker_service_startup` | 228 |
| `0x0011BA80..0x0011BAAC` | `smt4_worker_service_state_request` | 48 |
| `0x0011BAB0..0x0011BABC` | `smt4_worker_service_publish` | 16 |

The three contracts contribute **292 compiled bytes**. The reused accessor
`0x002BBD3C..0x002BBD64` contributes 68 bytes in this build. Its translation unit
also links the existing 56-byte query request `0x0014F42C`; that request is not
executed or newly validated by this mode. Initialization/publication at
`0x0011BA54` / `0x001272D4`, archive/file IPC, clearing and lifetimes reuse existing
source and evidence. Builder, oracle, declarations and symbol changes support
this source package and do not count as recovered game routines.

Startup uses `0x0044E644` both as its nonzero early-return guard and as the output
of service acquisition. Setup result `0x08A067F9` is accepted explicitly; other
nonnegative statuses are accepted too. A negative result diagnoses with site
`0x0010F5E4` and r2=1. Name-length and acquisition calls receive the original
`fs:USER` pointer `0x00407FB3`, length seven and flags zero. Acquisition failure
diagnoses with site `0x0010F60C` and r2=1; returning diagnostics permit the fresh
service load consumed by initialization. Its result remains ignored.

Startup writes `0x0044E640` to `0x0044E648`, then publishes the **address**
`0x0044E648` at `0x00471A68`. The publisher returns its incoming word unchanged.
The reused accessor checks/reloads the shared guard/service word, diagnosing zero
with `0xE0A046DB` / site `0x002BBD58`. It establishes only two diagnostic arguments;
no new constant r2 contract is imposed.

The new request writes only command words zero and one (`0x08620040`, value),
loads the pointed-to service and executes SVC 0x32. Negative kernel results return
directly; all nonnegative results select response word one. Startup supplies zero
as the value. A negative selected result restores the caller frame and tail-calls
diagnostics with site `0x0010F654`, r2=1. Source preserves the observable r0 result
on early return, ordinary return and a returning final diagnostic; these C return
types describe the compared register contract, not inferred original prototypes.
GCC eliminates the redundant positive special-status comparison and inlines the
request/publisher into startup. This is behavioral reconstruction, not matching.

## Validation and domain

Primary: `local/validation/service-startup-20261011-final/COMPLETE.json`.
The pinned freestanding C11 ARMv6K build is warning-clean with
`-Wall -Wextra -Werror`; its **4,016-byte** image passes **1,333 original/rebuilt
pairs**. `service-startup.json` records 141 startup calls, 50 direct request calls,
five publisher calls and nine direct accessor calls. All 67 original instruction
sites in the connected four-body group execute: **57 new and ten reused**.
`function-boundaries.txt`, raw original disassembly, `startup-original-ghidra.txt`
and compiled disassembly agree on the selected extents and modes. The inherited
`comparison.json` field `new_instruction_addresses=94` describes file ownership,
not this package's new source.

The corpus covers zero/positive/sign-boundary/all-bit service and result words,
exact special setup status, independent kernel/service outcomes and absent reply
writes. It checks poisoned TLS and surrounding global/storage bytes at each
boundary and return, exact service name and acquisition arguments, request order,
service handles, callee-saved registers and stack restoration. Diagnostic models
both return and terminate at each startup diagnostic site. Returning models can
change the guard/service word. Initialization SVC callbacks can also replace or
zero that word, separating the handle already published to archive state from
the handle subsequently consumed by the accessor/state request. The final
diagnostic boundary explicitly checks restored SP and return LR before its tail
call. Volatile registers and flags are clobbered by modeled calls.

Two added persistent sequences execute startup, repeat startup's guard, descriptor
registration, concrete file open/close, prefix removal and another guarded startup
without reseeding either machine. One includes failed initialization, a service
word replacement and a returning state-request error. Both return their pool nodes.
The four earlier initialization/archive/file sequences also remain in this mode.

Setup `0x002C15C4`, ASCII length `0x002C32E4`, acquisition `0x002C1590`, TLS/SVC
replies, locks and diagnostic delivery remain explicit models. `fs:USER` is an
external original-address read-only data symbol checked against the pinned map;
no original executable helper runs on the rebuilt path. Pools, registry and
backing storage are synthetic. Valid mapped, disjoint storage is the domain;
invalid/aliasing pointers, concurrency, real service interpretation, complete
startup and live gameplay are unverified. State observations do not prove every
intermediate store order. The former dev/validated runs used the subsequently removed duplicate
accessor; only `service-startup-20261011-final` is authoritative for final source.

Audit: `local/validation/service-startup-20261011-final-audit/COMPLETE.json`.
Four compiled faults are rejected: publishing the wrong pointer level, consuming
the acquisition result instead of reloading the service, changing the state-request
header, and bypassing the checked accessor. `negative-checks.json` records each
assertion. `regressions.json` verifies the exact prior 3,600-byte initialization
binary plus full comparison, service, archive, clear, descriptor and initialization
evidence objects. `public-tests.log` records all **134 tests passing**. `jobs.json`
records commands and exits. All Ghidra runs were sequential and all started
commands completed.

```powershell
python tools/check_resource_worker_file_owner.py --recover-startup --output local/validation/NEW-STARTUP
python tools/check_resource_worker_file_owner.py --recover-startup --mutant startup-pointer --output local/validation/NEW-STARTUP-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-initialize --output local/validation/NEW-INITIALIZE-REGRESSION
python -m unittest discover -s tests
```

## Next independent source package

Replace acquisition model **`0x002C1590`** through its tail at **`0x0012954C`** and
consumed eight-byte name-copy helper **`0x002ADBA4..0x002ADBB8`**. Batch the directly
consumed length routine **`0x002C32E4..0x002C3340`** if its mapped word-read domain
is established. This removes active startup boundaries, rather than repeating
startup or the accessor. Reuse `--recover-startup` and the TLS/SVC fixture.

Static leads in `local/validation/service-startup-20261011-static/`:
`next-service-acquisition.log`, `next-acquisition-tail.log`,
`next-service-name-pack.log`, and `next-service-length.log`. The saved export
reports 124 bytes for `0x002C1590` and no separate entry for `0x0012954C`;
confirm current noncontiguous function membership before implementing. Raw code
checks signed service-manager count at `0x00471B90`, signed name length <=8,
then transports eight name bytes, length and flags in request `0x00050100`.
It loads service-manager handle `0x00471BA4`; a nonnegative kernel result publishes
response word three regardless of response status. Compare guard/length failures,
exact eight-byte transport, untouched output on kernel failure, publication on
service failure, and persistent use by startup and archive registration.

Keep setup/connect `0x002C15C4` / `0x0011CD48` as explicit models in that package
unless evidence warrants batching them. Their static leads are also saved;
connect includes a retry path, so it is a real separate uncertainty boundary.
Backing pools, initial locks, complete startup and deferred live gates remain open.

## Prior static package (2026-10-08)

2026-10-08. Project-authored analysis against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.

### Selection and acceptance

The completed service-initialization milestone is preserved. No optional extraction or compiler work is needed.
Acceptance for this new milestone remains a warning-clean ARM build and controlled
original/rebuilt comparisons of initialized early return, accepted/error statuses,
returning and terminal diagnostics, global reload/publication, exact request order,
untouched memory and persistent registration use. None of these new behavioral
acceptance criteria is claimed passed by this static package.

The available interval was insufficient for connected source
implementation and comparison. This package saves verified original-code findings;
no recovered contracts, removed models, source edits or new build are claimed.

### Verified evidence

`local/validation/service-startup-20261008-static/findings.json` records:

- Pinned executable hash and all 26 source/tool/config hashes from the preceding
  initialization COMPLETE manifest agree with existing workspace files.
- The existing 2026-10-06 saved-project function export identifies ARM bodies at
  `0x0010F5B8..0x0010F664` (172 bytes), `0x0011BA80..0x0011BAAC` (44),
  `0x0011BAB0..0x0011BABC` (12), and `0x002BBD3C..0x002BBD64` (40).
  Ends are exclusive; adjacent literal words are not instructions. This checks
  the existing export, not freshly queried current Ghidra database membership.
- All 111 instruction/literal words printed in the three previous static logs
  agree with the pinned executable. Some words lie beyond the selected bodies;
  this count is an integrity check, not behavior coverage.
- Address `0x00407FB3` contains the NUL-terminated ASCII name `fs:USER`, seven
  bytes excluding its terminator. Nine consumed literal words were recorded.

No Ghidra, build, behavioral comparison or public regression job was started.
Existing working-tree changes and original inputs were preserved.

### Contracts to implement and comparison hazards

`0x0010F5B8` guards the word at `0x0044E644`. This is also the output address
passed to acquisition `0x002C1590`, and the service word subsequently loaded from
base `0x0044E640` plus four. Treating the guard as an independent Boolean would
misrepresent the observed layout. The early-return path leaves this loaded word
in r0; establish the consumed caller return contract before assigning a C return
type. The normal path does not contain an unconditional zero-return instruction.

Setup `0x002C15C4` accepts exact status `0x08A067F9` before testing other statuses
for bit 31. Negative results diagnose at `0x002BBD70` with PC tag `0x0010F5E4`
and r2=1. The name-length call `0x002C32E4` feeds r2 to acquisition; its implementation
remains unverified here. Acquisition receives output pointer `0x0044E644`, name
pointer `0x00407FB3`, length and zero in r3. Its negative result diagnoses with
PC tag `0x0010F60C`, then a returning diagnostic permits a fresh service load.
Do not cache the pre-diagnostic service word in the future reconstruction.

The caller reuses recovered `0x0011BA54`, writes `0x0044E640` to `0x0044E648`,
and passes the address `0x0044E648` to `0x0011BAB0`, which stores that address at
`0x00471A68`. This is a pointer to the newly written word, not the word's value.
The publisher leaves its input in r0; caller-consumed return semantics are still
to be defined. Initialization failure is already ignored by the recovered callee.

Accessor `0x002BBD3C` checks the same service/guard word. If zero, it diagnoses
with r0=`0xE0A046DB`, r1=`0x002BBD58`. It does not initialize r2 at that call site;
do not invent a third constant argument. After a returning diagnostic it reloads
`0x0044E644`, permitting diagnostic-side state mutation to affect the result.

Request `0x0011BA80` writes only `0x08620040` and its supplied value to TLS+0x80
and TLS+0x84, then loads the service through its incoming pointer and performs
SVC 0x32. Negative kernel results return directly; any nonnegative result selects
response word 1. Preserve all other command words. Startup passes zero as the
request value and an on-stack copy of the accessor result. A negative result
restores the caller frame and tail-branches to diagnostics with tag `0x0010F654`
and r2=1; nonnegative results return through the ordinary epilogue. Include this
tail-call path and returning diagnostic behavior in the ABI/return review.

These are static instruction interpretations, not dynamically validated contracts.
TLS/SVC, service setup/acquisition and diagnostic delivery remain explicit models;
name length must be recovered or explicitly modeled. Synthetic pools/registry,
concurrency, invalid storage and real service interpretation remain outside scope.
Live G1/G2 gates, full startup, backing pools and initial locks remain open.

### Next task

Continue this same unfinished milestone, not the completed initialization package.
Confirm current saved Ghidra membership if needed, then implement the four bodies
above and integrate them with `src/resource_worker_service_initialize.c` using
`tools/check_resource_worker_file_owner.py` and
`tools/ghidra/CompareResourceWorkerFileOwner.java`. Add an explicit startup mode;
keep existing modes unchanged. Exercise service-word guard aliasing, exact name
and length, accepted/signed statuses, diagnostic mutation/reloads, publisher pointer
indirection, two IPC requests in order, and persistent archive registration.
Build and compare the new mode, run affected existing mode regression and public
suite once, and record exact evidence before declaring the milestone complete.
