# Service-manager setup through startup

2026-10-11. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategy review and acceptance

The previous acquisition milestone is complete. No reprioritization
was needed. Before implementation, every source/tool/config hash in the acquisition
manifest and the pinned executable was checked. Results are in
`local/validation/service-setup-20261011-static/handoff-check.json`.

Acceptance selected before implementation: confirm saved function membership,
build warning-clean ARM source, and compare signed count guards and modulo
increments, exact repeat-setup status, lock/reload order, failure handle publication,
finite retry predicates and delay, registration IPC, increment despite registration
failure, and connected startup/archive/file lifetimes. These bounded criteria pass.
Live gameplay, whole-game startup and project G1/G2 remain open.

## Recovered source and model replacement

New `src/resource_worker_service_setup.c` / `.h` provides four contracts:

| Original ARM range (exclusive end) | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x002C15C4..0x002C161C` | `smt4_worker_service_setup` | 88 |
| `0x0011CD48..0x0011CDD8` | `smt4_service_manager_connect` | 192 |
| `0x00129510..0x00129544` | `smt4_service_manager_register` | 60 |
| `0x001382CC..0x001382E4` | `smt4_service_connect_port` | 20 |

The optional `--recover-setup` mode replaces **one active call model**, setup;
connect, registration and the SVC wrapper were previously hidden behind it.
The four contracts contribute **360 compiled bytes**. Existing delay
`0x002BB4F0` from `src/resource_wait.c` is reused, not counted as new recovery.
Its translation unit adds 120 bytes including an unexecuted wait routine.
Builder/oracle changes, header integration and symbol metadata support this
source target; they are not additional recovered game behavior. Earlier checker
modes preserve their original boundaries.

Setup acquires recursive lock `0x004E9BA8`, then loads signed count at
`0x00471B90`. A positive count increments modulo 2^32 and returns `0x082067F9`.
This differs from startup's explicit `0x08A067F9` comparison. A nonpositive count
connects using the original `srv:` name at `0x0040B6E4`. Both paths release the
lock and retain their result across release, regardless of the modeled release
return value or its changes to count.

The connect wrapper presents output and name in r0/r1 to SVC 0x2D, stores returned
r1 unconditionally, and returns r0. Failure does not preserve the previous handle.
The caller stores every attempt at `0x00471BA4`. Retry requires signed result
bits 31..27 equal -5, bits 26..21 equal 4, and bits 9..0 equal 1018. Bits 20..10
do not affect this decision. Each retry executes the recovered delay with signed
64-bit duration 500,000, which reaches the modeled sleep boundary `0x001382E4`.
The original contains no retry limit; only the comparison scripts are finite.

A final negative connect result returns without registration or count increment.
Every nonnegative result, including nonzero, executes registration. Registration
writes command words zero/one as `0x00010002` and `0x20`, loads the manager handle,
and executes SVC 0x32. Negative kernel status returns directly; nonnegative status
returns command word one. The connect caller then reloads and increments count,
even when registration returned a negative kernel or service result. Source uses
unsigned arithmetic for count wrap, retaining signed comparisons at the guards.

## Validation

Primary: `local/validation/service-setup-20261011-final/COMPLETE.json`.
The freestanding C11 ARMv6K build uses `-Wall -Wextra -Werror` and produces a
**4,764-byte** image. All **2,793 original/rebuilt pairs** pass, including 74 direct
setups, 58 connect callers, 40 registration requests, 18 connect wrappers and
158 startup calls. All **77 new original instruction sites** are visited.
The consumed five original delay sites execute; its short-delay path is not
newly validated. `service-setup.json` records 446 connect SVC calls, 392 registration
requests and 36 sleeps across both paths. The older generic comparison field
`new_instruction_addresses=94` still refers to file ownership, not this package.

Fixtures cover signed count extremes, acquisition-lock changes to count, reload
after registration changes, overflow to the negative range and wrap to zero,
release changes, independent status/handle signs, exact command contents and
untouched neighbours, absent replies, every single-bit perturbation of a retry
status, ignored retry-field bits, and multiple retries ending in success/failure.
The retry oracle independently uses mask `0xFFE003FF` / value `0xD88003FA`.
Boundary snapshots and final guarded storage check publication and mutation order;
callee-saved registers, stack restoration and instruction-domain guards remain
active. This is controlled emulation, not hardware or live gameplay evidence.

Two new persistent sequences begin with manager count zero, retry, register,
run startup and its guard again, repeat setup, register an archive descriptor,
open/close a file, remove the archive and reuse the startup guard without reseeding.
One sequence returns registration kernel failure yet proceeds through recovered
count increment and the explicitly returning diagnostic model. Both end with
manager count two and all borrowed pool nodes returned. Existing persistent
startup/archive/file sequences also execute. Older setup-status fixtures are
translated to actual registration replies only in the new mode; the earlier
acquisition mode remains unchanged.

Fresh read-only Ghidra membership is saved in
`service-setup-20261011-static/membership.txt`; the primary manifest saves exact
function boundaries, original instructions and rebuilt disassembly. The first
development run exposed a harness ordering bug: after mapping SVC 0x2D to a
synthetic event address, instruction classification read that event address.
Classification now reads the actual PC. No recovered source correction was needed.
The failed development run is not acceptance evidence.

Audit: `local/validation/service-setup-20261011-audit/COMPLETE.json`.
Four compiled faults are rejected: unsigned setup count guard, wrong retry
description, skipping count increment on registration failure, and suppressing
failure-handle publication. The acquisition regression preserves its exact
**4,284-byte binary** and all eleven compared binary/evidence fields, including
the full prior acquisition/startup/initialization and lifetime results. All
**134 public tests pass**. Commands and exits are in `jobs.json`; Ghidra jobs
ran sequentially and all commands finished.

TLS, kernel replies, sleep scheduling, locks and diagnostics remain modeled.
Manager, pool, registry and backing memory are synthetic; concurrent mutation,
unbounded retry liveness, invalid/aliased pointers, real service interpretation,
initial lock construction and complete startup remain outside the domain.
The existing acquisition UQSUB8 host instruction implementation remains explicit.
The linked query IPC routine and wait routine are not newly validated. No original
binary helper runs on the rebuilt path.

## Reproduction and next independent milestone

```powershell
python tools/check_resource_worker_file_owner.py --recover-setup --output local/validation/NEW-SETUP
python tools/check_resource_worker_file_owner.py --recover-setup --mutant setup-increment --output local/validation/NEW-SETUP-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-acquisition --output local/validation/NEW-ACQUISITION-REGRESSION
python -m unittest discover -s tests
```

Next recover **diagnostic record and delivery**, replacing active model
`0x002BBD70..0x002BBD98` through delivery `0x002AD7E8..0x002AD8F0` in the same
startup/archive fixture. Fresh saved membership and callers are in
`service-setup-20261011-static/next-diagnostic-membership.txt`; raw instruction
leads are `next-diagnostic.log` and `next-diagnostic-delivery-full.log`.
This shared dependency is exercised by startup/acquisition and archive failures;
it advances existing behavior instead of starting unrelated preparation.

The wrapper writes a record at `0x004D4200`: byte one zero, halfword +2 `0xBCA3`,
byte zero zero, site at +8, result at +4; it ignores incoming r2 and tail-calls
delivery. Delivery locks `0x004D4280`, conditionally connects a diagnostic service,
calls SVC wrapper `0x00144900..0x00144918` (SVC 0x35, not a copy), sends request
`0x00146964..0x0014699C`, closes/reloads the handle and routes according to record
type. Inspect its consumed copy `0x002BCFAC` before selecting the request boundary.
The request sends header `0x00010800` and 128 copied bytes. Static helper listings
are retained alongside the delivery lead; none is newly recovered here.

Reuse this package's connect wrapper and existing delay. Define explicit bounds
for lower calls `0x002C5470..0x002C54A4` and `0x002C367C..0x002C373C`; do not
assume the old diagnostic model's arbitrary returning cases describe real delivery.
Compare record layout/order, kernel-failure publication, captured/reloaded handles,
IPC payload, type-dependent return/wait routing and finite retry prefixes (special
status `0xD0401834`, type two, delay 5,000,000), then connected failure paths.
Backing storage, initial locks, full read integration and deferred live gates remain
open. Do not repeat the completed setup or acquisition milestones.
