# Service publication and initialization request

2026-10-08. Project-authored reconstruction against EU base v0 expanded code
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external source reused.

## Strategic review and acceptance

Verified every recorded source/tool hash
in the previous descriptor manifest before editing; see
`local/validation/service-initialize-20261008-static/handoff-check.json`.
The descriptor milestone is complete. Its explicitly evidenced publication caller
and request wrapper are the next useful bounded source milestone, with no new
extraction, compiler or port prerequisite. Existing working-tree changes remain.

Acceptance declared before implementation: ARM source/build and original/rebuilt
agreement for exact command words and untouched memory, service/global publication,
kernel/service result selection, unconditional caller zero and persistent use by
descriptor registration. This package meets that bounded acceptance; full startup
and service acquisition are separate dependencies, and live gates remain open.

## New recovered contracts

`src/resource_worker_service_initialize.c` adds two contracts declared in
`src/resource_worker_backend.h`:

| Original ARM range, exclusive end | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x001272D4..0x00127308` | `smt4_worker_service_request` | 56 |
| `0x0011BA54..0x0011BA78` | `smt4_worker_service_initialize` | 76 |

The request obtains TLS and writes exactly three words at TLS+0x80:
`0x08610042`, the supplied value, and `0x20`. Remaining command words are preserved.
It loads the service through its incoming pointer after these stores, executes
SVC 0x32, and returns a negative kernel result unchanged. Any nonnegative kernel
result, including a positive value, selects response word 1 instead. Without a
response write this word remains the supplied request value. No interpretation
of these constants or of unwritten command words is inferred.

The caller publishes its input to global `0x0044E660`, passes a local copy with
value `0x040201C8` to the request and returns zero regardless of kernel or service
failure. Publication is not rolled back on failure. GCC inlines the request into
the caller; the separate compiled wrapper is also compared directly. The original
local pointer is an implementation detail; command bytes and the service passed
to SVC are compared without relocation. Saved Ghidra bodies and raw disassembly
agree on both extents. `initialize-original-ghidra.txt` visits all 22 instructions;
original literal pools are excluded. Build disassembly records the inlined body.

These are **two new recovered contracts, 132 compiled bytes**. No older intercepted
call model is removed: these entries were absent from previous corpora. Existing
archive/file IPC, descriptor creation/registration, clearing and lifetime source
are reused, not counted as new recovery. Builder, oracle, interface and symbol
changes support only the selected source target.

## Validation and limits

Primary: `local/validation/service-initialize-20261008-validated/COMPLETE.json`.
The freestanding C11 ARMv6K build uses `-Wall -Wextra -Werror`; its 3,600-byte image
passes **1,120 original/rebuilt pairs**. `service-initialize.json` records 50 direct
request pairs, 62 publication pairs, all 22 original instruction sites and 224
initialization SVC observations across both machines. The inherited
`comparison.json` instruction count still refers to file ownership, not this unit.

Direct cases independently cross kernel and service values 0, 1, 0x7FFFFFFF,
0x80000000 and 0xFFFFFFFF, with and without response writes. Service handles and
request values include zero, positive, sign-boundary and all-bit words. Poisoned
TLS and surrounding global/storage bytes are checked at the request boundary
and return, as are request handle, boundary order, stack restoration and
callee-saved registers. Modeled calls clobber volatile registers/flags.

Four persistent sequences (two descriptor-registration lifetimes and two inherited
singleton lifetimes, each with three rounds) now execute publication before their
archive/file operations without reseeding memory. They use handles zero,
0x12345678 and 0xFFFFFFFF; the middle initialization has a negative kernel result
and all have a negative service response. Subsequent original and rebuilt archive
requests still consume the published handle. Exhaustion, cleanup, prefix removal
and node reuse retain the accepted lifetime checks. Descriptor stack-pointer
normalization and all prior bounded domains remain as documented in the descriptor
report; this package does not broaden their claims.

TLS acquisition and SVC request/reply behavior remain modeled. Locks and diagnostic
delivery in connected lifetimes also remain models. Pools, registries and backing
storage are synthetic. Nonaliasing mapped arguments and valid concrete vtables are
the compared domain; invalid pointers, aliasing with TLS/global storage, service
interpretation, real concurrency and complete startup are outside it. Boundary and
return observations do not establish identical intermediate store ordering.
This is not matching, a whole-game build, live gameplay or a native port.

Audit: `local/validation/service-initialize-20261008-audit/COMPLETE.json`.
`jobs.json` records commands/exits; `negative-checks.json` records rejection of four
compiled faults: wrong header, positive kernel result treated as failure, nonzero
caller return and wrong global publication slot. `regressions.json` compares the
full descriptor-mode comparison, clear/service/descriptor objects and exact accepted
3,468-byte binary hash. `public-tests.log` records all 134 public tests passing.
The initial development comparison also passed before header declaration placement
and persistent-sequence reporting were corrected; the validated directory is the
final authoritative run. All Ghidra jobs execute sequentially on the saved read-only
project.

```powershell
python tools/check_resource_worker_file_owner.py --recover-initialize --output local/validation/NEW-SERVICE-INIT
python tools/check_resource_worker_file_owner.py --recover-initialize --mutant initialize-kernel --output local/validation/NEW-SERVICE-INIT-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-descriptor --output local/validation/NEW-DESCRIPTOR-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Recover the directly evidenced service-startup caller `0x0010F5B8..0x0010F664`
and its consumed publication/request/accessor dependencies:
`0x0011BAB0..0x0011BABC`, `0x0011BA80..0x0011BAAC` and
`0x002BBD3C..0x002BBD64`. Verify saved extents before implementation.
Static leads are `next-startup.log`, `next-state-initialize.log` and
`next-service-accessor.log` in this package's static directory. The original caller
at `0x0010F618` directly invokes the now-recovered initialization routine.

Startup guards global `0x0044E644`, calls service setup `0x002C15C4`, checks its
special accepted status `0x08A067F9`, obtains a name length through `0x002C32E4`,
then requests the named service through `0x002C1590`. It publishes through the
recovered caller, installs a pointer at `0x00471A68` via `0x0011BAB0`, and sends
command `0x08620040` through `0x0011BA80` after accessor `0x002BBD3C`. The accessor
checks the guard, diagnoses zero and reloads the service word after a returning
diagnostic. Recover this connected caller behavior with service-acquisition and
diagnostic models explicit; do not claim those calls recovered. Inspect the name
bytes/literal map and saved function membership first. Reuse TLS/SVC fixtures and
compare early return, special/error status branches, global reload/publication,
request order, returning/terminal diagnostics and persistent registration use.
Backing pools and initial locks remain independent startup dependencies.
