# File-size dispatch, concrete method and IPC

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored reconstruction; names are descriptive, not original symbols.
No external implementation was reused.

## Strategic review and acceptance

The archive-service milestone is complete: all
recorded source/tool identities still matched its manifest, checked in
`local/validation/worker-size-service-20261008-audit/handoff-check.json`.
The next size-service chain is a modeled dependency of recovered cache/seek
behavior and has direct instruction/vtable evidence. Deferred live gates, optional
extraction and compiler research do not block this target.

Acceptance declared before implementation: verify saved extents; recover null
handling, virtual dispatch, command preservation, 64-bit output and exact
kernel/service result selection; execute the chain through recovered cache/seek;
build ARM source, compare bounded behavior, reject semantic faults, and retain
affected regressions. TLS, kernel responses and diagnostics remain explicit models.
The saved extents were checked before source implementation in the audit's
`original-extents.txt`; final validation repeats those checks.

## Recovered contracts

`src/resource_worker_file_size_service.c` adds three contracts:

| Original ARM body, exclusive end | Source contract |
| --- | --- |
| `[0x002A8914,0x002A893C)` | `smt4_worker_file_size_service` |
| `[0x003DFCA8,0x003DFCC8)` | `smt4_worker_file_size_method` |
| `[0x00356DE8,0x00356E1C)` | `smt4_worker_file_service_size` |

All three match the saved Ghidra extents. Error/header literals immediately after
the dispatcher/IPC bodies are data. GNU disassembly and the hash-bound saved
Ghidra listing agree. Vtable `0x00420998` slot +8 contains `0x003DFCA8`.

The dispatcher accepts `(size_output, untagged_object_address)`. Either null
argument returns `0xE0E046BC` without a virtual call or memory modification.
Otherwise it loads object+0, selects vtable+8 and tail-dispatches
`method(object, size_output)`, preserving the returned status. It does not remove
tags itself; recovered cache/seek callers clear bit zero. The object address is
distinct from the kernel handle stored at concrete object+4.

The concrete method calls the already recovered handle accessor `0x00239CD0`,
captures its returned handle in a local word and passes that word's address plus
the output pointer to IPC. The accessor's zero-handle diagnostic remains modeled;
if it returns, the accessor reloads object+4. Tests cover both terminal diagnostics
and returning diagnostics that replace the handle. The accessor is reused source,
not a fourth newly recovered contract.

IPC reads TLS with `MRC p15,0,Rd,c13,c0,3`, writes only header `0x08040000` at
TLS+0x80, loads the handle through its first argument, and enters SVC `0x32`.
All other command words remain intact before the request. A kernel result with
bit 31 set returns unchanged and preserves the caller's eight output bytes,
even if the modeled kernel changed response memory. Every nonnegative kernel
result copies both words from command+8/+12 to caller output, then returns
command+4. This publication occurs even when that service status is negative.
Positive kernel results are successes. Volatile source accesses preserve output
publication before the service-status load; rebuilt disassembly confirms it.

The connected cache layer treats the returned service status separately: a
negative result clears its two cache words and preserves its caller's output
and cursor. Thus negative service status can publish into the cache layer's
local IPC output without publishing to its caller. Successful queries retain
both words, including high-bit sizes; signed position validation remains the
existing recovered behavior.

## Integration and boundaries

`tools/check_resource_worker_file_size.py` links the new source, existing handle
accessor, size/seek adapters and lower cache/seek/position source. Section garbage
collection excludes unrelated owner/read routines; explicit linker roots keep
every tested entry. No original helper executes on the rebuilt path.

The checker extends the existing position oracle through a small optional
service-execution hook in `CompareResourceWorkerFilePosition.java`. Its default
still performs the prior size-call model. The new checker executes dispatch,
method, accessor and IPC instead. It reuses the owner checker's explicit MRC/SVC
interception approach and the existing signed Java-long cache/cursor oracle.
This replaces **one aggregate size-service call model** in the new connected
corpus with **three new source contracts** and an already recovered accessor.
Headers, builder, oracle and symbol metadata are supporting work.

The standalone checker uses a synthetic concrete file object/vtable and separate
lower five-word object. It does not construct file ownership or run the full
worker allocation/I/O region. Older worker-I/O modes, including
`--recover-file-position`, retain their documented size model and wider fixture
domains. New direct source does not silently broaden those historical modes.

## Validation

Primary: `local/validation/worker-size-service-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K image is **928 bytes**, with **192
compiled bytes** for the three new entries (48 dispatcher, 72 method, 72 IPC).
GCC inlines IPC into the concrete method; the separately callable IPC is also
retained and tested. This is behavioral source recovery, not binary matching.

All **576 original/rebuilt pairs** pass: **91 direct chain probes** and **485
connected cache/seek probes**, including two persistent sequences on each path.
All **31 new instruction sites** and nine retained accessor sites were visited.
Two original sites are intercepted MRC/SVC instructions, not executed platform
operations. Both paths together perform **618 TLS reads and SVC requests**;
476 connected dispatcher invocations include null-handle failures without IPC.
Ten alternate virtual calls and 24 handle-diagnostic entries validate dispatch
selection and the reused accessor boundary.

Direct probes cross independent kernel/service values zero, one, maximum signed
positive, sign-bit-only and all-ones. Output probes include zero, one, high-only,
unequal low/high words, signed minimum and all-ones. Nonzero command sentinels
detect accidental clearing. The modeled response changes status, both size words
and an extra word even on kernel failure. Full guarded TLS, file/vtable/handle
storage and output bytes are checked before request and at return. Null output,
null object and both-null dispatcher calls make no TLS/SVC request. An alternate
slot +8 target verifies receiver/output forwarding and returned status, including
negative statuses. A wrong adjacent slot is an invalid execution target.

Connected probes retain the independent position oracle and cover absolute,
current, end and invalid origins; zero/one, carry across 32 bits, signed extrema
and all-bit offsets/cursors/sizes; cache hits, equality refresh, signed rejection,
two-query end seeks, changing sizes and errors. Null/tag-only lower handles clear
stale cache without IPC. Persistent sequences retain TLS, cache and cursor through
hits, equality, kernel failure, service failure, recovery, second-query failure
and shrinkage. Public-call stack alignment/restoration, callee-saved registers,
caller stack word and lower stack guards remain checked. SVC requires word
alignment; its explicit model preserves LR/callee-saved registers and clobbers
volatile registers/flags.

Audit: `local/validation/worker-size-service-20261008-audit/COMPLETE.json`.
Five compiled semantic faults are rejected: missing single-null checks, wrong
virtual slot, duplicated output high word, positive kernel result treated as
failure, and publication suppressed on negative service status. The retained
position regression reproduces its exact **1,628-byte** binary and entire
comparison object (2,304 worker, 3,312 direct position, 210 isolated adapter and
48 allocation cases). The archive regression reproduces its exact **2,748-byte**
binary and entire **670-pair** comparison object. All **134 public tests** pass.
Commands, exits, assertions, manifests and source/header identities are saved
in the audit. The development run passed 566 pairs; the final run adds ten
connected null/tag-only-handle probes with identical compiled source bytes.

The bounded domain uses mapped, separate, word-aligned objects and aligned
eight-byte outputs. Nulls are tested only where the dispatcher handles them.
Faulting/overlapping pointers, concurrency, alternate TLS, real file services,
diagnostic delivery and timing remain unverified. Instruction visitation does
not establish all predication combinations. No full original-target build,
native runtime, live evidence or gate closure is claimed.

```powershell
python tools/check_resource_worker_file_size.py --output local/validation/NEW-SIZE-SERVICE
python tools/check_resource_worker_file_size.py --mutant publish --output local/validation/NEW-SIZE-NEGATIVE
python tools/check_resource_worker_io.py --recover-file-position --output local/validation/NEW-POSITION-REGRESSION
python tools/check_resource_worker_file_owner.py --recover-archive-services --output local/validation/NEW-ARCHIVE-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Recover the **read-service chain and its pre-read delay**: dispatcher
`0x002A4E54`, concrete method `0x003564A8`, IPC `0x00356D04`, and helper
`0x002ADC48`. Read [the lower-read report](resource-worker-file-read.md),
[wait/delay](resource-wait.md) and [consumed quotient](unsigned-quotient.md).
The archive audit's `next-read*.log` and this audit's `next-read-context.log`,
`next-read-ipc.log` and `next-read-link.json` provide static leads. Candidate body
ends are `0x002A4EB0`, `0x003564E8`, `0x00356D58` and `0x002ADCD0`; verify saved
extents before source work. Vtable `0x00420998` slot +0 selects `0x003564A8`.

Unlike size, read dispatch calls `0x002ADC48(1)` before virtual dispatch. Its
instructions read bytes +0/+1 and word +0x18 from state `0x0044E650`, optionally
execute SVC `0x28`, divide 100 (nonzero argument) or 380 (zero argument) by a
low-nibble-derived value 1..16 via `0x002C6C64`, truncate the added delay to
16 bits, and tail-call `0x002BB4F0` with delay times 1,000,000 when nonzero.
Reuse `src/unsigned_quotient.c` and `src/resource_wait.c` for those already
recovered consumed contracts; platform query/sleep behavior stays explicit.
These are static observations, not recovered helper behavior in this package.

Read IPC's visible header is `0x080200C2`; it transports a 64-bit cursor, byte
count and buffer descriptor and publishes count after nonnegative kernel status.
Replace `smt4_worker_file_read_service` through the recovered loop, with exact
request/payload/count effects, partial progress, failures, cursor arithmetic and
delay ordering. Reuse the existing read/position and IPC harnesses; do not skip
the pre-read side effect. Allocator ownership/release integration, startup,
locks/clear/diagnostics and deferred live gates remain independent open work.
