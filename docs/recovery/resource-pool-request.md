# Pooled resource request IPC

2026-10-08. Project-authored EU base v0 recovery, expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategic review and acceptance

Forty-eight previous file/evidence
identities match, including the accepted binary; see
`local/validation/pool-request-20261008-static/handoff-check.json`.
Existing uncommitted owner/clear work was preserved. The completed owner and
constructor are dependencies, not repeated recovery objectives.

Selected ARM `0x002B5DD0..0x002B5E6C`, the request model still used by that owner.
This directly advances original-game source and removes a consumed game-call
model; optional extraction, compiler research and port work do not unblock it.
Before implementation, acceptance was set to a warning-clean ARM build, exact
TLS command/descriptors and buffers, separate kernel/service failure behavior,
handle publication, and caller cleanup integration under named remaining models.
All those bounded criteria pass. No acceptance gate or reference fact changed.

## Recovered contract

`src/resource_pool_request.c` adds `smt4_resource_pool_owner_request`, one original
entry contract. The declaration in `src/resource_pool_owner.h` now describes the
recovered boundary. The original body has 39 ARM instructions and a command
literal at `0x002B5E6C`; its saved function ends at `0x002B5E6B`. GCC emits 160
bytes, including literals, in the 3,696-byte linked image. This is behavioral
reconstruction, not binary matching or a full original-target application.

The routine reads the thread pointer with MRC p15 and writes these words at
TLS+0x80. Parameters have descriptive/raw-word names; no additional service
semantics are inferred from the command number.

| Word | Value |
| --- | --- |
| 0 | `0x08030204` |
| 1, 2 | `word1`, `word2` (incoming r2, r3) |
| 3, 4 | first type and byte length |
| 5, 6 | second type and byte length |
| 7, 8 | final two scalar arguments |
| 9, 10 | `(size1 << 14) | 0x802`, first buffer address |
| 11, 12 | `(size2 << 14) | 2`, second buffer address |

Shifts truncate to 32 bits. There is no length validation or buffer dereference
in this routine. Store order is 0,3,4,7,1,2,5,6,8,9,10,11,12. It then loads the
service handle through its first argument and executes SVC 0x32. A negative
kernel result returns unchanged and leaves the handle output untouched. Every
nonnegative kernel result publishes command word 3 and returns command word 1,
**even when the service status is negative**. The source retains volatile TLS
loads/stores and the kernel instruction as a platform boundary.

Original instructions and saved extents are in
`local/validation/pool-request-20261008-static/static.txt`; independent objdump
decoding, including the literal, is in the primary `original-request.log`.
Both agree with the parameter layout, store order, sign test and publication.

## Comparison and negative evidence

Primary: `local/validation/pool-request-20261008-final/COMPLETE.json`.
`tools/check_resource_pool_owner.py --recover-request` links the new source;
`CompareResourcePoolOwner.java` observes entry arguments but executes both
original and rebuilt request bodies. Only TLS provisioning and SVC responses
are supplied. It never copies predicted command words into either machine.

- **132 owner pairs**, including 60 kernel/service/response combinations,
  ten initializer status/alternate-vtable cases, two second-pool exhaustion
  cases with zero/nonzero handles, and 60 calls in eight persistent allocation
  sequences. All 107 caller and 55 constructor instruction sites remain visited.
- **70 direct request pairs**: 20 descriptor probes use each length at
  0,1,16,20,`0x3FFFF`,`0x40000`,`0x40001`,`0x7FFFFFFF`,`0x80000000`,`0xFFFFFFFF`,
  with a complementary second length and swapped zero/all-ones buffer addresses.
  Fifty probes cross five kernel results, five service results and written versus
  untouched responses. Distinct full-width scalar words and poisoned output
  expose truncation, slot confusion and failure publication.
- **12 direct constructor pairs** retain the previous poisoned-layout checks.
  There are **372 actual request executions** across original/rebuilt machines;
  early allocation exhaustion skips the request. All 39 request sites execute.

Each request checks exactly one TLS read and kernel call, all 13 command writes
in order, all 320 guarded TLS bytes, kernel handle, stack argument preservation,
return value and exact output-store count/value. Caller comparisons check both
buffers at entry, kernel submission and request return, including the three FF
padding bytes. Stack-relative addresses differ between builds: each descriptor
must name that machine's independently checked buffer. Full object/pool/input/
output fixtures, ordered nonstack writes, cleanup order, stack guards,
callee-saved registers and execution budgets retain the prior oracle checks.

Audit: `local/validation/pool-request-20261008-audit/COMPLETE.json`.
Three compiled faults are rejected: missing first-descriptor slot bit (case 0,
ordered command writes), gating on service status as well as kernel status
(case 7, IPC result), and returning TLS service status after kernel failure
(case 36, IPC result). See `negative-checks.json` for exact assertions and binaries.
The affected default owner regression preserves its entire comparison object
(84 owner / 12 constructor pairs) **and exact 3,536-byte binary hash**; see
`regressions.json`. All **134 public tests** pass (`public-tests.log`).
Shared allocator/clear sources did not change in this package, so their separate
previous evidence remains scoped as recorded rather than being rerun unnecessarily.

The first behavioral development run passed; the final run adds preserved-buffer
checks at SVC/return and keeps service responses independent of kernel errors.
An initial local static-inspection launcher was named `inspect.py`, shadowing the
Python standard module; renaming it to `inspect_request.py` fixed the import
before a Ghidra job launched. This affected no source comparison result.

## Models and limits

The new optional mode removes **one game-call interception**, request `0x002B5DD0`.
Default owner mode and older harnesses retain their documented models; unchanged
binary/comparison evidence verifies that boundary. Header, checker and symbol
updates support the source contract and are not additional recovered routines.

TLS location and SVC 0x32 behavior are scheduled. Kernel responses either overwrite
status/handle words or leave the command unchanged, independently of kernel result;
some caller cases also apply the prior synthetic service-global change at the
kernel boundary. Volatile registers/flags are clobbered. This does not establish
actual kernel ABI completeness, service acceptance or valid resource contents.
TLS is re-poisoned per invocation; persistent sequences retain pool/object state,
not cross-request TLS history. Direct descriptor addresses are passed opaquely,
not dereferenced. Service/output/TLS storage is mapped and disjoint; arbitrary
aliasing, invalid pointers, real scheduling and concurrency are unverified.

Initializer `0x00145E9C`, virtual cleanup `0x003567F0`/`0x00356438` and synthetic
alternates, and SVC 0x23 remain models. Cleanup still does not return nodes to
pools. Initial storage/locks/second pool are synthetic, and successful exclusive
outcomes remain scheduled. Full teardown/return/reuse, original startup, live
G1/G2, full ABI/compiler identity, matching and source-transfer gates stay open.

## Reproduction and next independent milestone

```powershell
python tools/check_resource_pool_owner.py --recover-request --output local/validation/NEW-POOL-REQUEST
python tools/check_resource_pool_owner.py --recover-request --mutant request-descriptor --output local/validation/NEW-REQUEST-DESCRIPTOR-NEGATIVE
python tools/check_resource_pool_owner.py --recover-request --mutant request-publish --output local/validation/NEW-REQUEST-PUBLISH-NEGATIVE
python tools/check_resource_pool_owner.py --recover-request --mutant request-kernel --output local/validation/NEW-REQUEST-KERNEL-NEGATIVE
python tools/check_resource_pool_owner.py --output local/validation/NEW-OWNER-REGRESSION
python -m unittest discover -s tests
```

Next recover **initializer `0x00145E9C..0x0014627C`** through this caller, replacing
its modeled object writes/results. The saved static inspection identifies a
40-byte initial virtual read, optional subsequent reads, size/capacity failure
paths, four embedded views, two pool/lock initializations, and final ownership
publication. Reuse recovered `0x002A4EB4` and `0x002C3B54`; inspect and batch the
direct 32-byte helper `0x00145E7C..0x00145E9C`. The virtual-read target and diagnostic
`0x002BBD70` require explicit boundary decisions. Start from the static report
above and existing file-read-service evidence; do not assume that fixture data
or a recovered similarly named method identifies the concrete virtual target.
Compare short/error reads, capacity boundaries, both loading modes, exact embedded
layouts and owner failure cleanup. Request and constructor recovery are complete.
