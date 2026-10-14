# Descriptor archive creation and registration

2026-10-08. Project-authored reconstruction against EU base v0 expanded code
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external source reused.

## Strategic review and acceptance

The previous alternate milestone is complete: its source/tool identities and
binary matched its manifest before edits; see the static directory's
`handoff-check.json`. Existing uncommitted work was preserved. The recorded
archive descriptor factory uses validated archive IPC and backend lifetime, so
it advances original source without extraction, compiler or port prerequisites.

Acceptance declared before implementation: recover `0x00127220`, build ARM source,
and compare descriptor transport, captured/reloaded service words, failure-output
preservation versus exhaustion null publication, both handle halves, and persistent
return/reuse. Static caller inspection then justified batching its direct registration
caller `0x0011B860` and descriptor builder `0x002B5FCC`. Before adding them, acceptance
was extended to descriptor layout, prefix publication and registration rollback.
They share the same fixture and dependency chain; no adjacent unrelated routine
was implemented. The bounded milestone is complete with the evidence below.

## Recovered contracts

`src/resource_worker_archive_descriptor.c` implements three new contracts declared
in `src/resource_worker_backend.h`:

| Original ARM body, exclusive end | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x002B5FCC..0x002B5FE4` | `smt4_worker_archive_descriptor_make` | 24 |
| `0x00127220..0x001272C4` | `smt4_worker_backend_create_descriptor` | 176 |
| `0x0011B860..0x0011B8D0` | `smt4_worker_backend_register_descriptor` | 128 |

The ARM image grows from the current 3,140-byte dependency image to 3,468 bytes;
the new source contributes 328 compiled bytes. See final symbols/disassembly for
exact linked extents.
Saved Ghidra function objects match all three original extents. Static Ghidra
and raw disassembly agree; literal pools are excluded from instruction counts.
The static evidence records the direct calls at `0x0011B87C` and `0x0011B888`.
No saved-project annotations were changed.

The builder writes the low byte of its selector at +0, zero at +1 and zero halfword
at +2, then the two supplied full-width words at +4/+8. It returns its destination.
The source fixes size and offsets with static assertions. Selector meanings and
identifier interpretation are not inferred. Direct cases check truncation at
255/256/257 and full-width signed boundaries with poisoned surrounding storage.

The factory receives output in r0 and an opaque descriptor address in r1. It
copies global `0x0044E660` into a local service word and calls archive open
`0x002ADBE8` with archive 7, type 2, the unchanged descriptor address and 12 bytes.
It does not inspect descriptor memory or validate its address. A negative result
returns unchanged, preserving caller output. Nonnegative results capture the
64-bit archive and reload global service before taking pool `0x004D431C` through
`0x002B5D6C`. An acquired node receives vtable `0x004209F8`, service at +4 and
handle low/high at +8/+12. Success publishes the node and returns zero, including
when the service returned a positive status.

On exhaustion, the factory publishes null, reloads global service again and closes
the acquired archive with `0x002ADBB8`, even when both handle words are zero. It
ignores close status and returns `0xD8604659`. The two global reads after open have
different purposes: object service is captured before lock callbacks; failure
cleanup reads service after those callbacks. The guarded oracle distinguishes both.

Registration takes a prefix name and 32-bit identifier. It constructs a local
12-byte descriptor with selector zero, identifier at +4 and zero at +8, then
calls the new factory. Factory failure bypasses registration. Otherwise it invokes
existing prefix registration with both flags zero. Registration failure invokes
the newly created object's current vtable+0x30 and returns the registration error
after disposal. Success leaves the object registered. This caller does not publish
the singleton global used by `0x00354DEC`; every untouched global byte is checked.

## Integration and models

`tools/check_resource_worker_file_owner.py --recover-descriptor` implies archive
and file IPC recovery plus recovered clearing. It links the three new contracts
with existing pool take, backend ownership, prefix registration/removal, file
ownership, clear and IPC source. Original instructions execute on the reference
path; compiled source executes on the rebuilt path without original binary helpers.
The descriptor builder may be inlined into the compiled registration caller;
its separately compiled entry is also compared directly.

This package adds **three recovered contracts**. It replaces no pre-existing
intercepted call in older modes: the new entry path did not previously exist in
their corpora. Existing archive/file IPC, clearing and lifetime contracts are
reused, not counted again as new recovery. Builder/oracle/symbol/interface changes
support these named contracts and do not count as additional game code.

Two new persistent sequences, with and without pool clearing, execute three rounds
of actual descriptor registration, open failures, successful publication, exhausted
factory cleanup, file open/close, prefix removal and pool reuse. Both machines retain
all memory between calls. Two inherited singleton lifetime sequences remain intact.

The registration caller's stack descriptor is relocated for cross-build comparison.
At archive-open entry, the checker verifies its actual pointer lies within the
caller stack, all twelve actual bytes match the declared layout, and archive/type/
length arguments agree. Only the pointer in command+0x14 is canonicalized, including
stale command contents after close; descriptor bytes are never normalized.
Standalone factory descriptor addresses are compared exactly, including zero,
unaligned and all-bit opaque values. No pointed memory is accessed in those probes.
Older generic factory stack descriptors retain their existing normalization and
previously documented scope; this package does not broaden their byte-level claims.

TLS acquisition, SVC request/reply behavior, recursive lock calls and diagnostic
delivery remain modeled. Clearing executes recovered instructions. Kernel responses
and callbacks are scripted, not real service behavior. Initial pool/registry/storage/
globals are synthetic; declaration or fixture installation does not recover startup.

## Validation and limits

Primary: `local/validation/archive-descriptor-20261008-final/COMPLETE.json`.
The freestanding C11 ARMv6K build is warning-clean with `-Wall -Wextra -Werror`.
Its **3,468-byte** image passes **1,008 original/rebuilt pairs**, including **224**
direct descriptor factories, **28** direct descriptor builders and **68** actual
registration callers. The remaining cases cover inherited and connected ownership,
IPC, teardown and file operations. All **75 new original instruction sites** are
visited; `descriptor-factory.json` owns those counts. The generic `comparison.json`
field `new_instruction_addresses=94` retains the older file-ownership meaning.
The descriptor-specific two persistent sequences are separate from the inherited
two sequences reported by generic `comparison.json`.

The oracle compares all guarded pool, global, registry, node, output, descriptor,
name/path and TLS bytes at every modeled boundary and at return. It checks boundary
order/arguments, public stack alignment, callee-saved registers, stack restoration
and lower guards. Call models clobber volatile registers and flags. Cases cover
kernel/service sign boundaries independently, positive results, absent response
writes, null/full-width service words, null/nonempty pools, selective clear bits,
counter wrap, zero/high-only/distinct/all-bit handles and ignored close failures.
Registration cases include empty, duplicate and full registries, terminal versus
returning diagnostic cleanup, failure preservation and actual node reuse.

This is a mapped, nonaliasing storage domain with valid concrete vtables and bounded
names. Opaque descriptor addresses do not establish pointer validity at the real
service. Overlap, arbitrary virtual implementations, cyclic/double-owned pools,
concurrent/reentrant service behavior and real kernel interpretation remain outside
comparison. The oracle checks observable boundary/return state, not identical store
ordering between boundaries. Instruction visitation does not prove every predication
outcome. This is not matching, a whole-game build, live gameplay or a native port.

Audit: `local/validation/archive-descriptor-20261008-audit/COMPLETE.json`.
See `negative-checks.json`, `regressions.json`, `public-tests.log` and
`validation-jobs.json` for exact checks and exits. All **134 public tests pass**. Six compiled faults test wrong
request size, late service capture, failure-output clobber, duplicated handle high
word, selector-byte shift and wrong rollback virtual slot. Existing archive+clear,
archive IPC, file IPC and default ownership modes are checked against their accepted
full comparison objects. The three modes without clear retain exact accepted binary
hashes. The archive+clear build is 3,140 rather than historical 3,132 bytes because
the pre-existing aligned-zero helper adds eight bytes. Rebuilding with the hash-
verified historical clear source exactly reproduces the historical binary; see
`clear-baseline-explanation.json` and its recorded compiler commands. This isolates
the difference without altering source or weakening the behavioral regression.
The first audit stopped on that binary assertion; remaining checks continued only
after this explanation was verified. Whole-project G1/G2 live and G3/compiler/
matching/transfer gates remain open.

```powershell
python tools/check_resource_worker_file_owner.py --recover-descriptor --output local/validation/NEW-DESCRIPTOR
python tools/check_resource_worker_file_owner.py --recover-descriptor --mutant descriptor-rollback --output local/validation/NEW-DESCRIPTOR-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-archive-services --recover-clear --output local/validation/NEW-ARCHIVE-CLEAR-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Recover **service-global publication and its initialization request**:
ARM `0x0011BA54..0x0011BA78` and `0x001272D4..0x00127308`. The former publishes the
incoming service word to `0x0044E660`, passes a local copy and constant `0x040201C8`
to the latter, then returns zero regardless of its result. The IPC wrapper writes
header `0x08610042`, its incoming r1 and constant `0x20` at command+0/+4/+8,
then selects kernel or service result. Do not infer semantics for unwritten command
words or the constants. Exact saved extents, direct call linkage and literals are
in `local/validation/archive-descriptor-20261008-static/caller-ghidra.txt`,
`static-ghidra.txt`, `next-service-initialize.log` and `next-service-request.log`.

Reuse the archive/file checker TLS/SVC fixture. Compare exact request words and
untouched memory, service capture/global publication, kernel/service sign selection
in the direct wrapper, unconditional zero in its caller and persistent use of the
published service by the newly recovered descriptor registration chain. This is a
bounded global-publication contract, not complete service acquisition or startup.
Full read-service integration, backing storage/pool startup, initial lock construction
and diagnostic delivery remain open independent dependencies. Do not repeat the
completed descriptor/alternate/factory/owner lifetime milestones.
