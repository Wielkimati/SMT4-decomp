# Archive-service IPC open and close

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored reconstruction; descriptive names are not original symbols.
No external implementation was reused.

## Strategic review and acceptance

The file-service milestone is complete, as is the earlier allocator objective.
Archive open/close are the next connected, evidenced call models. Deferred live
checks and optional extraction/compiler work do not block this source target.
The prior manifest's source/tool hashes matched; see the audit's
`handoff-check.json`. Both candidate extents were checked in the saved Ghidra
project before implementation (`original-extents.txt`).

Acceptance: recover archive open `0x002ADBE8` and close `0x002ADBB8`; preserve
request words and untouched memory, stack descriptor and 64-bit transport,
kernel/service result selection and handle publication; execute factory
failure/exhaustion cleanup, registration rollback and persistent archive/file
reuse; build ARM source, compare original/rebuilt behavior, reject semantic
faults and retain affected regressions. TLS and kernel behavior stay modeled.
The evidence below meets this bounded milestone. Whole-project gates do not change.

## Recovered source contracts

`src/resource_worker_archive_service.c` implements the existing declarations in
`src/resource_worker_backend.h`:

| Original ARM body, exclusive end | Contract |
| --- | --- |
| `[0x002ADBE8,0x002ADC44)` | `smt4_worker_backend_archive_open` |
| `[0x002ADBB8,0x002ADBE4)` | `smt4_worker_backend_archive_close` |

Both match saved function extents. Raw GNU decoding, saved Ghidra instructions,
literal headers and the hash-bound mapped executable agree. Literal header
words at the exclusive ends are data, outside the 34 instruction sites.

Both read TLS with `MRC p15,0,Rd,c13,c0,3`, use TLS+0x80 as their command buffer,
load the service handle through their first argument and enter SVC `0x32`.
Open receives service/output/archive/type in r0/r1/r2/r3 and data/byte length
in two caller stack words. It writes:

| Command offset | Value |
| --- | --- |
| +0x00 | `0x080C00C2` |
| +0x04 | archive identifier |
| +0x08 | path type |
| +0x0C | byte length |
| +0x10 | `(byte_length << 14) OR 2`, modulo 32 bits |
| +0x14 | opaque data address |

The source retains original store order: header, length, descriptor/data, then
archive/type. It imposes no size limit and does not dereference path data.
On a kernel result with bit 31 set, open returns that result and preserves both
caller output words even if the modeled response changed command memory.
Every nonnegative kernel result publishes the low/high words from command+8/+12,
then returns command+4. Publication also occurs on negative service status.
A volatile output store preserves publication before the service-status read
in the rebuilt instructions. This is not an aliasing or concurrency guarantee.

Close receives the 64-bit archive in r2/r3 with unused r1 padding. It writes
header `0x080E0080` and low/high archive words at command+0/+4/+8. All other
command words remain untouched before SVC. Negative kernel results return
unchanged; otherwise it returns command+4. It does not alter the input service
word and has no caller output. Positive kernel results are not failures.

## Integration and models removed

`tools/check_resource_worker_file_owner.py --recover-archive-services` implies
`--recover-services`, linking archive/file IPC with existing ownership, backend,
prefix, open and cleanup source. The original machine executes both archive
bodies; the rebuilt machine executes their compiled source. Both acquire modeled
TLS pointers, construct real request bytes, enter the explicit kernel response
model and execute response selection/publication themselves.

This adds **two recovered contracts** and removes **two archive-service call
models** in the new mode. The earlier file-service contracts are reused, not
counted as new. Builder, header, oracle, symbol and report edits support this
source and are not additional game recovery. The older file-service/default
modes retain their exact models and comparisons.

The factory's local self-referential path descriptor has different original and
rebuilt stack addresses. The oracle validates each actual pointer, its two words,
caller stack bounds and aligned output at archive entry. It canonicalizes only
that descriptor address in command+0x14 for cross-build guarded-memory checks,
including stale command contents after subsequent close. No output values,
status words or other request fields are normalized. Direct opaque data probes
need no relocation.

TLS acquisition, SVC request/response and close-handle behavior, locks, clearing
and diagnostics remain models. Registry/pool startup is synthetic. The inherited
aggregate `services_svc_locks_clear_diagnostics_modeled` flag remains true for
platform service behavior; `archive-services.json` explicitly records that
archive call interception is removed. Neither actual kernel/service behavior
nor real archive identity is established.

## Validation

Primary: `local/validation/worker-archive-service-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K image is **2,748 bytes**, including
**160 compiled bytes** for the archive source. All **670 original/rebuilt pairs**
pass: 61 direct archive opens, 61 direct archive closes, 134 factory calls,
26 singleton calls, 8 archive teardowns and 380 other retained/connected probes.
The two persistent sequences run three archive/file rounds each on each machine.
All **34 new archive instruction sites**, 38 retained file-IPC sites and 94
retained ownership sites are visited. Four archive sites are intercepted MRC/SVC
instructions, not executed platform operations. Both implementations together
perform 442 archive opens, 198 archive closes, 392 file opens and 192 file closes:
1,224 modeled TLS acquisitions and SVC requests in total.

The state oracle checks every guarded TLS, input, output, object, pool and
registry byte before modeled boundaries and at return. Distinct nonzero initial
command words detect accidental clearing. Responses either preserve command
memory or write status, both archive words and an extra response word. Independent
kernel/service values cover zero, positive, maximum positive, sign-bit-only and
all-bit results. Byte lengths cover 0/1/511/512/513, the 18-bit descriptor-shift
boundary and full-width values. Distinct low/high values, zero/one/high-only/all-bit
handles, arbitrary path types/data, poisoned ABI padding and caller argument
preservation catch truncation and transport mistakes.

Connected cases cover factory output preservation versus null publication,
service capture/reload under callback changes, exhaustion close, duplicate/full
registration rollback, zero-handle disposal, terminal/returning diagnostics and
captured handle use. Persistent sequences retain memory across archive kernel
and service failures, success, archive exhaustion while an owner remains active,
file failures/exhaustion, close, removal and reuse. Public-call stack alignment,
callee-saved registers, stack restoration and lower guards are checked. SVC
requires word alignment; GCC leaf wrappers can retain four-byte alignment there.
The model preserves LR/callee-saved registers and clobbers volatile registers/flags.

Audit: `local/validation/worker-archive-service-20261008-audit/COMPLETE.json`.
Four compiled faults were rejected: wrong descriptor shift, duplicated high
handle word, positive kernel results treated as failure, and output publication
conditional on service success. Both retained regressions reproduce their exact
binary hashes and complete comparison objects: file service **2,588 bytes / 386
pairs**, default ownership **2,416 bytes / 257 pairs**. All **134 public tests**
pass. Commands, exits, assertions and manifests remain in the audit. Development
validation passed 664 pairs; final validation adds six persistent exhaustion
probes and enforces publication ordering explicitly.

The bounded domain uses mapped, nonaliasing word-aligned storage, aligned 64-bit
outputs and synthetic pools/registries. Opaque path data includes zero and full-width
values. Pointer faults, overlapping TLS/arguments, concurrency, alternate TLS,
real services and live gameplay remain unverified. Instruction visitation does
not establish every predication outcome. This is a subsystem ARM build, not
matching, a complete 3DS build or native port.

```powershell
python tools/check_resource_worker_file_owner.py --recover-archive-services --output local/validation/NEW-ARCHIVE-SERVICE
python tools/check_resource_worker_file_owner.py --recover-archive-services --mutant archive-high --output local/validation/NEW-ARCHIVE-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-services --output local/validation/NEW-FILE-SERVICE-REGRESSION
python tools/check_resource_worker_file_owner.py --output local/validation/NEW-OWNER-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Recover the **file-size service chain**: dispatcher `0x002A8914`, concrete file
method `0x003DFCA8`, and IPC wrapper `0x00356DE8`. The existing size/cache/seek
source still models `smt4_worker_file_size_service`. The audit's
`next-dispatch-link.json` and `next-size*.log` establish static linkage: dispatcher
uses vtable+8; file vtable `0x00420998` holds `0x003DFCA8` there; that method
calls recovered handle accessor `0x00239CD0` and IPC `0x00356DE8`. Candidate body
ends are `0x002A893C`, `0x003DFCC8`, `0x00356E1C`; verify saved extents first.
The IPC header is `0x08040000`, with TLS/SVC and 64-bit output behavior visible.

Use the owner checker for concrete object/accessor/IPC fixtures and
`tools/check_resource_worker_io.py --recover-file-position` plus
`docs/recovery/resource-worker-file-position.md` for affected cache/seek callers.
Replace the size-service call model through that bounded chain, checking null
arguments, virtual dispatch, failure output preservation, cache clearing versus
publication and seek boundaries; retain TLS/SVC models. Do not blindly treat the
read boundary as another IPC leaf: `0x002A4E54` calls `0x002ADC48` before virtual
dispatch. Read-method/static leads are saved, but that separate side-effect
boundary needs inspection when read recovery is selected. Allocator ownership,
startup, synchronization and live gates remain independent open dependencies.
