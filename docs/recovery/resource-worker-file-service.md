# File-service IPC open and close

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored reconstruction; descriptive names are not original symbols.
No external implementation was reused.

## Strategic review and acceptance

Concrete file ownership is complete; its two modeled file-service calls are
the next evidenced dependency. The old allocator objective is already complete,
and optional extraction/compiler work does not unblock this target. Neither
deferred live gates nor downstream port work prevents this bounded recovery.

Acceptance declared before implementation: recover open `0x00356C28` and close
`0x00356D5C`; preserve exact TLS command words and untouched memory, stack/64-bit
argument transport, kernel versus service result selection and handle output;
execute the wrappers through existing file ownership lifetimes; build ARM source,
compare original/rebuilt behavior, reject semantic faults and retain affected
regressions. TLS acquisition and SVC responses remain explicit platform models.
The evidence below satisfies this milestone; it does not close G1/G2 or G3.

## Recovered contracts

`src/resource_worker_file_service.c` implements the existing declarations in
`src/resource_worker_file_owner.h`:

| Original ARM body, exclusive end | Contract |
| --- | --- |
| `[0x00356C28,0x00356C98)` | `smt4_worker_file_service_open` |
| `[0x00356D5C,0x00356D84)` | `smt4_worker_file_service_close` |

Both bodies agree with saved Ghidra extents. The prior ownership audit contains
independent raw ARM disassembly and literal headers; final evidence repeats raw
disassembly and saves Ghidra instructions and extents. The literal words at the
exclusive ends are data, outside the function instruction counts.

Both read TLS using `MRC p15,0,Rd,c13,c0,3` and use the command buffer at TLS+0x80.
Open constructs these ten u32 words, in original order:

| Command offset | Value |
| --- | --- |
| +0x00 | `0x080201C2` |
| +0x04 | transaction |
| +0x08, +0x0C | archive low word, high word |
| +0x10 | path type |
| +0x14 | byte length |
| +0x18 | flags |
| +0x1C | attributes |
| +0x20 | `(byte_length << 14) OR 2`, modulo 32 bits |
| +0x24 | opaque data address |

The public ABI consumes service pointer, output pointer and transaction in
r0/r1/r2. r3 is padding before the aligned uint64 archive; its two words and
type/data/bytes/flags/attributes occupy seven caller stack words. The wrapper
imposes no descriptor-size check. Its caller's 512-byte check is a separate
recovered contract. No path data is dereferenced here.

After writing the command, open loads the handle through the service pointer
and enters SVC `0x32`. A kernel result with bit 31 set returns unchanged and
preserves the caller's handle output, regardless of scripted response writes.
Every nonnegative kernel result publishes command+0x0C to the handle output,
then returns command+0x04. Publication also occurs when that service status is
negative. It is not conditional on a zero kernel result or successful service
status. The output store precedes the service-status read.

Close writes only `0x08080000` at command+0, loads its handle through the input
pointer and enters SVC `0x32`. Negative kernel results return unchanged;
nonnegative results select command+4. It does not modify the input handle or
clear other command words. These wrappers do not themselves establish service
semantics, kernel execution or real handle validity.

## Integration and model accounting

`tools/check_resource_worker_file_owner.py --recover-services` links both
wrappers with the existing ownership/backend/prefix/open/cleanup sources.
It removes interception at `0x00356C28` and `0x00356D5C` only in this mode.
The rebuilt path uses these compiled definitions, without original binary
helpers. The original and rebuilt instructions acquire a modeled TLS pointer,
construct real command bytes, reach an explicit SVC request/response model,
and execute their own response selection and output stores.

Two persistent sequences run three archive/file rounds each on both machines.
Archive creation/registration, successful file open, exhaustion, service failure,
kernel failure, close, file reuse, removal and archive reuse execute without
reseeding state between calls. Thus stale command words survive across open/close
and later requests. Existing owner callback, diagnostic, vtable-reload, teardown
and pool-return probes also execute with the concrete file IPC wrappers.

This package adds **two recovered contracts** and removes **two file-service
call models** in the new mode. Header, builder, oracle, symbol and report changes
support that source; they are not additional game recovery. The default owner
checker and older worker/backend modes retain their exact prior boundaries.

TLS pointer acquisition, SVC `0x32` responses, SVC `0x23` close-handle behavior,
archive services `0x002ADBE8` / `0x002ADBB8`, locks, clearing and diagnostic
delivery remain modeled. Registry/pool startup is synthetic. The inherited
`services_svc_locks_clear_diagnostics_modeled` comparison field remains true
because archive services and platform operations are still modeled; the separate
`services.json` records removal of the two file-service call models.

## Validation and limitations

Primary: `local/validation/worker-file-service-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K image is **2,588 bytes**, including
**172 compiled bytes** for the new wrappers. All **386 original/rebuilt pairs**
pass: 61 direct service opens, 50 direct service closes, and 275 connected or
retained ownership/backend/prefix probes, including two persistent sequences.
All **38 new instruction sites** and all **94 retained ownership sites** are
visited. Four new sites are intercepted MRC/SVC instructions; this does not
establish execution of those platform operations. Both paths together acquire
TLS and send a request 584 times: 392 opens and 192 closes.

An independent state oracle checks every guarded TLS, input, output, object,
pool and registry byte at each modeled boundary and at return. Request buffers
start with distinct nonzero words; only documented stores may change them.
The SVC model either leaves the buffer untouched or overwrites status, handle
and an additional response word. Full response memory and unwritten words
remain checked. Kernel and service values independently exercise 0, 1,
`0x7FFFFFFF`, `0x80000000` and `0xFFFFFFFF`. Descriptor tests cover 0/1/511/512/513,
the 18-bit shift boundary and full-width values. Nonzero/distinct transaction,
archive halves, type, flags, attributes, handles and poisoned r3 detect argument
order, padding and truncation errors.

Checks enforce public-call eight-byte stack alignment, stack restoration,
callee-saved registers, caller stack argument preservation and lower stack
guards. SVC preserves LR and callee-saved registers while scripting r0 and
clobbering volatile registers/flags. As in the prior owner checker, SVC itself
requires word alignment: rebuilt leaf wrappers may use a four-byte-aligned SP
at this instruction. This is a behavioral build, not binary or ABI identity.

Audit: `local/validation/worker-file-service-20261008-audit/COMPLETE.json`.
Three compiled faults are rejected: wrong descriptor shift, handle publication
conditional on service success, and treating positive kernel results as failure.
The default owner regression reproduces its **2,416-byte binary and complete
257-pair comparison object**. All **134 public tests** pass. The audit records
commands, exits, failure assertions, source/reference hashes and next-target
static disassembly. The first development comparison also passed; final validation
adds kernel failures inside persistent lifetimes and service-entry alignment.

The bounded domain uses mapped, word-aligned, nonaliasing TLS, caller, object,
pool and registry storage with two synthetic file nodes. Data pointers are
opaque, including zero and full-width values. Kernel behavior, pointer faults,
overlapping arguments/TLS, concurrency, alternate TLS contexts, real services
and live gameplay remain unverified. Instruction visitation is not a claim of
every possible predication or aliasing behavior.

```powershell
python tools/check_resource_worker_file_owner.py --recover-services --output local/validation/NEW-FILE-SERVICE
python tools/check_resource_worker_file_owner.py --recover-services --mutant ipc-publish --output local/validation/NEW-FILE-SERVICE-NEGATIVE
python tools/check_resource_worker_file_owner.py --output local/validation/NEW-OWNER-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Recover **archive-service IPC open and close**, the remaining service-call models
in these connected lifetimes: open `0x002ADBE8` and close `0x002ADBB8`.
The audit's `next-archive-link.json` and `next-archive-*-console.log` bind static
instructions to the reference. Candidate exclusive body ends are `0x002ADC44`
and `0x002ADBE4`, immediately before literal headers `0x080C00C2` and
`0x080E0080`; saved Ghidra extents still need checking.

Both use TLS+0x80 and SVC `0x32`. Open transports stack descriptor arguments,
constructs six command words and publishes a 64-bit response at command+8 after
a nonnegative kernel result. Close transports the archive low/high words in
r2/r3. These are static leads, not yet recovered source contracts. Reuse the
owner checker's explicit MRC/SVC support and archive lifecycle oracle, checking
exact command words, untouched bytes, 64-bit publication, result selection,
factory failure/exhaustion cleanup and persistent archive/file reuse. Retain
TLS/SVC as platform models. Allocator ownership/storage, startup, synchronization,
private locale data and deferred live gates remain separate open dependencies.

Package-22 continuation: the archive milestone above is now validated in
[archive-service IPC](resource-worker-archive-service.md). Optional
`--recover-archive-services` implies this report's mode and removes both archive
call models. This report's original file-only mode, counts and models remain
unchanged and were reproduced byte-for-byte. File-size service recovery is next.
