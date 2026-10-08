# Concrete file-object creation and close ownership

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored reconstruction; descriptive names are not original symbols.
No external implementation was reused.

## Strategic review and acceptance

Archive ownership is
complete. Concrete file ownership is its evidenced next dependency, through
archive vtable +0 and file vtable +0x2C/+0x30. The previous allocator objective
and optional extraction queue are superseded completed/deferred work, not this
milestone. The prior backend manifest's source/tool identities all match; see
`local/validation/worker-file-owner-20261008-static/handoff-check.json`.

Acceptance declared before implementation: recover the four instruction-backed
contracts below; preserve the unsigned 512-byte limit, service-failure output,
construction and pool-exhaustion cleanup; check close/teardown/pool-return order
and callback reloads; execute persistent archive creation, registration, file
open/close, removal and reuse; build warning-clean ARM source, compare original
and rebuilt state, reject semantic faults and retain affected regressions.
File/archive services, kernel SVC, locks, clear, diagnostics and startup remain
explicit boundaries. This package meets that bounded acceptance. G1/G2 live
evidence and G3 compiler/ABI/provenance/transfer gates remain open.

## Recovered contracts

`src/resource_worker_file_owner.c` and `.h` add four original ARM contracts:

| Original body, exclusive end | Source contract |
| --- | --- |
| `[0x003565A0,0x00356660)` | `smt4_worker_backend_file_open` |
| `[0x00239CD0,0x00239CF4)` | `smt4_worker_file_handle` |
| `[0x00356578,0x003565A0)` | `smt4_worker_file_teardown` |
| `[0x00356438,0x003564A4)` | `smt4_worker_file_dispose` |

All four match saved Ghidra function extents, checked before implementation in
the static directory's `function-disassembly.txt` and again in final validation.
Original vtable `0x004209F8` +0 names open. File vtable `0x00420998` +0x2C and
+0x30 name disposal and teardown. Source uses the existing generic pool take
`0x002B5D6C` with file pool `0x004D4358`, and the checked archive service accessor
`0x0023A004`. No saved-project annotation was changed.

Open checks descriptor word +8 as **unsigned** bytes: values above 512 return
`0xE0E046BF` without touching caller output or calling dependencies. It initializes
a local file handle to zero and gets the archive service. It then loads the
archive's 64-bit handle and descriptor type/data/bytes, and calls `0x00356C28`
with transaction zero, flags forwarded verbatim, and attributes zero. The
64-bit archive parameter starts on the stack; incoming r3 is ABI padding at
that service boundary. The three descriptor words are forwarded without
interpreting the pointed-to data. A returning diagnostic can change descriptor
words after the initial limit check: the original reloads them without another
check. This conditional continuation is explicitly exercised.

A negative service result is returned exactly, preserving caller output even
when the service writes the local handle. A nonnegative result takes a file
pool node. Success writes its handle at +4 and concrete vtable at +0, publishes
the node and returns zero. Exhaustion publishes **null**, closes the acquired
handle using original SVC `0x23` even if that handle is zero, ignores the SVC
result and returns `0xD8604659`. This differs from the outer recovered open
dispatcher `0x002BB944`, which preserves its caller output on either failure.

The checked file accessor returns object+4. Zero calls diagnostic `0x002BBD70`
with `0xE0A046DA` and original site `0x00239CEC`. A returning continuation
reloads object+4; terminal probes stop at diagnostic entry. The comparison does
not establish that diagnostics normally return.

Teardown closes a nonzero object+4 via SVC `0x23`, then clears that word after
the SVC returns, regardless of its result or scripted handle mutation. Zero
skips the SVC. It preserves the vtable, returns the receiver and touches no
other object fields. It does not itself send the file-close service command.

Disposal first checks object+4. A nonzero value goes through the checked accessor
and is copied to a local word for file-close `0x00356D5C`. Its result and any
change to that local copy are ignored. After the service, disposal **reloads
the receiver's current vtable** and invokes +0x30. Thus service changes to the
handle or vtable affect teardown. It then locks file pool+0x30, stores the
current free head into object+0, publishes the object as the head, decrements
used count +0x2C modulo 32 bits, and tail-unlocks. Teardown's return is ignored.
The source retains virtual dispatch; an alternate scripted teardown establishes
that it is not hardcoded to the concrete method.

## Integration and model accounting

The dedicated `tools/check_resource_worker_file_owner.py` links the new source
with existing backend, prefix, open/resolver/UTF-16 and cleanup source. The
existing null-safe close dispatcher `0x002B9450` executes against the concrete
file object. Two persistent sequences, each with three rounds on **both**
implementations, create/register an archive, open a file, hit pool exhaustion,
hit service failure, close, reopen/reuse, close, remove the archive and attempt
an open through the removed prefix. Neither emulator is reseeded between calls.
Both file and archive pool heads/counts return to their expected state.

This adds **four recovered contracts**. In this new connected checker it
replaces the archive backend's modeled file-open virtual operation and executes
concrete file disposal behind the existing close dispatcher. Backend creation,
disposal, registration/removal and pool take are reused recovery, not new code.
Builder, header and oracle changes support these contracts and are not additional
game recovery. The older backend and worker checker modes retain their models;
the new checker does not imply that their historical corpora grew deeper.

File services `0x00356C28` / `0x00356D5C`, archive services `0x002ADBE8` /
`0x002ADBB8`, SVC `0x23`, lock/unlock, clearing and diagnostic delivery are
modeled. Pool/registry startup storage is synthetic. No original binary helper
executes on the rebuilt path. The linked cleanup translation unit also contains
other previously recovered methods, but this package executes only its close
dispatcher; its preclose/release externs are unreachable in this corpus.

## Validation and limits

Primary: `local/validation/worker-file-owner-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K build is **2,416 bytes**, including
**452 compiled bytes of new source**. All **257 original/rebuilt pairs** pass:
120 direct opens, 21 checked accessors, 20 teardowns, 21 disposals, 33 close
dispatches, 6 singleton registrations, 6 removals and 30 connected opens.
Persistent-sequence calls are included in those counts.

All **94 original target instruction sites** were visited; two are SVC sites
where execution is intercepted, so this does not establish kernel execution.
Both paths together make 242 modeled file-open calls, 84 modeled file-close
calls, 126 SVC-close calls and 14 alternate-teardown calls. Eight diagnostic
probes stop at entry and eighteen use explicitly returning models.

At every modeled boundary and on return, the independent oracle checks full
guarded pool/global/node/output/descriptor/name/path/registry regions, exact
service arguments, event order and output/status effects. Public-call stack
alignment, callee-saved registers, stack restoration and lower stack guards
are checked. Models clobber volatile registers/flags. SVC preserves LR and
callee-saved registers; its result and volatile registers are scripted.
GCC's leaf teardown has a four-byte-aligned SP at its SVC, while the original
has eight-byte alignment. SVC is an instruction, not an AAPCS public call;
word alignment is checked there, and eight-byte alignment remains required at
every actual function boundary. This is behavioral evidence, not ABI identity
or binary matching.

Cases cover descriptor lengths 0/1/511/512/513/0xFFFFFFFF; signed result
boundaries; type/flag/handle forwarding; output writes and non-writes by the
service model; empty/nonempty pools; option bit 0 versus other bits; zero,
normal and wrapping counts; zero/nonzero handles; callbacks clearing/replacing
handles and replacing vtables; lock-side pool changes; and reuse. Modeled
descriptor data is opaque and not dereferenced. The domain uses mapped,
word-aligned, nonaliasing caller/object/pool storage and two synthetic nodes.
Only eight-byte file-node clearing is used here; the prior pool checker retains
its broader clear-length corpus. Arbitrary pointer faults, concurrency, aliasing,
cyclic/double-return pools, real service behavior and live gameplay are outside
the evidence boundary. Instruction visitation is not all-predication coverage.

Audit: `local/validation/worker-file-owner-20261008-audit/COMPLETE.json`.
Three compiled faults test the 512-byte comparison, post-SVC clearing and
vtable reload after close. The retained archive-backend checker reproduces its
1,592-byte binary and full 607-pair comparison object. All 134 public tests pass.
The audit retains commands, exits, assertions, regression identity and logs.

The first development run stopped at an overstrict eight-byte-alignment check
at the rebuilt SVC; the second stopped because SVC scanning read an unmapped
synthetic callback address. Both were checker errors, corrected without changing
recovered source. Development run three passed. Final validation adds the
descriptor-reload and additional forwarding probes.

```powershell
python tools/check_resource_worker_file_owner.py --output local/validation/NEW-FILE-OWNER
python tools/check_resource_worker_file_owner.py --mutant dispose-reload --output local/validation/NEW-FILE-OWNER-NEGATIVE
python tools/check_resource_worker_backend.py --output local/validation/NEW-BACKEND-REGRESSION
python -m unittest discover -s tests
```

## Completed continuation and next independent milestone

Package 21 completed the file-service continuation below. See
[file-service IPC recovery](resource-worker-file-service.md): the optional
`--recover-services` mode executes both wrappers through these ownership
lifetimes, while this report's default mode retains its original models.
The next independent task is archive-service IPC `0x002ADBE8` / `0x002ADBB8`.
The following records this package's original handoff criteria.

Recover the now-explicit **file-service IPC request/response wrappers**:
open `[0x00356C28,0x00356C98)` and close `[0x00356D5C,0x00356D84)`.
Both saved function extents and instructions are in the static evidence;
the audit's `next-service-link.json` and `next-service-*-disassembly.log`
include literal headers `0x080201C2` and `0x08080000`. They read the TLS pointer
with `MRC p15,0,r4,c13,c0,3`, build commands at TLS+0x80 and enter SVC `0x32`.
These are static continuation findings, not recovered contracts.

Next acceptance: exact command-buffer words/descriptors and preservation of
unwritten words; original stack/64-bit argument transport; distinction between
kernel failure and service response status; open-handle output preservation on
kernel-negative return versus response publication; close response selection;
and execution of these wrappers in the current file-ownership lifetimes with
only TLS acquisition and SVC request/response left as explicit platform models.
Reuse the pinned build and checker; inspect available emulator support for the
named MRC/SVC only as necessary. Do not repeat file ownership or start general
IPC infrastructure, extraction, compiler or port work. Archive services, startup,
allocator ownership/storage, private locale data and deferred live gates remain
independent open dependencies.
