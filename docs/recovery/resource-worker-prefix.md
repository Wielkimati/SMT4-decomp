# Worker prefix registration and removal

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored behavioral source; names describe observed contracts, not
original library symbols. No external implementation was reused.

## Strategic review and acceptance

Configuration and the older allocator objective are
complete. Prefix mutation is the next connected milestone: it replaces the
populated registry fixture feeding recovered resolver/open behavior. All 41
prior source/tool/binary identities matched before edits
(`local/validation/worker-prefix-20261008-audit/handoff-check.json`).
Optional extraction/compiler research, live checks and port work remain deferred.

Acceptance declared before implementation: instruction-backed normalization and
signed-byte keys; exact invalid/duplicate/full/missing statuses; vacancy before
duplicate checks; guarded key/pointer/flag writes; clear before disposal and a
post-call global reload; persistent register/open/remove/reuse; warning-clean ARM
build, original/rebuilt comparisons, meaningful fault rejection and retained
regressions. Registry startup, backend disposal and diagnostic delivery remain
explicit dependencies, not claimed recovered callees.

## Recovered contracts

`src/resource_worker_prefix.c` and `.h` implement:

| Original ARM body (end exclusive) | Source contract |
| --- | --- |
| `[0x002B5E70,0x002B5FB8)` | `smt4_worker_prefix_register` |
| `[0x002C4054,0x002C41A4)` | `smt4_worker_prefix_remove` |

Both normalize byte names, stopping at NUL or colon among the first eight
bytes. The normalized delimiter is colon. Thus ordinary valid names have at
most seven bytes. Packing shifts the previous 64-bit key left eight and ORs a
**sign-extended** byte. Source uses unsigned word-pair arithmetic to preserve
this without signed-overflow assumptions. The local shared normalization helper
is a source factoring, not a third recovered original entry.

If no delimiter appears, both enter diagnostic `0x002BCE9C`. The primary evidence
for that chain remains the cleanup report: it reaches SVC `0x3C`; normal return
is not established. Separate terminal probes stop at diagnostic entry. Under an
explicit returning model, both read eight bytes at private `0x00407FBC`, looking
only for colon. The pinned bytes contain no colon, producing key zero. NUL in
this fallback is not a delimiter. Source keeps this private-data dependency and
the conditional continuation rather than assuming diagnostics return.

The registry at `0x004D43E0` contains 32 records with 16-byte stride: key low/high
at +0/+4, backend at +8, byte flags at +12/+13, preserved bytes +14/+15. The open
header now declares this storage writable. Resolver semantics are unchanged.

Registration rejects zero keys with `0xE0E046BC`. It scans in order and checks
the backend word for vacancy **before** comparing the key. At the first vacancy
it writes both key words, the supplied backend, and the low bytes of both flag
arguments, returning zero. A zero backend is accepted and leaves the record
vacant for later registrations. An occupied equal key returns `0xC82044B4`.
Exhausting the table returns `0xD8604659`. A vacant equal-key record is reusable;
an earlier vacancy can admit a duplicate of a later occupied record.

Removal searches even a zero key, taking the first equal record regardless of
backend. It captures backend and +13, clears backend then both key words, and
preserves both flags and the trailing bytes. A captured null backend returns
`0xC8804465` **after clearing**, without searching a later duplicate. No match
also returns that status. A nonnull backend returns zero. Only a zero +13 flag
invokes backend vtable slot +0x30, with the backend as receiver. Its result is
ignored. After it returns, removal reloads global word `0x0044E658` and clears
it only if it still equals the removed backend. A nonzero +13 suppresses both
disposal and the global comparison. Callback changes to the cleared record
survive; the routine does not clear it a second time.

## Integration and comparison domain

New `--recover-prefix` implies configuration and the existing bootstrap, locale,
path, cleanup, open, read, position, method and allocation chain. After locale configuration and before the
connected worker I/O body it executes registration into guarded synthetic storage.
All 32 destination positions are exercised. The populated matching record is
therefore produced by recovered source. Initial vacant/occupied storage and
backend objects remain fixtures. Earlier modes keep their original setup.

Direct mutation probes and persistent sequences execute the two new entries and
the existing open/resolver chain. Backend +0x30 disposal is a scripted model that
can preserve/replace/clear the global, publish the removed backend into it, or
repopulate the cleared record. The model clobbers volatile registers and flags.
Assertions check the cleared record and unchanged global at callback entry,
then exact final storage and the post-call reload.

The domain uses mapped 32-bit addresses, readable name prefixes, nonaliasing
name/table/global/backend storage and valid backend/vtable objects for disposal.
Names need only the bytes through the first delimiter, or eight bytes on the
diagnostic path. Exact input/fallback read footprints, complete table/global
guards, immutable backend/name bytes, stack restoration and callee-saved
registers are checked. Callback mutation is scripted, not a proof of arbitrary
reentrant calls or concurrent mutation. No real filesystem or lifetime policy,
null/invalid name handling, binary matching, full-game build or live agreement
is established.

This package adds **two original contracts** and replaces the populated prefix
fixture in its connected mode. There was no existing intercepted registration
or removal call to remove. The writable declaration, build option and checker
extension are integration/supporting changes, not additional recovered routines.
Private locale/mapping data and callback relocation, OS read/size, backend
open/close/disposal, diagnostics, allocator ownership, raw storage/registration,
clearing, locks and registry startup remain modeled or open. G1/G2 live evidence
and full ABI/provenance/transfer gates remain open.

## Validation

Primary: `local/validation/worker-prefix-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K image is **5,052 bytes**, adding
**504 compiled text bytes**: 164 shared normalization, 164 registration and
176 removal. Compiler rodata remains 16 bytes. All **166** original instructions
in the new bodies were visited (1,222 combined). Visitation does not establish
every predication outcome or live coverage. GCC remains a behavioral toolchain,
not an identified matching compiler.

The **692 direct pairs** exercise every table position, vacancy/duplicate order,
null publication/removal, full-table rejection, zero keys, NUL/colon and
seven/eight-byte boundaries, four input alignments, sign transitions at every
byte position of one- through seven-byte keys, noncanonical flag words, and
disposal/global effects. **Six persistent sequences** (three per implementation)
register, open, reject a duplicate, remove, fail to open, reuse the slot with a
different backend, open, remove and fail to open again. There are **12 terminal**
and **12 explicitly returning diagnostic probes**, and **290 modeled disposal
calls**, counting both implementations.

The **2,304 connected worker pairs** execute **4,608 registrations**, then the
existing configuration/conversion/open/read/cleanup chain. All inherited direct
probes remain active with their original documented boundaries.

Audit: `local/validation/worker-prefix-20261008-audit/COMPLETE.json`.
Three compiled faults are rejected (`negative-checks.json`): checking a stale
equal key before vacancy, unsigned key bytes, and caching the global before
disposal. The first two fail guarded table-state assertions; the third fails
the post-disposal global assertion. Retained configuration and legacy I/O modes
reproduce their accepted **complete comparison objects and binaries** (4,548
and 548 bytes), recorded in `regressions.json`. All **134 public tests** pass;
both streams and actual exit zero are captured in `public-tests-console.log`.
`validation-jobs.json` records all eight sequential audit jobs, commands, exit
codes and durations. No launched job remains active.

The development run passed. Before final validation, the checker was strengthened
to assert pre-publication state for both diagnostic continuations, and the
reload fault became specifically a cached-before-disposal fault. No recovered
source fix was required. Final validation uses the exact recorded source/tool
hashes. The workspace audit checks those identities, the unchanged pinned
executable, package files and whitespace.

Run from `SMT4-decomp`, with fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-prefix --output local/validation/NEW-PREFIX
python tools/check_resource_worker_io.py --recover-prefix --mutant registry-reload --output local/validation/NEW-PREFIX-NEGATIVE
python tools/check_resource_worker_io.py --recover-locale-config --output local/validation/NEW-CONFIG-REGRESSION
python -m unittest discover -s tests
```

## Continuation: backend lifetime completed

The package described below is now recovered and validated in
[backend lifetime](resource-worker-backend.md). Its dedicated persistent
sequences execute concrete archive disposal; this report's original checker
mode and evidence retain modeled disposal.

### Original continuation findings

Recover the **concrete backend ownership lifetime** installed by factory
`0x003568C8`: pool take `0x002B5D6C`, disposal `0x003562D0`, teardown
`0x0035674C`, checked service-word accessor `0x0023A004`, and singleton
registration caller `0x00354DEC`. Batch factory/caller integration with those
lifetime routines when fixtures permit. This follows the actual backend behind
registry removal's modeled vtable +0x30, rather than selecting an unrelated leaf.

Static continuation evidence is in the audit's `next-registry-ghidra.txt`,
`next-function-354dec.c`, `next-backend-link.json`, and
`next-backend-{factory,pool-take,dispose,teardown,accessor}-disassembly.log`.
The factory uses pool `0x004D431C` and vtable `0x004209F8`; its +0x30/+0x34
words identify disposal/teardown. Instruction extents to verify against saved
function objects are `[0x003568C8,0x00356974)`, `[0x002B5D6C,0x002B5DD0)`,
`[0x003562D0,0x0035631C)`, `[0x0035674C,0x003567A0)`,
`[0x0023A004,0x0023A028)` and `[0x00354DEC,0x00354E60)`.
These are static findings only, not new recovered contracts.

Next acceptance: guarded pool head/count updates, empty-pool behavior and
optional clear arguments; factory service-error output preservation versus
allocation-failure null publication and service cleanup; actual object/vtable
construction; teardown's conditional 64-bit-handle close and post-call clearing;
disposal-before-pool-return; singleton registration rollback/publication; then
persistent create/register/open/remove/reuse on the same objects. Keep OS/archive
open `0x002ADBE8`, close `0x002ADBB8`, diagnostic `0x002BBD70`, lock calls and
optional clear `0x00139F54` explicit until separately recovered. The checked
accessor reloads +4 after its zero-value diagnostic; do not assume that call
returns without a stated model.

Registry startup remains open. GNU decoding at `0x003F3568` shows registry
construction through Thumb array helper `0x002C5FAC` and record initializer
`0x003561F0`, followed by several pool/lock initializers and destructor
registration. The saved Ghidra project has no containing function at the
inspected startup instruction or the record entry. This broader startup family
is not required for the bounded ownership lifetime above; its storage remains
synthetic.
