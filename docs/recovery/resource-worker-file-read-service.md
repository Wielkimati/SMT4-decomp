# Worker read service and pre-read delay

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored recovery in
[`resource_worker_file_read_service.c`](../../src/resource_worker_file_read_service.c).
No external implementation was reused.

## Strategic review and acceptance

The preceding size milestone is complete. Its manifest's 18 file hashes and
928-byte binary were checked before editing (`handoff-check.json` in this audit).
This replaces an aggregate game-code dependency under A07/G2; repeating the older
allocation objective or optional extraction would not advance this dependency.
G1/G2 live gates and G3 ABI/provenance/transfer gates remain open.

Acceptance selected before implementation: verify the original extents and
virtual slot; reconstruct dispatch, method, IPC and required pre-read side effects;
build ARM source and compare exact requests, output/payload effects, cursor/count
arithmetic and failures through the recovered loop; reject meaningful compiled
faults and preserve affected earlier modes. TLS, query/request SVCs, sleep and
diagnostics stay explicit models. The package satisfies that bounded milestone.

## Recovered source contracts

| Entry | Original instructions, exclusive end | Contract |
| --- | --- | --- |
| `0x002A4E54` | 23, `0x002A4EB0` | Read dispatch with null checks and pre-read delay |
| `0x003564A8` | 16, `0x003564E8` | Concrete file method, handle accessor and IPC |
| `0x00356D04` | 21, `0x00356D58` | Read command marshalling and count publication |
| `0x002ADC48` | 34 locally, `0x002ADCD0` | State-dependent query, quotient and delay selection |

The saved Ghidra helper body is disjoint: `[0x001382BC,0x001382CC)`,
`[0x001382E4,0x001382EC)` and `[0x002ADC48,0x002ADCD0)`. The first two
ranges are timing stubs included by analysis, not newly recovered source in this
package. The final checker asserts this exact saved body and separately enumerates
the 34 local instructions. The original branch at `0x002ADCC8` targets the already
recovered delay selector `0x002BB4F0`. Saved extents and instruction listings are
in `original-read-service-ghidra.txt`; independent GNU listings are the four
`smt4_worker_file_*.log` files in the primary directory.

Read dispatch receives count pointer/object in r0/r1, cursor low/high in r2/r3,
and buffer/byte count on the stack. It rejects a null **object or buffer** with
`0xE0E046BC`, without delay or virtual dispatch. It does not validate the count
pointer or reject a zero byte count. On a valid request it calls the helper with
argument one, then loads the object's vtable and calls slot +0. Vtable
`0x00420998` selects `0x003564A8`. A modeled sleep changing the object's vtable
proves the load occurs after the delay. Alternate virtual targets preserve the
six-argument forwarding and exact status.

The concrete method calls the already recovered handle accessor `0x00239CD0`,
stores the returned kernel handle locally and passes its address to IPC. The
accessor's zero-handle diagnostic can stop or return and change the handle; the
returned replacement is consumed. The accessor is reused, not a new contract.

IPC acquires TLS with `MRC p15,0,*,c13,c0,3`. At TLS+0x80 it writes:

| Word | Value |
| --- | --- |
| 0 | `0x080200C2` |
| 1 / 2 | cursor low / high |
| 3 | requested bytes |
| 4 | `(bytes << 4) | 12`, modulo 32 bits |
| 5 | buffer address |

Other command bytes are preserved. SVC `0x32` receives the captured handle in r0.
A negative kernel status returns unchanged and preserves count output. Every
nonnegative kernel status, including positive values, publishes response word 2
and returns response word 1. Publication also occurs when that service result is
negative. Actual buffer writes are kernel effects, distinct from count publication.
The source adds no validation or error-time payload rollback.

The pre-read helper uses state at `0x0044E650`, the same original address as the
backend state. Byte +0 zero returns immediately. Otherwise byte +1 nonzero enters
SVC `0x28` with that byte in r0. If returned r0 bit 4 is set, the helper divides
100 for a nonzero mode, or 380 for mode zero, by `(r0 & 15)+1`. It reuses
`src/unsigned_quotient.c` at the consumed nonzero-divisor contract. After the query
it reads state word +0x18, adds the quotient, truncates to 16 bits and, only when
nonzero, calls recovered `smt4_file_delay` with the result times 1,000,000 as an
int64. This always selects the modeled sleep boundary. Query-time state mutation
probes distinguish this load from an early cached load. Helper return registers
are incidental and not claimed by the void interface. The query's real meaning,
real elapsed time and scheduling are not inferred from its bits.

## Build and behavioral evidence

Primary: `local/validation/worker-read-service-20261008-final-checked/COMPLETE.json`.
The freestanding C11 ARMv6K build passes `-Wall -Wextra -Werror` and contains
**708 bytes**. Four new contracts account for **388 compiled bytes**: delay 124,
dispatch 108, IPC 92 and method 64. The rest reuses handle access, lower read,
read adapter, delay selector and unsigned quotient. `-fno-inline` preserves
call boundaries for the reused comparison hook; this is not a matching claim.
The rebuilt path executes no original instructions or original binary helpers.

All **824 original/rebuilt pairs** pass:

- 98 direct dispatch/method/IPC cases.
- 219 helper cases.
- 507 connected lower-read/adapter cases, including two persistent sequences
  on each path.

All **94 new original instruction sites** are visited, including intercepted
query, TLS and request instructions. Both paths together issue 1,462 TLS reads,
1,462 SVC read requests, 1,704 queries and 1,680 sleeps. Fourteen alternate virtual
calls and 24 diagnostic entries are checked. These are visitation/call counts,
not exhaustive input or predication coverage.

Direct requests cross independent kernel/service statuses zero, one, signed
maximum, sign-bit-only and all-ones; full-width cursors; descriptor truncation
at `0x10000000`; zero/one/large counts; null object/buffer combinations and
conditional null count storage. Nonzero sentinels guard the complete TLS region,
file/handle/vtable storage, count output and payload. Kernel responses change
command words even on kernel failure. Bounded error cases deliberately write
up to three payload bytes, ensuring failure paths preserve actual external
side effects while suppressing count/cursor publication as appropriate.

Helper cases cover both numerator branches (including all-ones mode), all 16
divisors, byte values zero/one/255, absent query result bit 4, unrelated high bits,
base-only delays, maximum 16-bit delay, 32-bit addition wrap, truncation to zero,
and query-time base replacement. Checked ordering includes query before sleep,
delay before command writes and vtable selection after sleep.

Connected cases reuse the independent Java signed-count/read-loop oracle. They
cover zero/full/short/zero-count reads, positive statuses, kernel and service
failures, failure after earlier progress, cursor carries and signed extrema,
32-bit total/buffer/remaining wrap, null/tag-only lower handles and buffer-null
failure. Full-width inconsistent counts use opaque buffers and bounded scripted
termination; they do not assert that real services return such counts. Two
persistent sequences retain TLS, cursor/cache and payload across short success,
failure, retry and zero request. Original/rebuilt traces, complete guarded data,
caller output, object state, stack restoration and callee-saved registers agree.
SVC models preserve LR/callee-saved registers and clobber volatile registers/flags;
public call alignment and word alignment at SVC are checked separately.

The final checked run narrows the reused delay PC whitelist to its documented
instruction extent and corrects two unused retained-target endpoint constants.
It reproduces the prior final binary and entire 824-pair comparison object;
`final-check.json` in the audit records equality and current input hashes.
The development pass had 809 pairs; the final pass adds 15 base-only/disabled-query
helper probes and retains the identical compiled binary. Initial static inspection
incorrectly expected a contiguous Ghidra helper body; saved disjoint membership
was inspected and explicitly asserted. No source disagreement or behavioral
assertion was bypassed.

## Models removed, integration and limits

This package adds **four entry contracts**, bringing the maintained total to
**108 plus two adapted worker regions**. It removes the aggregate
`smt4_worker_file_read_service` model in the new standalone checker through the
recovered lower loop and read adapter. The helper, quotient, delay selector,
concrete method, accessor and IPC all execute. Header declarations, builder,
comparison hook, oracle and metadata are supporting integration work.

Concrete file objects/vtables, backend state and TLS storage are synthetic.
The complete worker's ownership/open/size/read/close chain is not yet combined
in this checker. Older worker-I/O modes retain their read-service models and
wider opaque-handle/buffer domains; the new optional hook leaves their default
behavior intact. Size-service and file/archive lifetime checkers retain their
own documented scopes. Platform query, TLS, SVC request/payload, sleep and
diagnostic delivery remain models. Pool/registry startup, allocator ownership,
clearing and locks remain independent recovery/integration work.

Evidence is bounded to mapped, nonaliasing objects, word-aligned outputs and
reachable scripted streams. Nulls are included only on paths that do not
dereference them. Arbitrary faults/aliasing, concurrent mutation, unbounded
streams, genuine filesystem effects and live gameplay remain unverified. This
is neither a full original-target build nor a native port or live gate closure.

## Reproduce and audit

```powershell
python tools/check_resource_worker_read_service.py --output local/validation/NEW-READ-SERVICE
python tools/check_resource_worker_read_service.py --mutant truncate --output local/validation/NEW-READ-SERVICE-NEGATIVE
python tools/check_resource_worker_io.py --recover-file-read --output local/validation/NEW-READ-REGRESSION
python tools/check_resource_worker_file_size.py --output local/validation/NEW-SIZE-REGRESSION
python -m unittest discover -s tests
```

Audit: `local/validation/worker-read-service-20261008-audit/COMPLETE.json`.
Detailed commands and actual results are in its `commands.json`,
`negative-checks.json`, `regressions.json` and `public-tests-console.log`.
Seven compiled faults are rejected: a missing single-null guard, wrong vtable
slot, wrong buffer descriptor, positive kernel status treated as failure,
publication suppressed on service failure, truncation before addition and swapped
delay numerators. The retained read-mode regression reproduces its exact
**1,764-byte** binary and complete comparison object; size reproduces its exact
**928-byte** binary and all **576 pairs**. All **134 public tests pass**.
All Ghidra work ran sequentially on the authoritative read-only project, and all
started commands finished.

## Next independent milestone

Recover **clearing used by pool and worker allocations**:
`smt4_worker_backend_clear` at `0x00139F54` and
`smt4_resource_allocate_zero` at `0x002C3B9C`, including its consumed shared
word/tail body at `0x002C4B88`. These are still modeled in the recovered backend
pool and allocation paths. Static GNU leads are `next-clear-pool.log`,
`next-clear-allocation.log` and `next-clear-shared.log` in this audit.
Candidate exclusive ends are `0x00139F84`, `0x002C3BDC` and `0x002C4BD8`;
verify saved disjoint function membership before implementation.

The pool helper fills words until the address equals the exclusive end; it does
not compare unsigned ordering or round an invalid endpoint. The byte-count
helper handles initial unaligned bytes, reaches the shared word loop and writes
an exact tail. Preserve observed widths/alignment/count behavior and bound mapped
fixtures; do not turn either into a safer native replacement. Reuse backend/file
pool ownership and worker allocation harnesses to replace actual clear models
through allocation, option-controlled clearing and reuse. Relevant sources are
`src/resource_worker_backend.c`, `src/resource_worker_data_allocate.c` and
`src/resource_allocate_lower.c`; reuse `tools/check_resource_worker_backend.py`
and `tools/check_resource_worker_io.py --recover-allocation` or the data checker
for caller integration. Acceptance should include untouched guards, zero lengths,
word values, alignment/tail/block boundaries and caller-state preservation.
These are next-task static leads only; no clearing source is recovered here.
