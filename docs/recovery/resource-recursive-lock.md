# Recursive resource lock ownership and counts

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; no external implementation was reused.
Source names describe observed roles, not original symbols.

## Strategic review and acceptance

The completed clearing milestone was verified against its manifest, current
source/tool hashes and binary (`handoff-check.json` in the audit below).
This
advances A07/G2 source recovery and removes a concrete dependency of recovered
pool callers. Inner allocation and clearing are complete; optional extraction,
compiler work and port implementation are not prerequisites. No reprioritization
of the recorded next task was needed.

Acceptance declared before implementation: verify saved function extents; recover
the exact three-word layout, same-owner recursion, post-base-acquire TLS reread,
unsigned count wrap and owner publication before base release; build ARM source;
compare original/rebuilt behavior and execute the wrappers through selected pool
lifetimes. Keep TLS, exclusive-monitor, arbitration and concurrency limits explicit.
This bounded milestone passes. It does not close the deferred live G1/G2 gates.

## Recovered source

`src/resource_recursive_lock.c` and `.h` add two entry contracts:

| Original interval, end exclusive | Source function | Rebuilt bytes |
| --- | --- | ---: |
| `0x002C3AFC–0x002C3B34` | `smt4_worker_backend_acquire` | 80 |
| `0x002C3A78–0x002C3A98` | `smt4_worker_backend_release` | 28 |

The saved Ghidra bodies exactly match both intervals. Audit `static-ghidra.txt`,
primary `original-ghidra.txt` and independent GNU `original-smt4_*.log` listings
record the evidence. No saved project mutation was made.

The aligned argument addresses three 32-bit words: base lock at +0, TLS owner
at +4 and recursion count at +8. Acquire reads CP15 c13/c0/3 before loading the
owner. Equal values skip the base lock, even when both are zero. Otherwise it
calls recovered base acquire `0x001464F8`, rereads TLS and writes that new value
to the owner. It then loads and increments the count modulo 2^32. Neither zero
nor overflow is rejected; the count is loaded after the base call, not cached.

Release reads and decrements the count modulo 2^32 and stores it unconditionally.
Only a zero result clears the owner and enters recovered base release
`0x00138FC0`. In particular, initial zero becomes `0xFFFFFFFF` without releasing.
Release does not read TLS or validate ownership. The owner clear precedes base
release, so effects of a later arbitration callback are not overwritten.

Volatile word accesses preserve the observed field order/widths. The TLS helper
uses ARM MRC with a compiler memory clobber; it adds no hardware memory barrier.
The existing `src/resource_lock.c` remains unchanged and supplies both base-lock
contracts. These are original-address-space routines, not native synchronization
services. Return-register scratch values, matching instruction shape, timing,
arbitrary thread execution and a portable C concurrency model are not claimed.

## Direct original/rebuilt comparisons

Primary: `local/validation/recursive-lock-20261008-final-checked/COMPLETE.json`.
Pinned GCC builds a warning-clean freestanding ARMv6K image of **396 bytes**:
108 new wrapper bytes and 288 bytes of previously recovered base locks. Rebuilt
execution stays in the rebuilt image; no original helper instructions are used.

All **164 comparisons** pass, including **four bounded pending prefixes** and
two persistent four-call recursive lifetimes. The corpus crosses eight count
boundaries, equal/different ownership and TLS values including zero and all ones;
it also covers base-lock retry and contention schedules, release wake behavior,
and effects on owner/count at modeled arbitration. TLS may change after base
acquisition, explicitly testing the second read. Persistent calls acquire,
recursively acquire, release once, then release fully without reseeding the object.

Both paths must consume independent ordered wrapper events (TLS reads, field
loads/stores and base entry/return) and the existing base-lock event-plan oracle.
Checks cover exact field widths and order, exclusive attempts and retries, full
guarded object bytes, stack guards/restoration, callee-saved registers, initialized
reads, allowed memory/PC extents and instruction budgets. `results.tsv` records
inputs, accepted wrapper/base events and final three-word bytes. Pending cases
stop before a scheduled next exclusive load and do not claim a return or liveness.

All **22 wrapper sites** and 54 previously recovered base sites are visited;
the retained base regression covers all 75 base sites. The new comparison executes
352 TLS observations, 188 base entries, 368 exclusive-store attempts and 16
arbitration calls across both paths. Counts describe the bounded corpus only.

TLS reads are intercepted MRC observations. LDREX/STREX/CLREX instructions execute,
but monitor outcomes and competing writes are scheduled. Arbitration `0x002A88FC`
is intercepted with checked arguments, caller clobbers and optional state changes.
Its kernel effects and arbitrary real concurrency remain outside this checker.

## Pool integration and models removed

Primary: `local/validation/recursive-lock-backend-20261008-final-checked/COMPLETE.json`.
The backend checker now accepts `--recover-locks`; combined with `--recover-clear`
it builds a **2,372-byte** image and passes **619 caller comparisons** with six
persistent sequences. The 607 retained cases remain, and twelve calls add three
nested pool sequences with outer counts 1, `0x7FFFFFFF` and `0xFFFFFFFE`.

Pool take, factory, disposal and prefix registration/removal execute real recursive
and base locks. At each wrapper entry, the caller-state oracle checks all fixture
bytes; actual instructions execute to the saved return address, and the resulting
state must equal the independent expected state. No modeled lock result is copied
into memory. Same-owner pool reuse preserves the outer owner/count; ordinary
creation/disposal returns the lock to base=1, owner=0, count=0.

The mode executes **1,344 recursive wrapper calls**, **1,296 exclusive stores**,
**1,320 TLS reads** and **114 clearing calls**, across both paths. Its monitor
always succeeds, TLS is fixed, and no arbitration path is reached. Contention
and pending prefixes are covered separately by the direct checker. The artificial
state mutation previously attached to lock callbacks is disabled in this mode;
real lock instructions have no such service callback. Other service/diagnostic
effects remain as specified by the backend oracle.

Initial pool storage and lock words are synthetic. Archive services, diagnostics
and alternate callback dispatch remain modeled. The file-owner and other allocator/
worker modes retain their documented lock models. The new header link, builder
option, execution hooks, oracle and manifest changes support the two recovered
contracts; they are not additional game-code recovery.

## Audit, regressions and limits

Audit: `local/validation/recursive-lock-20261008-audit/COMPLETE.json`.
`negative-checks.json` records three compiled faults rejected by behavioral
assertions: cached TLS misses the second observation; clearing owner after base
release violates publication order; saturating increment stores `0xFFFFFFFF`
where wrapping requires zero. The final saturation fault reads the count once,
so that rejection tests arithmetic rather than an extra volatile read.

Retained base-lock, backend-clear and archive/file-owner-clear runs reproduce
their accepted binary hashes and entire comparison objects: **4,156**, **607**
and **670** comparisons in **288**, **1,976** and **3,132** bytes respectively.
`regressions.json` identifies both old and fresh manifests. All **134 public
tests** pass (`public-tests-console.log`). `validation-jobs.json` records commands
and exits. The final direct/pool rechecks retain identical binaries/comparisons
after refining the negative fault and combined-mode metadata.

The first development comparison mistook a base acquire retry at the entry address
for a second wrapper call; the harness now recognizes entry only while outside
the base routine. The recovered source did not change to accommodate that failure.
A temporary audit script named `inspect.py` initially shadowed Python's standard
module; renaming it fixed the inspection launcher. Neither failure is acceptance
evidence. All started commands completed, including sequential Ghidra jobs.

Mapped aligned lock objects, bounded schedules and synthetic pool objects are the
validated domain. Invalid pointers, aliasing with code/stack, arbitrary contention,
kernel monitor fidelity, runtime lock construction and full allocator ownership
remain open. Full ABI, matching, original-target application
builds, live gameplay and provenance/transfer gates remain separate.

```powershell
python tools/check_resource_recursive_lock.py --output local/validation/NEW-RECURSIVE-LOCK
python tools/check_resource_recursive_lock.py --mutant count-wrap --output local/validation/NEW-LOCK-NEGATIVE
python tools/check_resource_worker_backend.py --recover-clear --recover-locks --output local/validation/NEW-LOCK-POOL
python tools/check_resource_lock.py --output local/validation/NEW-BASE-LOCK
python tools/check_resource_worker_backend.py --recover-clear --output local/validation/NEW-BACKEND-REGRESSION
python tools/check_resource_worker_file_owner.py --recover-archive-services --recover-clear --output local/validation/NEW-OWNER-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Recover pool storage initialization **`0x002A4EB4–0x002A4F54`**, batching its
connected recursive-lock initializer **`0x002C3B54–0x002C3B70`** and base initializer
**`0x00138F44–0x00138F5C`**. Audit `next-pool-config.txt` and `next-pool-leads.txt`
confirm these saved bodies. `next-pool-init.log` shows the original caller
`0x00146284`: pool configuration at `0x00146308`, lock initialization at
`0x00146310`, and subsequent recovered pool take at `0x00146334`. This directly
supports replacing initial topology/lock fixtures in a bounded pool lifetime.

Static findings only: the six-argument pool initializer rounds element size and
storage start by division/multiplication, derives usable bytes, writes options,
stride/start/bytes/count/alignment fields, then builds its free list backward.
It rereads stride/start from +0x18/+0x1C in the loop and uses unsigned comparisons.
Reuse recovered quotient `0x002C6C64` in `src/unsigned_quotient.c`; it currently
claims nonzero divisors only. The base initializer retries exclusive stores of
one; the recursive initializer calls it before clearing owner/count.

Next acceptance: preserve wrapping arithmetic and exact pool/arena writes,
non-power-of-two alignment in bounded nonzero-divisor fixtures, initialization
store order and failed-exclusive prefixes; execute initialized topology/locks
through actual pool take/return/reuse. Start with a mapped valid arena and keep
zero-divisor, pathological wrapping/nonterminating lists, backing storage ownership
and global startup explicit. Reuse this package's pool and exclusive harnesses.
Do not treat adjacent archive-factory listings in the audit as an admitted task,
and do not repeat recursive acquire/release or start extraction/port work.
