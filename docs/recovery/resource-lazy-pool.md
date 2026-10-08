# Lazy static-pool allocation

2026-10-08. Project-authored EU base v0 instruction recovery, bound to expanded
executable SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed roles; no external implementation reused.

## Strategic review and acceptance

All recorded file hashes in
the primary initializer manifest still match; the audit manifest exists. See
`local/validation/lazy-pool-20261008-audit/handoff-check.json` (an empty hash map
does not imply file verification for a manifest without that field).
Pool initialization is complete. The next recorded milestone is lazy allocation,
which connects those recovered dependencies to an actual game caller. No return
to completed inner allocation, optional extraction or compiler work was needed.

Before implementation, acceptance was set to recover ARM `0x00146284..0x00146350`
and Thumb `0x002C0128..0x002C013A`, preserving first-call construction and
publication order, distinct guard predicates, repeated calls, exhaustion and
outer ownership/count. Execute recovered initialization, quotient, recursive/base
locks and pool take in a persistent bounded arena. The criteria pass below.
A STOP file was observed after the primary comparison; only current-package
validation and handoff work continued. No new recovery target was started.

## Source contracts

`src/resource_lazy_pool.c` adds `smt4_resource_lazy_pool_take` (ARM original) and
`smt4_resource_static_guard` (Thumb original). The rebuilt unit uses ARM for both;
the compiler inlines the helper into the caller while retaining its exported
32-byte function. The caller occupies 220 bytes, including literal data. The
package adds 252 bytes to the existing 2,688-byte comparison image: 2,940 total.
No binary matching or instruction-shape equivalence is claimed.

Static provenance is the previous audit's `next-lazy-pool-ghidra.txt`,
`next-lazy-pool.log` and `next-guard.log` under
`local/validation/pool-init-20261008-audit/`. These agree on saved extents,
instruction modes, literals and branches. The new `visited.txt` records execution
of all 51 caller and nine guard instruction addresses.

The caller acquires recursive lock `0x004D43D0`, then reads guard
`0x0044E650+12`. An odd word bypasses the helper. An even word reaches the helper,
which reads the full word and returns zero if nonzero; only zero is replaced by
one and returns one. Thus a nonzero even word does not initialize the pool, and
the guard is set before construction. This is a plain word guard under the
caller lock, not a proposed native atomic initialization service.

Construction at pool `0x004D42E0` writes zero at offsets 4, 8, 12, 16, 20, 36,
48; then vtable address `0x00420B9C` at zero, all-ones at 56 and zero at 52, in
that order. It calls recovered pool initialization with element size `0x130`,
storage `0x00430940`, bytes `0x1300`, alignment four and options zero. Recovered
recursive initialization follows at pool+48. Original sites at `0x00146320`
and `0x00146328` are NOPs, not destructor registration or guard-finalization
calls; the source retains two NOPs without inventing either service.

On every call, including already initialized and exhausted calls, the caller
publishes `0x004D42E0` at global+4, executes pool take, releases the outer lock,
and returns the node or null. It does not return the previously published pointer
or skip publication when the guard is nonzero. Incidental registers/flags and
timing are outside the source interface.

## Comparison and regression evidence

Primary: `local/validation/lazy-pool-20261008/COMPLETE.json`.
The warning-clean ARMv6K build passes **76 calls in 12 persistent sequences**.
Guards are 0, 1, 2, `0x80000000`, `0xFFFFFFFE` and `0xFFFFFFFF`, each with an
unowned outer lock or same-TLS ownership at recursion depth three. Zero-guard
sequences begin with poisoned pool fields, locks and all node bytes and run 18
calls: all 16 nodes followed by two exhausted calls. Nonzero-guard sequences
use a synthetic existing two-node pool with used count seven and run four calls.
No fixture is reseeded between calls. No predicted result is copied into memory.

An independent state oracle predicts every nonstack word write in order, including
outer lock acquisition, guard, construction, initializer list writes, publication,
pool take and both releases. It also checks one guard read for odd values and two
for even values. Both original and rebuilt paths must match the oracle and full
guarded pool, outer-lock, global and backing-storage bytes. The checker verifies
return values, callee-saved registers, stack restoration/guards, initialized reads,
allowed instruction intervals and execution budgets. All 60 new instruction sites
execute. Visitation does not imply all concurrency or predication outcomes.

All game dependencies on the reached path execute original instructions versus
recovered source: initialization, quotient, recursive/base locks and pool take.
Only fixed TLS reads and successful exclusive-store outcomes are scheduled.
This new corpus removes caller construction/publication and initialized pool
results as fixtures on the first-call path. Older harness modes retain their
documented models. Harness, header and symbol metadata are support, separate
from the two recovered contracts.

Audit: `local/validation/lazy-pool-20261008-audit/COMPLETE.json`.
Two compiled faults are rejected: treating the helper guard as a bit predicate
(case 44, guard two), and publishing null (case zero). Their exact assertions
are in `negative-checks.json`. The retained initializer regression reproduces
the full accepted comparison object and binary SHA-256: 317 initialization
comparisons, six initialized lifetimes and 54 consumer calls in 2,688 bytes.
All **134 public tests** pass; see `public-tests-console.log`.

```powershell
python tools/check_resource_lazy_pool.py --output local/validation/NEW-LAZY-POOL
python tools/check_resource_lazy_pool.py --mutant guard --output local/validation/NEW-LAZY-GUARD-NEGATIVE
python tools/check_resource_lazy_pool.py --mutant publish --output local/validation/NEW-LAZY-PUBLISH-NEGATIVE
python tools/check_resource_pool_initialize.py --output local/validation/NEW-INIT-REGRESSION
python -m unittest discover -s tests
```

## Boundaries and next independent task

Initial outer-lock construction, backing-storage provenance/global startup and
TLS remain synthetic. Exclusive stores succeed in this caller corpus; failed
attempts and pending prefixes retain only the separate initializer/lock evidence.
No contention, arbitrary races, recursion overflow, aliasing, corrupt lists,
allocator return/reuse through this caller, or real kernel behavior is claimed.
The guard helper is compared through this caller on the stated words, not across
all callers or all 32-bit inputs. Other game services in the larger linked image
are not reached. Live G1/G2, full ABI, matching, the original-target application
and provenance/transfer gates remain open.

Next independent milestone: recover the actual caller at **`0x002ADCD8`**, whose
call to this lazy allocator at **`0x002ADCF8`** is recorded in the prior
`next-lazy-pool-ghidra.txt`. First inspect its saved extent, original instructions
and remaining constructor/error dependencies, then recover its consumed contract
and integrate this lazy allocator for success and exhaustion. The other evidenced
caller is `0x001270C4` (call at `0x001270E4`); batch it only if inspection establishes
a shared bounded contract/fixtures. Neither caller is claimed recovered here.
Use the existing authoritative Ghidra project sequentially and reuse
`check_resource_lazy_pool.py` and the ownership harnesses. Do not repeat the
completed initializer/lazy-allocator milestone or reopen optional extraction.
