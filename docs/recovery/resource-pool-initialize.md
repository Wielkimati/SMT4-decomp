# Pool storage and lock initialization

2026-10-08. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; no external implementation reused.
Names describe observed roles, not original symbols.

## Strategic review and acceptance

The scheduled review verified the previous recursive-lock milestone against both
manifests and all their source/tool hashes (`handoff-check.json` below).
The old inner-allocation objective is complete. No extraction,
compiler research, live session or port work is needed for this package.

Acceptance stated before implementation: recover pool configuration at
`0x002A4EB4`, recursive initialization at `0x002C3B54` and base initialization at
`0x00138F44`; retain rounding/wrapping, precise field order, backward list
construction with field reloads and exclusive retries; build ARM source and
compare original/rebuilt behavior; execute initialized topology and locks through
pool take, return and reuse. Use nonzero divisors and bounded mapped storage,
with pathological lists, backing ownership and global startup explicitly open.
This bounded milestone passes; deferred G1/G2 live gates remain open.

## Recovered contracts

`src/resource_pool_initialize.c` and `.h` add three contracts:

| Original interval, end exclusive | Source function | Rebuilt bytes |
| --- | --- | ---: |
| `0x002A4EB4..0x002A4F54` | `smt4_resource_pool_initialize` | 204 |
| `0x002C3B54..0x002C3B70` | `smt4_resource_recursive_lock_initialize` | 32 |
| `0x00138F44..0x00138F5C` | `smt4_resource_base_lock_initialize` | 24 |

Saved Ghidra bodies match all three intervals. Primary `original-ghidra.txt` and
the independent `original-smt4_resource_*.log` GNU listings bind the source to
the original instructions. Prior audit `next-pool-init.log` establishes an actual
caller: `0x00146284` calls configuration, inline-lock initialization and pool take
in that order. This package executes the entries and connected consumers; it
does not yet execute that startup caller.

The pool initializer consumes six arguments: receiver, element size, storage
address, storage size, alignment, options. All arithmetic is unsigned modulo
2^32. It writes options at +0x14, rounds element size using
`((element + alignment - 1) / alignment) * alignment`, and stores stride at
+0x18. It similarly rounds the storage address and stores start at +0x1C.
Usable bytes are `((storage + size - start) / stride) * stride`, stored at +0x20.
The quotient calls execute recovered `src/unsigned_quotient.c` on the rebuilt
path, with its existing nonzero-divisor contract.

The initializer then writes used count zero at +0x2C and alignment at +0x28.
Starting at `start + usable - stride`, it compares addresses unsigned and writes
the previous head at each node's first word, building the free list backward.
After each node write it reloads stride/start from +0x18/+0x1C before subtracting
and comparing again. Finally it publishes head at +0x24. It does not clear node
payloads, preserve a previous free list, acquire a lock or validate its inputs.
Fields outside these writes remain unchanged. Volatile accesses preserve the
observed ordering; the original LDRD is represented by its two ordered word reads.

Base initialization executes LDREX/STREX until a store of **one** succeeds.
It does not branch on the loaded value or insert a barrier. Recursive
initialization calls that operation before clearing owner +4 and count +8.
Failed exclusive prefixes leave owner/count untouched. These are original
32-bit address-space contracts, not proposed native synchronization services.
The consumed interfaces are void: incidental return registers, flags, timing,
matching instruction shape and portable C concurrency semantics are not claimed.

## Original/rebuilt evidence and integration

Primary: `local/validation/pool-init-20261008-final-checked/COMPLETE.json`.
The warning-clean freestanding ARMv6K image is **2,688 bytes**, including 260
new initializer bytes, the previously recovered 56-byte quotient and existing
backend/prefix/open/clear/lock source. No original binary helper executes on the
rebuilt path.

**317 initialization comparisons** pass: 283 pool calls and 34 lock calls,
including four pending exclusive prefixes. All **53 new instruction sites** are
visited. The direct pool corpus crosses element sizes 1, 4, 15, 16, 17 and 31;
alignments 4, 8, 12, 16 and 20; storage offsets 0, 1 and 3; empty, single and
three-node capacity with trailing bytes. Five additional short/large-size probes
exercise unsigned usable-byte underflow and wrapped end arithmetic while reaching
no node writes. Two scheduled mutation probes change stride or start after the
first node store and require subsequent reloads. These mutations establish
consumed loads, not arbitrary concurrent correctness.

Lock cases cross base words zero, one, sign-bit and all-ones values, with zero,
one or four failed stores before success. Pending schedules stop immediately
before the next LDREX after one or five failures; they claim neither return nor
liveness. Both paths execute **188 initialization exclusive attempts** in total.
Initial owner/count words are nonzero in direct lock and connected fixtures.

The checker independently predicts ordered field reads/writes and attempted
exclusive stores, and verifies complete guarded fixture bytes, stack argument
preservation, stack bounds/restoration, callee-saved registers, initialized reads,
allowed instruction ranges and execution budgets. Actual original quotient
instructions and recovered quotient instructions execute; no quotient result is
intercepted. Initialization hooks never copy oracle results into object storage.

**Six persistent consumer sequences / 54 calls** execute empty, one-node and
two-node pools with clearing disabled/enabled. They first poison topology, node
links and lock words, then execute both initializers without reseeding between
initialization and use. Each performs three create/register, duplicate-owner or
exhausted-take, and remove/return rounds. Complete byte checks preserve the
second free node where present. Reuse leaves head/count and lock ownership in
the independently expected state. Consumers execute **168 recursive wrapper
calls** and **12 clearing calls** across both paths.

This replaces preconstructed topology and successful lock-initialization results
in this new connected corpus. Older backend modes retain their published fixture
boundaries. Services and diagnostic behavior use the existing backend oracle;
TLS is fixed and consumer exclusive stores succeed. The new initializers have
separate failure schedules. Backing arenas, registry storage, OS services,
exclusive-monitor outcomes and TLS remain synthetic/scheduled. The header,
builder, oracle, instruction hooks and metadata are supporting changes, not
additional recovered game routines.

## Audit and limitations

Audit: `local/validation/pool-init-20261008-audit/COMPLETE.json`.
Three compiled faults are rejected: omitted element rounding, cached loop stride,
and owner/count clearing before base initialization. The final ordering fault is
a pure reordering of the original stores and call (`negative-init-order-refined`);
an earlier extra-store version is retained only as development evidence.

Retained direct recursive-lock and backend clear/lock regressions reproduce their
accepted binary hashes and entire comparison objects: **164 cases / 396 bytes**
and **619 cases / 2,372 bytes**. All **134 public tests** pass. Audit
`validation-jobs.json`, `negative-checks.json`, `regressions.json` and
`public-tests-console.log` record commands and outcomes. The final recheck after
refining the negative control preserves the source binary and comparison results.

The first development run passed its first 272 pool cases, then rejected a
proposed huge-stride fixture in the oracle's mapped-list domain check. Those
inputs create pathological unsigned traversal and were not executed or counted
as accepted cases. They were replaced by five bounded underflow/wrapped-end
probes; no source change was made to conceal that fixture failure.

Zero alignment, zero rounded stride, arbitrary unaligned/aliased pointers,
pathological wrap/nonterminating lists, arbitrary races and kernel monitor
fidelity remain outside this evidence. All reached node words are mapped and
word-aligned. Storage allocation/ownership, global startup and complete allocator
integration remain open. Full ABI, matching, an
original-target application, live gameplay and provenance/transfer remain separate.

```powershell
python tools/check_resource_pool_initialize.py --output local/validation/NEW-POOL-INIT
python tools/check_resource_pool_initialize.py --mutant init-order --output local/validation/NEW-POOL-NEGATIVE
python tools/check_resource_recursive_lock.py --output local/validation/NEW-RECURSIVE-REGRESSION
python tools/check_resource_worker_backend.py --recover-clear --recover-locks --output local/validation/NEW-BACKEND-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Recover the actual **lazy static-pool allocator `0x00146284..0x00146350`**
and its required **Thumb guard `0x002C0128..0x002C013A`**. Audit
`next-lazy-pool.log`, `next-guard.log` and `next-lazy-pool-ghidra.txt` record
instruction/mode/extent evidence. These are static findings, not recovered
contracts. The larger `0x00145E9C` owner and adjacent archive-factory listings
are retained leads only, not prerequisites or an admitted adjacent work queue.

The caller acquires outer recursive lock `0x004D43D0`, examines global
`0x0044E650+0x0C`, and conditionally constructs pool `0x004D42E0` over static
storage `0x00430940` with element size `0x130`, storage size `0x1300`, alignment
four and options zero. It initializes the inline lock, publishes the pool at
global +4, takes a node, releases the outer lock and returns that node. The
Thumb guard reads the full guard word: zero is replaced by one and returns one;
nonzero returns zero. The caller's earlier bit-0 test is distinct from that full
word test. Preserve both tests and the existing original NOPs.

Next acceptance: exact first-call writes and publication order, repeated calls
without reinitialization, nonzero even guard behavior, pool exhaustion and
preservation of the outer owner/count. Execute the recovered initializer,
quotient, recursive/base locks and pool take in a persistent bounded static
arena. Reuse this checker and the existing backend lock hooks, adapting addresses
explicitly; do not copy initialized results into memory. Keep initial outer-lock
construction, static backing-storage provenance and real TLS/exclusives modeled
unless separately evidenced. Live gates remain deferred.
