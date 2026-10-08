# Pool word fill and allocation byte clearing

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored recovery from the pinned instructions; no external implementation
was reused. Descriptive source names are not original symbols.

## Strategic review and acceptance

The scheduled review verified the completed read-service manifest's source/tool
identities and 708-byte binary against disk (`handoff-check.json` in the audit).
This advances A07/G2 original-source recovery and removes
actual dependency models. The old inner-allocation objective is complete;
optional extraction, compiler research, live checks and port work are not needed.

Acceptance declared before implementation: verify the two entry extents and
consumed shared body; preserve equality termination, word values, alignment,
short lengths, word blocks and tails with exact destination write widths/order;
build ARM source; compare original/rebuilt destination effects and untouched
guards; execute real clearing through backend/file pool reuse and bounded worker
allocation; reject meaningful compiled faults and retain older comparison modes.
This package meets that bounded acceptance. It does not close a whole-game gate.

## Recovered source contracts

`src/resource_clear.c` and `.h` recover two original function entries and one
consumed aligned shared-body contract:

| Original interval, end exclusive | Source | Compiled bytes |
| --- | --- | ---: |
| `0x00139F54–0x00139F84` | `smt4_worker_backend_clear` | 24 |
| `0x002C3B9C–0x002C3BDC` | `smt4_resource_allocate_zero` | 120 |
| `0x002C4B88–0x002C4BD8` | `smt4_resource_fill_words` | 240 |

The saved Ghidra functions match the first two intervals. The third has **no
separate saved function object**, but has decoded instructions and direct branch
edges from the zero entry at `0x002C3BAC` and `0x002C3BC4`. The new C helper is a
source factoring of that consumed body, not evidence of another original public
function. `static-ghidra.txt` in the audit, the primary `original-ghidra.txt`, and
three GNU `original-smt4_*.log` files preserve independent boundary/instruction
evidence. No saved project mutation was made.

Word fill takes `(start, end, value)`, writes one 32-bit value at each address,
increments the address by four modulo u32 and stops **only on equality** with
the exclusive end. Start equal to end writes nothing. It does not test ordering,
round an endpoint, reject wrapping, or replicate the value's low byte. Valid
tested endpoints are reachable by four-byte increments. A mapped crossing from
`0xFFFFFFF0` through address zero distinguishes equality from unsigned ordering.
Unreachable endpoints and arbitrary unaligned word stores are outside the domain.

Byte zero takes `(destination, count)` with no consumed result register. For
counts below four it uses only byte stores. Otherwise a nonaligned address is
advanced to the next word boundary: prefix one uses a byte; prefix two uses a
halfword; prefix three uses a byte followed by a halfword. It subtracts this
prefix from the original byte count and enters the shared body. The shared body
writes full words in 32-byte blocks, then residual full words, then a halfword
and/or byte. The generalized aligned body uses the low halfword/byte of its
value for the tail; it does not replicate a byte across words. The zero caller
supplies value zero. Volatile typed destination stores preserve these observed
widths and order under the comparison compiler.

No meaningful result register is promised by these void source interfaces.
Stack scratch operations, volatile-register values, instruction grouping
(`STM` versus separate `STR`) and timing are not matching contracts. Callee-saved
registers and stack restoration are checked. Destination write traces are exact
at Ghidra's per-store p-code granularity; this does not establish bus transactions,
atomic multiword stores or concurrent behavior.

## Direct build and comparison evidence

Primary: `local/validation/resource-clear-20261008-final/COMPLETE.json`.
Pinned GCC builds a warning-clean, freestanding C11 ARMv6K image of **384 bytes**,
with no original helper instructions on the rebuilt path. GCC is the behavioral
toolchain; neither binary matching nor a reconstructed 3DS application is claimed.

All **874 original/rebuilt pairs** pass: 83 pool fills, 584 byte-zero calls and
207 aligned shared-body calls. All **48 original instruction sites** are visited.
For each path the independent oracle checks ordered destination addresses,
store sizes and values, full guarded memory, forbidden destination reads,
stack guards, stack restoration and callee-saved registers. The corpus covers
all four initial residues, every length 0–68, larger boundaries through 1,024,
low/high address fixtures, nonzero word patterns and selected pool address wraps.
Shared-body nonzero patterns additionally distinguish full words and low tails.
No calls are modeled in this direct checker. Visitation does not establish every
possible predication outcome or every u32 count.

## Caller integration and models removed

The optional `--recover-clear` modes compile the same source and execute the
original or rebuilt clearing body from the actual caller's registers through
its saved return address. They check the existing independent caller-state
oracle after execution; they do not apply a modeled clear result to memory.
Older modes retain their original corpora and interception boundaries.

| Evidence directory under `local/validation/` | ARM bytes | Compared caller cases | Executed clears, both paths |
| --- | ---: | ---: | ---: |
| `resource-clear-backend-20261008-final2` | 1,976 | 607 | 102 |
| `resource-clear-file-owner-20261008-final` | 3,132 | 670 | 66 |
| `resource-clear-data-20261008-final` | 1,400 | 1,970 | 3,940 |
| `resource-clear-worker-20261008-final2` | 1,340 | 2,304 connected + 48 direct wrapper probes | 6,912 |

Each directory contains `COMPLETE.json`. Backend mode retains three persistent
sequences; archive/file ownership retains two, including actual pool return and
reuse with optional clearing. Ownership mode also executes the previously
recovered archive/file IPC wrappers (`--recover-archive-services`). TLS, SVCs,
diagnostics and locks remain modeled; initial pool/registry storage is synthetic.
Clear calls include zero-length and option-disabled alternatives in the parent
corpora. Pool take's captured result and state survive the actual helper clobbers.

The data checker has **1,250 direct allocations and 720 connected metadata
lifetimes**, including actual raw routing, registration, selector and subsequent
conversion. It executes zeroing only for requested counts **0–1,024**, the mapped
domain. Its `clear.json` explicitly records **894 omitted large-size cases**;
these remain in the unchanged default checker with modeled clearing. All 720
connected lifetimes remain. The new mode also removes artificial clear-callback
lock mutation and volatile poisoning: recovered clearing has no such callback.
Other raw-storage, direct-registration and lock callback profiles remain. Unusual
alignment/low16-zero fixtures still exercise explicitly mapped zero-page users.

Worker mode implies `--recover-allocation` and executes object `0x002C244C`,
lower allocator `0x002C5544` and data allocator `0x002BF7EC` inside the existing
state-zero I/O region. Both allocation clear models are replaced. Allocation
metadata and guards persist through construction, modeled I/O and destruction.
All 299 original sites in that unit are visited, including 30 aligned-zero
sites; unaligned prefix instructions are separately covered by the direct checker.
Its 48 direct wrapper probes retain their lower-allocation model. Raw storage,
registration, locks and lower file/path services remain models in this mode.

These are two new function-entry contracts plus the consumed shared-body source.
Header declarations, builder switches, execution hooks, oracles and metadata are
supporting integration work, not additional recovered game routines. No clearing
model is claimed removed from an older mode or unrelated checker.

## Audit and limitations

Audit: `local/validation/resource-clear-20261008-audit/COMPLETE.json`.
Three independently compiled faults are rejected: unsigned ordering in place of
pool equality, two byte stores in place of an alignment halfword (same final
bytes but wrong widths), and inverted odd-tail selection. `negative-checks.json`
indexes exact assertions. Retained backend, archive/file ownership, worker-data,
worker-allocation and prefix-worker regressions reproduce their accepted binary
hashes and complete comparison objects; `regressions.json` records the checks.
All **134 public tests** pass. `validation-jobs.json` and console logs record
the sequential audit commands and exits. All started jobs finished.

Two development failures were harness issues: an execution method was initially
placed in the oracle class rather than the machine class (Java compile failure),
and the first worker check retained the old instruction-count expectation despite
successful comparisons. The latter now explicitly expects 30 added sites and
6,912 executed clears. No destination/state/ABI assertion was weakened, and the
recovered C source remained unchanged after its first passing direct comparison.

All fixtures are bounded, mapped and synthetic. Apart from selected pool wrap
probes, arbitrary address-space crossing, invalid pointers, destination/stack/code
aliasing, impossible pool endpoints and huge writes are unvalidated. Actual
allocation ownership/storage, concurrency, startup, private locale tables,
diagnostic delivery and platform services remain separate dependencies. G1/G2
live evidence remains deferred; full ABI, matching and provenance/transfer gates
remain open.

```powershell
python tools/check_resource_clear.py --output local/validation/NEW-CLEAR
python tools/check_resource_clear.py --mutant byte-width --output local/validation/NEW-CLEAR-NEGATIVE
python tools/check_resource_worker_backend.py --recover-clear --output local/validation/NEW-CLEAR-BACKEND
python tools/check_resource_worker_file_owner.py --recover-archive-services --recover-clear --output local/validation/NEW-CLEAR-OWNER
python tools/check_resource_worker_data_allocate.py --recover-clear --output local/validation/NEW-CLEAR-DATA
python tools/check_resource_worker_io.py --recover-clear --output local/validation/NEW-CLEAR-WORKER
python -m unittest discover -s tests
```

## Next independent milestone

Recover recursive lock wrappers **acquire `0x002C3AFC`** and **release
`0x002C3A78`**, shared by the recovered pool and allocator callers. GNU leads in
the audit are `next-recursive-acquire.log` and `next-recursive-release.log`.
Candidate ends are `0x002C3B34` and `0x002C3A98`; verify saved membership first.
The wrappers operate on a three-word lock: base lock at +0, TLS owner at +4 and
recursive count at +8. Acquire compares current TLS with the owner, calls
`0x001464F8` when different, then rereads TLS before publishing ownership and
increments the count. Release decrements modulo u32 and clears owner/tail-calls
`0x00138FC0` only on zero. These are static leads, not recovered contracts here.

Reuse `src/resource_lock.c`, `tools/check_resource_lock.py` and
`docs/recovery/resource-lock.md` for the already recovered base lock, plus this
package's pool/allocation fixtures. Next acceptance: exact owner/count and
wrap behavior, same-owner recursion, post-acquire TLS reread, owner clearing
before base release, bounded original/rebuilt instruction comparisons, and
replacement of wrapper lock models in selected pool/allocation lifetimes.
Keep TLS, scripted exclusives/arbitration and concurrency limits explicit; do
not add native mutex policy. Raw storage/ownership integration and registry/pool
startup remain subsequent independent work. Do not repeat completed clearing.
