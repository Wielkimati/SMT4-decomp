# Worker file size, seek and read adapters

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored recovery in
[`resource_worker_file_methods.c`](../../src/resource_worker_file_methods.c)
adds **three bounded entry contracts**, reaching **56 entries plus two adapted
worker regions**. The worker's size-method function-pointer type now expresses
the original 64-bit return and explicit low-word consumption. That caller change
and the comparison extension add no entry contracts. No external code was reused.

The subsequent [lower position package](resource-worker-file-position.md) executes
size/cache, seek dispatch and position through `--recover-file-position`.

## Strategic review and acceptance

The completed object-allocation milestone's recorded file identities, compiled
binary and full comparison object were verified before editing:
`local/validation/worker-methods-20261008-audit/handoff-check.json`.
This follows A07's source/build/
comparison gate.

Acceptance set before implementation: establish original function extents,
64-bit size/seek interfaces, read forwarding and negative-result boundaries;
build source for ARM; replace these virtual-method models in the retained
allocation/I/O corpus; check direct boundary cases and reject relevant compiled
faults; preserve allocation and legacy I/O regression results. Lower file/OS and
diagnostic models must remain explicit. Neither G1/G2 nor G3 is closed here.

## Original contracts

| Entry / extent (exclusive end) | Contract |
| --- | --- |
| `0x003DFC54`–`0x003DFC80` (11 instructions) | Calls `0x002BB8EC(object+4, &size)`. If result bit 31 is set, calls diagnostic `0x002BBD70(result, 0x003DFC70)`. Returns both stack output words in r0/r1 if execution resumes. |
| `0x00354F70`–`0x00354F9C` (11 instructions) | Calls `0x002ACA78` with object+4, unmodified offset in r2/r3 and origin as the fifth stack word. Also copies origin into r1, which is ignored by the inspected callee. Negative results tail-call diagnostic with site `0x00354F8C`; nonnegative results return. No caller-consumed return value. |
| `0x00354F9C`–`0x00354FA4` (2 instructions) | Tail-forwards object+4, count output, data address and requested byte count to `0x002BB864`, preserving its return. No diagnostic call. |

The explicit lower-seek r1 argument in the C declaration preserves the observed
register forwarding while occupying the AAPCS alignment gap before the 64-bit
offset. It is not a newly inferred semantic parameter. The public virtual seek
interface remains `(object, uint64_t offset, uint32_t origin)`.
Diagnostic sites are original code identities, not relocated GCC addresses.
The inspected diagnostic overwrites r2, so incidental caller r2 is not an input
contract; its two consumed words are checked exactly.

The original construction table at `0x00420870` installs `0x004208B0` with
adjustment zero. Slots +0x24/+0x0C/+0x28 select the three entries above. The saved
Ghidra function bodies agree with GNU instruction boundaries. Read-only
inspection, generated pseudocode, independent GNU listings and handoff checks
are under `local/validation/worker-methods-20261008-audit/`. Generated analysis
stays local. The final comparison independently asserts the pinned table values
and exports `original-methods-ghidra.txt`.

**Size failure is a real boundary:** inspection of `0x002BB8EC` shows that on a
negative lower result it clears two cached object words but does not write the
size output. Thus this adapter cannot promise a defined C size if the diagnostic
returns without establishing that output. Direct negative size probes stop at
the diagnostic entry, after checking result and site; they neither read the
unwritten output nor establish actual failure delivery. Connected size cases
use successful, output-writing models. The diagnostic itself writes a global
record at `0x004D4200` and tails to `0x002AD7E8`; neither routine is recovered or
executed by this package. Seek diagnostics are explicitly modeled as returning.

## Build and original/rebuilt comparison

Primary evidence: `local/validation/worker-methods-20261008-final/COMPLETE.json`.
The warning-clean freestanding C11 ARMv6K build is **1,088 bytes**, with **132 new
adapter bytes** (64 size, 60 seek, 8 read). No original instructions run on the
rebuilt path. This is GCC behavioral evidence, not binary matching or a complete
original-target build.

| Check | Observed result |
| --- | ---: |
| Original/rebuilt/oracle connected allocation/I/O cases | 2,304 |
| Retained direct object-allocation probes | 48 |
| Direct adapter probes | 210 |
| Original instruction addresses visited in combined unit | 293 |
| New adapter instructions visited | All 24 |
| Executed allocations, both paths | 6,912 |
| Adapter returns, both paths | 14,220 |
| Size-failure stops at diagnostic, both paths | 24 |
| Diagnostic calls, both paths | 2,448 |
| Maximum adapter instructions per invocation | 12 |

The allocation corpus, guarded metadata/payload and old state/object/path/close
oracles are retained unchanged. Synthetic vtables hold the real original entry
addresses on the original path and compiled entries on the rebuilt path; the
existing alternate-construction-adjustment fixtures remain exercised. The pinned
real table itself is checked separately and only has adjustment zero.

Connected sizes use the previous bounded lengths (0, 1, 68, 69, 127, 128, 129,
801), now returned with distinct nonzero high words. Only the low word reaches
the descriptor, data allocator and read. Size service statuses rotate through
0, 1 and `0x7FFFFFFF`; seek statuses through 0, `0x7FFFFFFF`, `0x80000000`,
`0xFFFFFFFF`. Read statuses retain both signs. This checks sign-bit predicates
and continued caller execution after a modeled returning seek diagnostic.

Direct size and read probes each cross five lower statuses with six contrasting
word patterns: 0, 1, `0x7FFFFFFF`, `0x80000000`, `0xFFFFFFFF`, `0x12345678`.
Size low/high words differ. Read count, buffer and length forwarding and the
exact returned status are checked without dereferencing synthetic data addresses.
Direct seek additionally crosses origins 0, 1, 2, `0x80000000`, `0xFFFFFFFF`;
both offset words and the fifth argument are checked. Unsupported origins are
forwarding probes, not successful lower seeks. Redundant origin dimensions are
omitted for methods that do not consume origin.

Each modeled service poisons volatile registers/flags. Oracles check lower call
order/count, diagnostic result/site, stack alignment/restoration/guards,
callee-saved registers, full size return, read count/status, unchanged object
bytes under these models and original/rebuilt traces. Read still writes bounded
fixture payload and a deliberately inconsistent count, testing that the worker
retains requested size. Huge/full-width direct inputs are ABI probes only.

## Models removed and limitations

Validation index: `local/validation/worker-methods-20261008-audit/COMPLETE.json`.
All seven compiled faults are rejected at their intended semantic assertions:
truncated size return, nonzero-versus-negative size status, truncated seek offset,
zeroed seek origin, wrong diagnostic site, unadjusted read receiver and altered
read result. Rejection markers and compiler/comparison logs are under
`local/validation/worker-methods-20261008-negative-*/`. The 2,304-case allocation
regression retains the complete previous comparison object and 956-byte binary;
the 3,456-case legacy regression retains its complete comparison object and
548-byte binary. All **134 public tests pass**. See the audit's `regressions.json`
and `public-tests.log`. No shared harness code changed, and the caller type fix
does not change either older compiled binary.

The first positive run passed; the final run removed redundant direct origin
cross-products for size/read, retained every meaningful boundary, and produced
the identical 1,088-byte binary. The temporary static-audit launcher initially
shadowed Python's `inspect` module; renaming that local launcher resolved it
before any Ghidra job started. All launched inspection/build/comparison jobs
finished, sequentially on the saved read-only project.

`--recover-file-methods` implies `--recover-allocation`. Only this new mode
replaces size/seek/read method interceptions with recovered source. The existing
allocation mode and default I/O mode retain their original boundaries. Raw
allocation, registration, zeroing, locks, conversion, open/preclose/close,
destruction and the three lower file calls remain models here. The lower file
models preserve object fields; actual cursor/cache mutations are next work.

Size failure after diagnostic, real file/OS results, diagnostic nonreturning
behavior, construction/destructor semantics, storage ownership/reuse, recursive
metadata ownership, synchronization/reentrancy, full worker lifetimes and live
agreement remain unverified. This is recovered original behavior within explicit
models, not a proposed native replacement or PC-port implementation.

## Reproduce and next independent milestone

From `SMT4-decomp`, use fresh directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-file-methods --output local/validation/NEW-WORKER-METHODS
python tools/check_resource_worker_io.py --recover-file-methods --mutant seek-offset --output local/validation/NEW-WORKER-METHODS-NEGATIVE
python tools/check_resource_worker_io.py --recover-allocation --output local/validation/NEW-ALLOCATION-REGRESSION
python tools/check_resource_worker_io.py --output local/validation/NEW-IO-REGRESSION
python -m unittest discover -s tests
```

Next recover **lower size/cache `0x002BB8EC`, seek-origin dispatch `0x002ACA78`
and position validation `0x00146458`**, then connect them to these adapters with
modeled OS size service `0x002A8914`. They share the five-word handle/cursor/cache
layout and directly replace dependencies reached here. Check size cache writes
and failure output preservation; 64-bit current/end-relative addition and signed
position bounds; cache-refresh/equality behavior; exact error results and caller
effects. Inspect instructions before trusting generated pseudocode: Ghidra
currently merges `[0x00146458,0x001464F4)` into `0x002ACA78`'s body even though
the dispatcher tail-branches there. Its pseudocode contains incidental register
and uninitialized-local artifacts. Saved listing and `2aca78.c` plus
`next-position-disassembly.log` in this audit directory are starting evidence.
Keep `0x002BB864`'s read loop, lower OS calls and diagnostic delivery separate
unless their necessity for that package is demonstrated.
