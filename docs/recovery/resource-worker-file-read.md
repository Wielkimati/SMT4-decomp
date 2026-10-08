# Worker lower read loop

2026-10-08, EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored recovery in
[`resource_worker_file_read.c`](../../src/resource_worker_file_read.c) adds
**one bounded entry contract**, reaching **60 entries plus two adapted worker
regions**. No external implementation was reused. Header/service declarations,
the optional comparison mode and a payload-model hook are supporting changes;
they add no recovered contracts.

The subsequent [open/path package](resource-worker-file-open.md) adds optional
`--recover-file-open`, executing prefix lookup, UTF-16 length and open dispatch
with a modeled backend virtual open.

The subsequent [read-service package](resource-worker-file-read-service.md)
recovers dispatch, concrete method, IPC and pre-read delay in a standalone checker
through this loop and its adapter. Its synthetic concrete file objects replace
the aggregate read model only there. This report's worker-I/O mode retains its
original model and full-width fixture domain; its binary/comparison regression
is recorded in the new package audit.

## Strategic review and acceptance

All 20 input-file identities and
its compiled binary were verified before edits in
`local/validation/worker-read-20261008-audit/handoff-check.json`. This package follows A07 by replacing
a game-code dependency reached by the recovered worker. No optional extraction,
compiler research, port implementation or live session is required. G1/G2 live
and G3 ABI/provenance/transfer gates remain open.

Acceptance declared before implementation: instruction-backed service ABI and
cursor/count semantics; a warning-clean ARM build; direct zero/partial/full/error
and arithmetic boundary comparisons; connected worker payload reads; meaningful
fault rejection and preservation of prior modes. OS read remains modeled.

## Original contract and source

ARM entry `0x002BB864`, exclusive end `0x002BB8EC`, has **34 instructions**.
The final comparison checks its saved Ghidra function extent and every instruction
address, exports `original-read-ghidra.txt`, and independently exports GNU
`original-read-disassembly.log`. At `0x002BB8BC`, the instruction word
`0xE0A34FCC` is explicitly asserted: `ADC r4, r3, ip, ASR #31`.

The lower receiver is worker object+4: tagged handle at +0, cursor low/high at
+4/+8, cached size low/high at +12/+16. The read loop leaves handle/cache intact
in the tested non-reentrant service domain. Its four arguments are receiver,
caller count pointer, 32-bit destination address and 32-bit requested byte count.
It reaches service `0x002A4E54` with local count pointer in r0, untagged handle in
r1, cursor low/high in r2/r3, destination at `[sp]`, and remaining bytes at
`[sp+4]`. Original local count is at `[sp+8]`; the rebuilt local has a different
frame offset. Both retain word alignment and eight-byte service-call alignment.

- A zero request makes no service call, writes caller count zero and returns zero.
- A service status with bit 31 set returns unchanged. Its local count is ignored;
  caller count remains untouched, and earlier successful cursor increments remain.
- Every nonnegative status consumes the returned count, adds it modulo 2^32 to
  the accumulated total, and advances the cursor by its **signed 32-bit value**
  modulo 2^64. The source uses unsigned low-word carry and a sign mask, avoiding
  C signed overflow or implementation-defined signed shifts.
- A count equal to the remaining request, or a zero count, terminates successfully.
  Otherwise the destination advances and remaining bytes decrease modulo 2^32,
  then another service call uses the updated cursor, address and count.
- Success publishes the accumulated count and returns **zero**, including when
  the service returned a positive nonzero status. Failure never publishes a
  partial total. The loop performs no size query or cached-size bounds check.

Source preserves the lack of an over-count check. Deliberately inconsistent
scripted counts expose signed extension, total/address wrapping and remaining
underflow; they do not establish that real file services can return those counts.
Termination depends on service responses. Faulting or overlapping object/count/
buffer storage, reentrancy, concurrent mutation and unbounded service streams
are outside the compared contract.

## Build and controlled comparison

Primary evidence:
`local/validation/worker-read-20261008-dev1/COMPLETE.json`.
The first positive run passed; its development-directory name is retained to
avoid rerunning an unchanged validated corpus. The warning-clean freestanding
C11 ARMv6K build is **1,764 bytes**, including **136 new read-loop bytes**.
GCC emits the same signed-count `ADC ... ASR #31` operation. No original code
executes on the rebuilt path. Binary matching and a complete original-target
build are not claimed.

| Comparison | Result |
| --- | ---: |
| Connected original/rebuilt/oracle worker cases | 2,304 |
| New direct lower/read-adapter cases, including retained steps | 724 |
| Persistent read/error/retry sequences | 2 |
| Retained direct position cases / persistent position sequences | 3,312 / 4 |
| Retained isolated adapter / object-allocation probes | 210 / 48 |
| New original read-loop addresses visited | 34 / 34 |
| Total original addresses visited | 431 |
| Connected read invocations, both paths | 4,608 |
| Modeled OS read calls, both paths | 8,008 |
| Maximum executed read instructions per invocation | 80 |

`--recover-file-read` implies position, method and allocation recovery. It replaces
the read-loop interception with original/rebuilt execution through real read
adapters in synthetic vtables. It retains the earlier path, allocation metadata,
descriptor, close/destructor and size/seek checks. OS responses now write each
actual bounded payload segment. An optional hook disables the older fixture's
whole-payload write at read completion, preventing that write from concealing
partial/failure effects. Original/rebuilt traces and full guarded payload bytes
must agree. Source never consumes returned count as the descriptor's requested
size, including short reads and failure after prior progress.

Connected lengths remain 0, 1, 68, 69, 127, 128, 129 and 801. Read fixtures cover
full reads, partial then full, partial then zero, immediate failure and partial
then failure. Zero requests normalize the worker's expected read result to success
because they never observe a negative service response. Older modes retain their
original supplied-result expectations. The prior synthetic lock-interference
effect is applied at read-method completion, independently of whether an OS call
occurred; it is not a recovered OS side effect.

Direct probes execute both the lower entry and its adapter. They combine zero,
one, two, 17, 128, signed maximum, sign-bit and all-ones requests with cursors
zero, low-word maximum, 2^32, signed 64-bit maximum/minimum and all ones. Handles
include zero, tag-only, high-bit and all-ones words. Service responses include
zero, positive one/maximum and negative minimum/all-ones statuses. Failure tests
alternate untouched local output and written poison. Bounded cases write fixture
payload; full-width address/count probes do not dereference those opaque buffers.
Explicit over-count scripts exercise wrap and failure after a high-bit count.

Two persistent sequences retain object/cache and destination bytes across partial
success, later error after another partial read, retry to completion and a zero
request, starting at a carry boundary and signed maximum. Each invocation checks
exact return/count behavior, all object words, count and object guards, payload
guards, service order/count/arguments, cursor snapshots, stack restoration and
callee-saved registers. Service models clobber volatile registers and flags.
A separate Java oracle uses signed integer extension and defined wrapping long
addition. Instruction visitation is bounded evidence, not exhaustive proof.

## Validation audit

Audit index: `local/validation/worker-read-20261008-audit/COMPLETE.json`.
All six compiled faults were rejected at semantic assertions:

| Fault | Observed rejection |
| --- | --- |
| `loop-sign` | Signed cursor/cache oracle |
| `loop-count-failure` | Caller count preservation |
| `loop-buffer` | Next service buffer/remaining arguments |
| `loop-remaining` | Next service buffer/remaining arguments |
| `loop-positive` | Exact result / success normalization |
| `loop-zero` | Unexpected extra OS call after zero count |

`negative-checks.json` binds each rejection to its generated source, binary,
command/log and `NEGATIVE.json`. The position, method, allocation and legacy
regressions retain **identical complete comparison objects and binaries**
(1,628 / 1,088 / 956 / 548 bytes) relative to the previous package. See
`regressions.json`. All **134 public tests pass**; actual output is retained in
`public-tests.log`. The first positive run and all six negatives/four regressions
finished without build or harness failures. Jobs used the saved project read-only
and sequentially. The audit verifies current manifest file hashes; no validation
job was left detached.

## Models removed and remaining limits

Only this new mode removes the `0x002BB864` read-loop model from connected worker
and new direct probes. The older position mode still intercepts it, and the
retained 210 isolated adapter probes still intercept relocated lower entries.
Their old counters and inherited model flags describe those narrower scopes;
the new `read_loop_recovered` and `os_read_service_modeled` fields describe the
new chain. Historical manifests and comparison objects are not broadened.

OS read `0x002A4E54`, OS size `0x002A8914`, diagnostic delivery, raw storage,
registration, clearing, recursive locks, path conversion, open/preclose/close,
destruction and complete ownership remain modeled or unrecovered here. The
service model has scripted results and bounded deterministic payload bytes; it
does not claim real filesystem behavior, error-time payload writes or timing.
Size-adapter failure still stops at diagnostic entry; seek diagnostics are
modeled returning. This package adds no native service replacement or port code.
Live gameplay remains deferred.

## Reproduce and next independent milestone

Run from `SMT4-decomp`, using fresh output directories and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-file-read --output local/validation/NEW-READ
python tools/check_resource_worker_io.py --recover-file-read --mutant loop-sign --output local/validation/NEW-READ-NEGATIVE
python tools/check_resource_worker_io.py --recover-file-position --output local/validation/NEW-POSITION-REGRESSION
python tools/check_resource_worker_io.py --recover-file-methods --output local/validation/NEW-METHODS-REGRESSION
python tools/check_resource_worker_io.py --recover-allocation --output local/validation/NEW-ALLOCATION-REGRESSION
python tools/check_resource_worker_io.py --output local/validation/NEW-IO-REGRESSION
python -m unittest discover -s tests
```

Next recover the connected **open/path dispatch** group: ARM open `0x002BB944`,
ARM prefix resolver `0x002B5CA0`, and Thumb UTF-16 length `0x002B5C8C`. Starting
GNU evidence is `next-open-disassembly.log`, `next-prefix-disassembly.log` and
`next-utf16-disassembly.log` in this audit directory. A finished sequential,
read-only Ghidra inspection (`read-open-ghidra.txt` and `function-*.c`) verifies
open `[0x002BB944,0x002BB9D4)`, resolver `[0x002B5CA0,0x002B5D68)` and Thumb
length `[0x002B5C8C,0x002B5C9E)`. The resolver's literal at `0x002B5D68` gives
prefix table `0x004D43E0`; its 32 records have a 16-byte stride, key low/high at
+0/+4 and returned pointer at +8. These are static next-task findings, not new
recovered source or behavioral acceptance. Verify instruction semantics and
ARM/Thumb interworking while implementing.
The observed resolver packs signed low bytes from UTF-16 units into a 64-bit key,
limits prefix scanning to eight units and searches 32 records in pairs. Open
builds a type-4 path descriptor after the colon and conditionally stores the
returned handle. Recover those source dependencies together with synthetic
prefix-table fixtures, keeping the backend virtual open service explicit.
Check first-match/absent/zero keys, short and maximum prefixes, signed-byte
packing, suffix byte length, exact error/status and failed handle preservation;
integrate through the existing worker read mode. Do not repeat completed
allocators, adapters, size/seek/read or optional extraction work.
