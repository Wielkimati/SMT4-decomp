# Service acquisition through startup

2026-10-11. Project-authored recovery against EU base v0 expanded executable
SHA-256 `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Names describe observed contracts, not original symbols. No external code reused.

## Strategy review and acceptance

The completed [startup milestone](resource-worker-service-startup.md) and current
handoff both select acquisition. This directly replaces two active game-call
models under A07, without optional extraction, compiler research or port work.
The review verified every source/tool/config hash in the previous startup manifest
and the pinned executable before edits; see
`local/validation/service-acquisition-20261011-static/handoff-check.json`.

Acceptance, selected before implementation: a warning-clean ARM build, verified
noncontiguous function membership, and original/rebuilt agreement for signed
manager-count and length guards, exact eight-byte name transport, request
`0x00050100`, kernel-failure output preservation, publication even on service
failure, length's mapped read domain, and connected startup/archive/file use.
Setup/connect remain a separate boundary. These bounded criteria pass; whole-game
startup, live G1/G2 and other project gates remain open.

## Recovered contracts and removed models

New `src/resource_worker_service_acquire.c` / `.h` provides **three contracts**:

| Original ARM instruction ranges (exclusive end) | Contract | Compiled bytes |
| --- | --- | ---: |
| `0x002C1590..0x002C15B8` and `0x0012954C..0x001295A0` | `smt4_worker_service_acquire` | 140 |
| `0x002ADBA4..0x002ADBB8` | `smt4_service_name_copy` | 20 |
| `0x002C32E4..0x002C3340` | `smt4_worker_service_name_length` | 108 |

The acquisition tail is part of the same saved function, not another recovered
entry. Fresh read-only Ghidra membership in `service-acquisition-20261011-static/
membership.txt` confirms the exact two ranges (124 original instruction bytes).
The comparison checks this address set rather than treating 124 bytes as one
contiguous range. Original instructions, literal words and rebuilt disassembly
are retained in the primary output directory.

The new optional `--recover-acquisition` mode replaces **two active call models**:
acquisition and name length. The copy helper was previously hidden inside the
acquisition model. Existing startup, publication, accessor, initialization,
archive/file IPC and ownership sources are reused. The shared header now imports
the recovered declarations. Builder, oracle, instruction support and symbol
metadata are supporting changes, not additional recovered game contracts.
Earlier checker modes keep their documented models.

Acquisition first reads signed manager count at `0x00471B90`. Nonpositive values
return `0xD8A067F8` without reading the name, writing the output or touching TLS.
Only then is the length compared as signed against eight; greater values return
`0xD9006405`. Negative length bit patterns pass, without imposing a new validity
check. The accepted path writes header, two name words, length and flags to
command words 0..4, then loads manager handle at `0x00471BA4` and performs SVC
0x32. The name transfer always reads eight bytes, regardless of length or NULs.
Negative kernel results preserve the output. Nonnegative results publish response
word three regardless of response status and return response word one. There is
no output clearing or service-status success guard.

The copy helper captures both words before either store and returns its destination
in r0. This preserves the compared overlapping-copy behavior, including unaligned
ordinary RAM. The source uses GCC `aligned(1), may_alias` words; the pinned build
emits the same two loads followed by two stores, with different scratch registers.
Length consumes individual bytes until aligned, then whole aligned words through
the first word with a zero byte. It returns the offset of the first zero, including
when multiple lanes are zero. Reads may extend past the terminator to the end of
that word. Source preserves those read widths/order, rather than silently narrowing
the required mapped domain. The reconstructed interfaces preserve compared r0
results; they do not establish original C prototypes or binary matching.

## Validation and bounded instruction support

Primary: `local/validation/service-acquisition-20261011-final/COMPLETE.json`.
The freestanding C11 ARMv6K build with `-Wall -Wextra -Werror` produces a
**4,284-byte** image. The three contracts add **268 compiled bytes**.
All **2,589 original/rebuilt pairs** pass: 101 direct acquisitions, 80 direct
copies, 1,064 direct lengths and the existing connected corpus, now including
152 startup calls. All **59 new instruction sites** are visited, including the
one CPU instruction handled below. The old `comparison.json` field
`new_instruction_addresses=94` still describes file ownership, not this package.

Checks cover signed count/length boundaries and guard precedence, null names
behind rejected guards, all initial name alignments, embedded NULs, high bytes,
unchanged command neighbours, separate kernel/service statuses, nonzero successful
kernel returns, absent reply writes, and zero/high/all-bit handles. Copy fixtures
include disjoint, identical and forward-overlapping storage. Length fixtures cover
initial byte prefixes, every zero lane, multiple zeros and long scans ending in
the final mapped word. Every possible byte value is independently scanned in
each word lane to exercise the instruction-support boundary. The two persistent
startup sequences still proceed through guard reuse, descriptor registration,
concrete file open/close, registry removal and pool-node reuse without reseeding.
The earlier initialization/archive/file sequences also run.

Ghidra 12.1.4 leaves UQSUB8 saturation as an undefined userop. The checker supplies
unsigned saturating byte subtraction **only at original PC `0x002C330C`**, after
asserting exact opcode `0xE6621FF1`. It independently subtracts each unsigned
lane and clamps below zero; it does not intercept the length routine or supply
its return value. All other length instructions execute, and the rebuilt source
uses ordinary shifts/comparisons. The independent oracle scans bytes. The primary
manifest explicitly records this host instruction implementation and its 2,470
executions. This is emulator-supported original behavior, not hardware evidence.
All direct length cases compare the complete source-data load address/size/order
trace as well as results, untouched memory, registers and stack restoration.

The first development run exposed a TLS-register naming assumption when GCC
selected LR for MRC output; the harness now uses Ghidra's `lr` alias. The second
run exposed the unsupported saturation userop. Neither failed run is acceptance
evidence. `service-acquisition-20261011-final` is authoritative for final code.

Setup `0x002C15C4`, TLS and SVC replies, locks and diagnostic delivery remain
modeled. Manager storage, pools, registry and backing storage are synthetic;
setup may explicitly change the manager count. Initial pool/lock construction,
invalid accepted pointers, acquisition storage aliasing, concurrent mutation,
MMIO, real service interpretation and live gameplay are outside the domain.
Direct copy overlap evidence does not broaden acquisition's disjoint-storage
domain. The reused query translation unit still links an unexecuted query IPC
routine, which this mode does not newly validate. No original binary helper
executes on the rebuilt path.

Audit: `local/validation/service-acquisition-20261011-audit/COMPLETE.json`.
Four compiled faults are rejected: unsigned length comparison, publication gated
on service success, copying the first name word twice, and reversed zero-lane
selection. `negative-checks.json` records the concrete assertions. The startup
regression retains the exact prior 4,016-byte binary and all ten compared binary/
evidence fields, including full startup, initialization, descriptor, clear and
archive/file result objects. All **134 public tests pass**; see `public-tests.log`.
`jobs.json` records the six audit commands and exits. All Ghidra jobs ran
sequentially; all started commands finished.

## Reproduction

```powershell
python tools/check_resource_worker_file_owner.py --recover-acquisition --output local/validation/NEW-ACQUISITION
python tools/check_resource_worker_file_owner.py --recover-acquisition --mutant acquire-signed --output local/validation/NEW-ACQUISITION-NEGATIVE
python tools/check_resource_worker_file_owner.py --recover-startup --output local/validation/NEW-STARTUP-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Replace startup's setup model `0x002C15C4..0x002C161C`, including connect/retry
`0x0011CD48..0x0011CDD8`, registration request `0x00129510..0x00129544` and
consumed connect SVC wrapper `0x001382CC..0x001382E4`. Confirm current saved
membership first. Raw leads are `service-acquisition-20261011-static/next-setup.log`,
`next-register.log`, `next-connect-svc.log` and the prior
`service-startup-20261011-static/next-service-connect.log`.

Extend the same acquisition fixture with scripted finite connect retries. Compare
signed already-initialized count, modulo increment, exact repeat-setup status
`0x082067F9` (distinct from startup's `0x08A067F9` comparison), lock/reload ordering,
connect output publication even on failure, exact retry predicate and 500,000
delay, registration header `0x00010002`/word one `0x20`, and increment after
registration even if registration fails. Reuse the already recovered delay
`0x002BB4F0` from `src/resource_wait.c`; its consumed duration selects sleep
`0x001382E4`. Do not duplicate that source or count it as a new contract.
Recursive lock source also already exists; retain explicit lock/kernel/scheduling
models where needed, rather than expanding into an unbounded concurrency package.
Finish with setup-to-acquisition-to-startup/archive use. Full backing storage,
initial locks, read integration and deferred live gates remain open.
