# Prefix registry initialization

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; descriptive names are not original symbols.
No external implementation was reused.

## Strategic review and acceptance

The teardown register repair
is complete; both of its cited manifests existed and their `files_sha256`
identities were checked before edits. Registry initialization is the next
independent source milestone and replaces a concrete registry fixture. No
extraction, compiler investigation, live session or port work is needed.

Acceptance declared before implementation: recover the Thumb array helper and
ARM record initializer, plus their consumed startup slice; compare null/ARM/Thumb
constructors, zero/nonzero count, stride/base transport and wrapping, call order,
ignored callback results, original-base return and guarded preservation of record
tails. Execute initialization followed by register/open/remove/reuse on the same
storage and feed the recovered worker chain. Build warning-clean ARM source,
retain prior comparison modes, reject meaningful compiled faults and run public
tests. Full startup and live G1/G2 remain outside this milestone.

## Recovered source contracts

| Original interval (end exclusive) | Contract | Source |
| --- | --- | --- |
| Thumb `0x002C5FAC..0x002C5FCE` | `smt4_array_initialize` | `src/resource_array_initialize.c` |
| ARM `0x003561F0..0x00356204` | `smt4_worker_prefix_record_initialize` | `src/resource_worker_prefix_initialize.c` |
| ARM slice `0x003F3570..0x003F3584` in `0x003F3568` | `smt4_worker_prefix_initialize` | `src/resource_worker_prefix_initialize.c` |

The array helper saves the original base, constructor, stride and count. A null
constructor skips the loop regardless of count. Otherwise it calls the constructor
exactly count times with the current address in r0, adding the unsigned 32-bit
stride after each call. Zero stride repeats one address; arithmetic wraps modulo
2^32. Callback results are ignored. It returns the original base, restores the
stack and preserves r4-r11. The source expresses the consumed argument/return
contract; it does not promise incidental caller-saved register or flag values.

The record initializer stores zero at +0, +4 and +8 and returns the address.
It preserves flags and padding at +12..+15. Its bounded receiver contract requires
word alignment and twelve writable bytes. The adapted startup slice loads the
record callback from `0x003F36F0`, the table address `0x004D43E0` from
`0x003F36F4`, stride 16 and count 32, and executes the helper. The source's r0
result represents the value at the slice's continuation; this is not a recovered
return statement or complete contract for the enclosing startup function.

Static evidence is in `local/validation/registry-initialize-20261013-static/`.
`membership.txt` confirms the saved Thumb body `[0x002C5FAC,0x002C5FCD]`,
the ARM record instructions and their modes. No separate saved function object
exists for the record or startup. The five startup instructions are not defined
in the saved listing; exact bytes, GNU decoding, literal checks and controlled
execution establish the slice instead. The private database was not changed.

## Comparison boundary

`--recover-registry-initialize` implies `--recover-break` and its existing
prefix/configuration/locale/path/file/allocation chain. The new checker derives
from the retained break checker. A default no-op fixture hook preserves older
modes; only the new mode replaces the initial key/backend fixture before each
connected registration. It poisons every key/backend and varies tail bytes, runs
original or rebuilt startup, then executes the existing worker case. These are
isolated initialized worker cases, not a claim that the real game initializes
the registry once per request.

Direct probes exercise null constructors with counts 0, 1, 32, `0x80000000` and
`0xFFFFFFFF`; modeled ARM/Thumb callbacks with counts 0, 1, 3 and 32; zero, unit,
positive and wrapping negative strides. Callback models clobber r0-r3/r12,
discard results, check receiver order, instruction decoding mode and stack
alignment, and preserve callee-saved registers. They do not dereference the
synthetic wrapping addresses. Concrete record probes use guarded aligned
storage, offsets 0/4/12 and strides 0/12/16/20. The oracle checks the exact
twelve-byte write footprint and every untouched guard/tail byte.

Two persistent lifecycles per implementation cover disposal and retained-owner
flags: initialize poisoned records, fail an initial open, register/open, reject a
duplicate, remove/fail open, reuse with a different backend, open, remove/fail
open. There are no registry resets between those operations. Existing registry
and open oracles check statuses, table state, disposal order, global effects and
the virtual backend receiver. Inherited arbitrary occupied-table probes keep
their original fixture boundary.

Remaining models: arbitrary constructor bodies, backend open/disposal, allocation
storage, locks/services and kernel responses retain their documented inherited
scope. Only the concrete record constructor executes here. Neither nonnull
constructors with billions of iterations nor invalid/misaligned writable
receivers, general callback aliasing/reentrancy, concurrent registry access or
abnormal callback unwinding is behavior-verified. Source and comparison code do
not add validation that the original lacks. Full original binary matching,
whole-program build, native playability and deferred live G1/G2 are unclaimed.

## Validation

Primary: `local/validation/registry-initialize-20261013-dev2/COMPLETE.json`.
The accepted directory keeps its development name; no later source/checker
changes are hidden behind it. The warning-clean freestanding ARMv6K GCC image
is **5,320 bytes**, 116 bytes above retained break mode. This is a behavioral
rebuild, not binary matching or a reconstructed game executable.

**57 direct original/rebuilt initializer pairs** pass; all **27 new original
instruction sites** execute (17 Thumb helper, five record and five startup).
Four persistent initialized lifecycles across both paths pass. The **2,304
connected worker pairs** execute **4,608 actual registry initializations**.
Instrumentation records 148,518 constructor entries across all new comparisons,
including the connected 32-record loops. The inherited 1,245 original sites and
all retained direct comparison families remain exercised; this number excludes
the separately recorded 27 initializer sites. Relevant files beside the marker:

- `registry-initialize-results.tsv`: direct cases, callback addresses and lifecycles.
- `original-registry-initialize-ghidra.txt`: visited sites, modes and saved membership.
- `original-array-initialize-disassembly.log`, `original-record-initialize-disassembly.log`,
  `original-registry-startup-disassembly.log`: independent GNU decoding.
- `comparison.json`, `build-command.json`, `build.log`, `disassembly.log`,
  `registry-initialize-entries.txt`: full inherited results and rebuilt identities.

The earlier `registry-initialize-20261013-dev` run stopped at a harness-only
ARM/Thumb assertion: the emulator's CPSR shadow did not track its decoding mode.
The corrected checker reads `thread.getContext()`'s TMode, as the existing break
checker does. No recovered source change was needed. This failed run is not
counted as behavioral acceptance.

`local/validation/registry-initialize-20261013-audit/negative-checks.json`
records five compiled faults and their actual assertion failures: wrong count,
wrong stride, changed base return, record-tail clearing and startup count 31.
Each build succeeds before the corresponding count/receiver/return/footprint/
startup-binding assertion rejects it. The public suite passes **134 tests** in
`public-tests.log`; `arm-consumers.json` records warning-clean compilation of
all **16 C units** whose compiler dependency lists consume either changed header.
These are supporting checks, not additional recovered contracts.

Audit: `local/validation/registry-initialize-20261013-audit/COMPLETE.json`.
`regressions.json` records retained break and prefix modes reproducing their
previous **complete comparison objects and identical 5,204/5,100-byte binaries**.
`validation-jobs.json` records all seven sequential fault/regression commands,
actual zero exits and durations. The audit verifies all 50 primary input hashes,
the rebuilt binary and pinned original executable; it also records package-file
and evidence hashes. Python compilation, JSON parsing, the 157-entry table sum
and whitespace checks pass. Ghidra jobs ran sequentially and every launched
command finished.

Reproduce from `SMT4-decomp`, choosing fresh outputs and running Ghidra jobs
sequentially on the authoritative saved project:

```powershell
python tools/check_resource_worker_io.py --recover-registry-initialize --output local/validation/NEW-REGISTRY-INITIALIZE
python tools/check_resource_worker_io.py --recover-registry-initialize --mutant init-tail --output local/validation/NEW-REGISTRY-TAIL-NEGATIVE
python tools/check_resource_worker_io.py --recover-break --output local/validation/NEW-BREAK-REGRESSION
python tools/check_resource_worker_io.py --recover-prefix --output local/validation/NEW-PREFIX-REGRESSION
python -m unittest discover -s tests
```

## Next independent source milestone

Recover the remaining **resource global startup** in ARM
`0x003F3568..0x003F36F0`, reusing the registry slice and existing pool/lock
initializers. The next original behavior is global publication and construction
of the backend pools, not another array-helper recovery. Start from
`next-resource-startup-disassembly.log`, `next-startup-literals.json` and
`next-startup-tail-disassembly.log` in the static directory above; verify saved
membership and mode before implementation.

The continuation clears global `0x0044E660`, initializes lock `0x004D43D0`, and
constructs pools at `0x004D431C`, `0x004D4358` and `0x004D4394`. Their backing
ranges start at `0x004306C0`, `0x004307C0`, `0x004308C0`; element/storage sizes
are 16/256, 8/256 and 8/128, all with alignment 4 and options zero. The common
vtable literal is `0x00420B9C`. Reuse `0x002A4EB4`, `0x002C3B54` and
`0x00138F44` from `src/resource_pool_initialize.c`, plus the recovered quotient.
The final branch is to `0x00225E68`, whose decoded body is a single `BX LR`;
do not invent destructor-registration effects for it or for the intervening
NOP sites. A broader runtime-library interpretation remains unproven.

Extend the initialized-backend harness in `tools/check_resource_pool_initialize.py`
with an explicit global-startup mode. Compare guarded global/pool fields,
list links and capacities, lock initialization/exclusive retries and ordering,
then feed take/create/register/open/remove/return/reuse with the actual global
storage. Reuse this package's registry source. Keep external services, backing
bytes and exclusive outcomes explicit; save partial source/static evidence if
an actual dependency boundary prevents the full connected milestone. Do not
repeat completed pool/lock leaf recovery or start port implementation.
