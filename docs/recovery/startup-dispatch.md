# Startup callback dispatch

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; names are descriptive, not original
symbols. No external implementation reused.

## Strategy review and acceptance

The prior
constructor milestone's recorded source/tool hashes all still matched before
implementation (`local/validation/startup-dispatch-20261013-static/prior-handoff-check.json`).
This package advances that constructor into its real startup dispatcher; it does
not repeat constructor recovery or resume deferred extraction/compiler work.

Acceptance declared before implementation: recover Thumb
`[0x00100CB8,0x00100CD2)` and ARM `[0x00102338,0x00102364)`, build warning-clean
source, compare ordered table reads/callback targets, modulo address arithmetic,
distinct termination conditions, ignored callback results, ARM/Thumb interworking,
callee-saved registers, restored stack and guarded memory. Traverse the pinned
636-entry relative table with the resource constructor executed, explicitly model
the other constructor bodies, preserve the pinned empty absolute range, reject
meaningful compiled faults and retain affected regressions. Full process startup
and live G1/G2 are outside this milestone and remain open.

## Recovered source contracts

`src/startup_dispatch.c` and `.h` add **two complete entry contracts**:

| Entry | Source | Effect |
| --- | --- | --- |
| Thumb `0x00100CB8` | `smt4_startup_dispatch_relative` | While cursor differs from end, read one word, call `(cursor + word) mod 2^32`, advance cursor by four modulo 2^32 |
| ARM `0x00102338` | `smt4_startup_dispatch_absolute` | While cursor is unsigned-lower than end, read an absolute target, call it, advance cursor by four modulo 2^32 |

Both callbacks have a no-argument, ignored-result interface. Neither loop adds
null-target, range-validity or nontermination handling. Callback bodies may
clobber caller-saved registers and flags. Future table words are read after the
preceding callback returns. The semantic C source uses explicit `uint32_t`
cursor arithmetic and volatile table loads; it requires the original 32-bit
address domain. It does not serialize host pointers.

Four linker symbols bind the original entries to their table endpoints. Relative
endpoints are `0x0042A188` and `0x0042AB78`; both absolute endpoints are
`0x0042AB78`. The two `_range` functions are parameterized comparison adapters
for these same loops, not additional recovered original entries. They permit
synthetic endpoint probes without inventing input parameters for the originals.
The ARM behavioral rebuild is not an instruction-mode or binary-matching claim
for the original Thumb dispatcher. Return/scratch register values, private stack
contents and the register holding the internal cursor are not exposed contracts.
Callbacks that inspect those incidental values are outside the compared ABI.

## Static binding and comparison

`local/validation/startup-dispatch-20261013-static/membership.txt` confirms saved
function bodies `[00100cb8,00100cd1]` and `[00102338,00102363]` and their Thumb/ARM
modes. Read-only Ghidra inspection did not change the saved project. Independent
GNU disassembly is included in the primary output; literals are kept distinct
from executable instructions. The relative loop's `BNE` differs from the
absolute loop's unsigned `BCS`/`BCC` checks.

`--recover-startup-dispatch` extends the existing pool/global build driver and
adds `CompareStartupDispatch.java`, reusing `GlobalPlan` for ordered constructor
effects. The checker hashes the original image, checks the four endpoint
literals, derives all 636 targets independently from the pinned table, checks
each table-read address and callback target in order, and verifies all 24
original dispatcher instruction sites execute across the corpus. It checks
stack guards, SP/r4-r11 preservation, target and return modes, full guarded state
and instruction budgets. Unlisted code cannot execute on either path.

The pinned relative traversal executes callback **331** at entry `0x0042A6B4`,
offset `0xFFFC8EB4`, target `0x003F3568`. On the rebuilt path the checked original
callback address is rebound to the compiled constructor before any instruction
there executes. Its registry, all three pools and four locks are constructed
through recovered source, using the inherited exact ordered-event oracle.
Two traversals use exclusive-failure schedules `[0,0,0,0]` and `[1,2,3,4]`.
The third pinned case confirms the absolute table is empty.

The other **635 constructor bodies per pinned traversal** are explicit models:
the checker supplies varying r0/r1/r2/r3/r12 and flags, temporarily substitutes
a `BX LR` instruction in emulator memory, executes that model return, then
restores the bytes. Their original bodies and effects are not executed or
claimed recovered. This exercises dispatcher call/return interworking while
keeping other constructors outside the domain. No dump or saved database bytes
are patched. Synthetic ARM and Thumb callbacks use initialized model stubs.

Twelve emulator-only synthetic pairs cover empty/single/mixed tables, a callback
changing the following table entry, unsigned high addresses, relative cursor
wrap through zero, reversed absolute bounds, and an absolute endpoint between
word boundaries. Original endpoint literals are changed only in emulator memory;
rebuilt probes call the range adapters. These probes do not assert that the
pinned application uses alternate tables or Thumb constructors. Full-width
offset addition is exercised by both negative pinned offsets and wrapping probes.

The new connected corpus replaces the isolated dispatch boundary with execution
and binds its resource callback to recovered source. It does **not** remove the
other constructor models, or change any older checker's published models.
Backing bytes remain synthetic and exclusive outcomes scheduled. The inherited
unrelated singleton starts zero as a fixture. Non-returning/malformed callbacks,
unreachable relative endpoints, unmapped storage, concurrency, reentrancy,
pending dispatch prefixes, full startup/read integration and live agreement
remain outside this bounded evidence. The retained constructor regression still
covers its own pending lock prefixes and persistent backend consumers.

## Validation

Primary: `local/validation/startup-dispatch-20261013-dev1/COMPLETE.json`.
The first build/comparison passed; the directory name is retained with exact
source/tool hashes in its completion marker.

- Warning-clean freestanding ARMv6K GCC image: **3,352 bytes**, a **192-byte**
  increase over the retained constructor build (including the two range adapters).
- **15 original/rebuilt pairs**: three pinned and twelve synthetic; **2,578**
  checked table reads and callbacks across both paths; **16** Thumb callback
  invocations; all **24** original dispatcher instruction sites executed.
- **Four concrete resource-constructor invocations** across both paths, checking
  **36** exclusive attempts and all ordered writes/guarded layouts.
- Three independently compiled faults rejected: relative `<` in place of `!=`
  fails the wrapping case; omitting the relative entry-address addition fails
  the pinned traversal; absolute `!=` in place of `<` fails reversed bounds.
  Rejections are runtime assertions, not compilation failures.
- Retained `--recover-global-startup`: identical **3,160-byte binary** and entire
  comparison object, including 21 constructor pairs, eight pending prefixes and
  70 persistent backend-consumer pairs. Shared recovered dependencies are unchanged.
- All **134 public tests** pass. Python syntax, symbol JSON, primary input hashes,
  original/rebuilt image hashes and package whitespace checks pass in the audit.

Audit: `local/validation/startup-dispatch-20261013-audit/COMPLETE.json` and its
supporting checks, negative results, regression summary and public-test log.
Ghidra jobs ran sequentially and all commands finished. No commit or live session was performed.

The initial local inspection launcher was named `inspect.py`, shadowing Python's
standard module during imports. It was renamed before the successful read-only
inspection; no source or behavioral assertion change was needed.

```powershell
python tools/check_resource_pool_initialize.py --recover-startup-dispatch --output local/validation/NEW-DISPATCH
python tools/check_resource_pool_initialize.py --recover-startup-dispatch --mutant dispatch-relative-bound --output local/validation/NEW-DISPATCH-NEGATIVE
python tools/check_resource_pool_initialize.py --recover-global-startup --output local/validation/NEW-GLOBAL-REGRESSION
python -m unittest discover -s tests
```

## Next independent source milestone

Recover table-resource registry initializer **`0x003F05F0`**, then replace its
modeled callback in this dispatcher corpus and exercise recovered registry/bulk
consumers from its resulting state. Pinned callback **190**, entry `0x0042A480`,
offset `0xFFFC6170`, resolves to this target. This replaces concrete registry
initial-state fixtures serving the already recovered table consumers.

Read `docs/tbcr-consumers-eu.md`, `docs/recovery/resource-lifecycle.md` and
`docs/recovery/resource-bulk.md`. Fresh GNU evidence is saved as
`next-table-registry.log`, `next-table-registry-continuation.log` and
`next-table-registry-binding.json` in this package's static directory. Confirm
saved membership before implementation: executable intervals are
`[0x003F05F0,0x003F090C)` and `[0x003F0CB8,0x003F0F50)`, linked by the branch
at `0x003F0908`; intervening literals/strings are not code. The final instruction
at `0x003F0F4C` is `BX LR`.

The first interval writes ancillary globals through `0x00446518` and
`0x00446520`, then initializes the 67-record registry at `0x0049382C` with path
addresses, cleared loaded/size fields and policy bytes. Preserve each record's
three opaque trailing bytes and exact ancillary writes; keep private strings
local, with explicit original address binding. NKMSortIndex remains slot 1,
path pointer `0x003F0930`, policy one. Use the existing dispatcher/global and
`tools/check_resource_bulk.py` / lifecycle harnesses as appropriate; do not
execute other original constructor bodies or resume live gameplay.
