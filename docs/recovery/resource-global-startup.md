# Resource global startup

2026-10-13. EU base v0 expanded executable SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project-authored instruction recovery; names are descriptive, not original symbols.
No external implementation reused.

## Strategy review and acceptance

Every file
and evidence hash in the preceding registry audit matched before changes;
`local/validation/global-startup-20261013-static/prior-handoff-check.json`
records that check. The completed registry milestone is not repeated. Its next
resource-global constructor is retained because it replaces concrete construction
fixtures feeding backend lifetime. No extraction, compiler research, live session
or port work is needed.

Acceptance declared before implementation: recover ARM `0x003F3568..0x003F36F0`,
reuse registry/array and pool/lock/quotient source, verify the no-effect tail,
compare exact ordered global effects and guarded bytes, all three pool layouts,
links/capacities, exclusive retries and pending prefixes, then execute persistent
take/create/register/open/remove/return/reuse from actual global storage. Build
warning-clean ARM source, reject meaningful compiled faults and retain affected
regressions. Complete process startup, external services and live gates are not
acceptance criteria for this bounded constructor.

## Recovered contract

`src/resource_global_startup.c` and `.h` add **one complete entry contract**,
`smt4_resource_global_startup`, covering `[0x003F3568,0x003F36F0)` and the semantic
return through `0x00225E68`. The latter is a single ARM `BX LR`; no separate
routine is counted. The prior registry slice remains a reused source adapter,
not another new recovery. The local C `construct_pool` helper represents repeated
inline instructions, not an original function entry.

The constructor performs these effects in order:

1. Initialize 32 records at `0x004D43E0`, stride 16, using the recovered array and
   record routines. Only each record's first twelve bytes are cleared.
2. Clear `0x0044E660`, then clear base word `0x004D43D0` and initialize that
   recursive lock. Its owner/count remain untouched until the base exclusive
   store succeeds.
3. Construct each pool below. Before configuration, clear words +4/+8/+12/+16/
   +20/+36/+48/+52, write `0xFFFFFFFF` at +56, and publish vtable `0x00420B9C`
   at +0. Execute pool configuration, then initialize its recursive lock at +48.

| Pool | Backing address | Element/stride | Storage bytes | Capacity |
| --- | --- | ---: | ---: | ---: |
| `0x004D431C` | `0x004306C0` | 16 | 256 | 16 |
| `0x004D4358` | `0x004307C0` | 8 | 256 | 32 |
| `0x004D4394` | `0x004308C0` | 8 | 128 | 16 |

All configurations use alignment four and options zero. The recovered pool
initializer constructs backward links, publishing the first node as head; node
payload bytes remain intact. The +56 sentinel is a real intermediate write even
though successful lock initialization subsequently clears it. The three NOP
sites do not register destructors. The final tail leaves `0x004D4394` in r0;
the C return type exposes that observed register result, not an inferred original
prototype. Incidental scratch-register values, flags and instruction shape are
not a matching claim.

Reused entries are `0x002C5FAC`, `0x003561F0`, the registry slice,
`0x002A4EB4`, `0x002C3B54`, `0x00138F44` and the consumed quotient. The new
mode executes these dependencies; it never copies expected initialized bytes
into either machine.

## Original evidence and comparison domain

`local/validation/global-startup-20261013-static/membership.txt` records exact
startup words and ARM TMode. Neither startup nor its no-op tail has a saved
function object. The startup listing itself is undefined in the saved database;
raw bytes, independent GNU disassembly and controlled instruction execution
establish the body. The tail is decoded as `BX LR`. Read-only Ghidra runs do not
change the authoritative database. Primary `original-smt4_resource_global_startup.log`
and `original-startup_noop_tail.log` independently decode the selected intervals.

`--recover-global-startup` extends `tools/check_resource_pool_initialize.py`
with `CompareResourceGlobalStartup.java`, reusing the existing backend and pool
harness. An independent ordered-event oracle checks every non-stack startup
write, pool field reload, exclusive load and attempted store. Full guarded bytes
are checked independently for both implementations. Instruction allowlists,
ARM/Thumb decoding mode, execution budgets, stack guards/restoration and
callee-saved registers are enforced; pending prefixes do not claim a return.

The direct domain includes initial fills 0, 255 and 165; successful schedules
with failures `[0,0,0,0]`, `[1,2,3,4]` and `[4,0,1,2]`; and pending prefixes at
each of four locks after one or five failures. Pending cases stop before the next
LDREX and verify that later construction and owner/count stores have not happened.

Two persistent sequences use different initial poisons and execute startup twice
on unused storage without reseeding. They attempt an absent-prefix open, a failed
archive creation, and three create/register/duplicate/open/remove/absent-open
rounds. Each removal concretely tears down and returns the node. They then take
all sixteen archive nodes, attempt a seventeenth take, and verify creation failure
and handle cleanup on exhausted storage. Every operation uses the actual global
pool and backing addresses; the other two constructed pools retain their complete
checked layouts and links throughout these consumers.

The new mode replaces global construction, pool header/list/lock-result and
registry key/backend fixtures with execution. This is fixture replacement in a
new corpus, not removal of a named intercepted call from an older mode. The
older pool/backend/worker modes retain their published scopes.

Remaining models: backing bytes are synthetic; exclusive outcomes and TLS are
scheduled; archive open/close, virtual backend file open and diagnostic/service
boundaries retain the backend harness's models. The service global starts cleared
by startup, then the explicit archive-open model publishes a nonzero service
before successful backend creation. Unrelated singleton word `0x0044E658` starts
zero as a fixture; this constructor does not initialize it. Backend vtable method
bindings are relocated harness fixtures. No claim is made for invalid/unmapped
storage, live-owner reinitialization, concurrent initialization, arbitrary callback
reentrancy, actual kernel monitors, full startup/read integration or live G1/G2.

## Validation

Primary: `local/validation/global-startup-20261013-dev2/COMPLETE.json`.
The warning-clean freestanding ARMv6K GCC image is **3,160 bytes**, including
**344 bytes** for the new constructor and 116 bytes of reused registry source
beyond the retained 2,700-byte pool mode. No original binary helper executes on
the rebuilt path. This is a behavioral rebuild, not an application build or
binary matching.

- **21 startup pairs**, including **eight pending pairs**, pass ordered effects
  and complete guarded-state checks. All **98 startup instruction sites** execute;
  five belong to the previously recovered slice. The tail's one site also executes.
- **326 startup exclusive attempts across both paths** are checked.
- **Two persistent global lifecycles / 70 consumer pairs** pass, executing
  **192 recovered consumer lock calls across both paths**.
- Three separately compiled faults are rejected: shifted second-pool storage,
  omitted transient count sentinel and nonzero service clearing. Their failures
  are exact ordered-event mismatches, not build failures.
- The retained pool regression passes its complete unchanged comparison object:
  317 initializer pairs, four pending prefixes and six lifetimes / 54 calls.
  Its binary is 2,700 bytes versus the historical 2,688; pre-existing
  lock, clearing and prefix source changes differ from that historical build.
  `retained-build-size-delta.json` records the exact changed symbol sizes. This
  package changes none of those sources and does not claim historical binary identity.

The retained registry regression reproduces the **identical 5,320-byte binary
and entire comparison object**, including its 57 direct initializer pairs and
2,304 connected worker pairs. All **134 public tests** pass. Audit `checks.json`
verifies every primary source/tool hash, the rebuilt and original image hashes,
Python syntax, symbol JSON, the 158-entry recovery table sum and package whitespace.
All commands finished; Ghidra jobs ran sequentially. No commit or live check was performed.

The first development run built the C successfully but its new Java checker
failed compilation on an incorrect Ghidra context API call. The checker was
corrected to the existing `getRegisterValue(...).getUnsignedValue()` pattern;
no recovered C change or behavioral assertion weakening was needed. `dev2` is
the accepted primary directory, with source/tool identities in its marker.

Audit details and retained registry/public checks are recorded in
`local/validation/global-startup-20261013-audit/COMPLETE.json` and its supporting
JSON/log files. Commands use new outputs and Ghidra jobs run sequentially:

```powershell
python tools/check_resource_pool_initialize.py --recover-global-startup --output local/validation/NEW-GLOBAL-STARTUP
python tools/check_resource_pool_initialize.py --recover-global-startup --mutant global-tail --output local/validation/NEW-GLOBAL-NEGATIVE
python tools/check_resource_pool_initialize.py --output local/validation/NEW-POOL-REGRESSION
python tools/check_resource_worker_io.py --recover-registry-initialize --output local/validation/NEW-REGISTRY-REGRESSION
python -m unittest discover -s tests
```

## Next independent source milestone

Recover the actual startup callback dispatchers: Thumb
`0x00100CB8..0x00100CD2` and ARM `0x00102338..0x00102364`, reusing this concrete
resource constructor for its consumed callback. These are unrecovered source
leads in `docs/startup-eu.md` / `config/symbols-eu.json`, unlike the already
completed worker-loop and pool leaves. This moves the validated constructor
one level toward actual startup without admitting all other constructors.

`startup-table-binding.json` in this package's static directory proves that
entry **331** at `0x0042A6B4`, storing `0xFFFC8EB4`, resolves modulo 2^32 to
`0x003F3568`. The relative table is `[0x0042A188,0x0042AB78)`, 636 entries.
`next-relative-dispatch.log` / `next-absolute-dispatch.log` preserve exact
instructions/literals. The relative loop terminates on pointer equality; the
absolute loop uses unsigned bounds and has equal endpoints in the pinned image.
Do not conflate their conditions.

Acceptance for the next package: source and warning-clean build for both entries;
controlled original/rebuilt callback order, target calculation, stride/wrapping,
ignored callback results, ARM/Thumb interworking, preserved registers and guarded
memory; exact pinned-table traversal with this resource callback executed and
all other callback bodies explicitly modeled; preserve the pinned empty absolute
range. If synthetic endpoint/table probes are added, label those emulator-only
fixtures separately from pinned-input behavior. Reuse the current global-startup
oracle and avoid running unrelated original constructors. Full process startup,
other constructor effects and live gates remain open.
