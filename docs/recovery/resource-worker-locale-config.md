# Worker locale category configuration and query

2026-10-08. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Project names describe observed behavior, not original library symbols.

## Selection and acceptance

Category configuration is the next connected source milestone, with
three saved Thumb bodies and only already-recovered executable dependencies.
The prior image and 37 source/tool identities were verified before changing the
builder (`local/validation/worker-config-20261008-audit/handoff-check.json`).

Acceptance: instruction-backed query, mask dispatch, ordinary-name configuration
and five-word restoration; exact partial publication and unchecked byte arithmetic;
guarded original/rebuilt return, state and serialization agreement; configuration
before connected worker conversion/open; warning-clean bounded build, meaningful
fault rejection and retained regressions. Optional extraction, compiler research,
live gameplay and port implementation are outside this package.

## Source contracts

`src/resource_worker_locale_config.c` and `.h` recover:

| Original Thumb body (end exclusive) | Source contract |
| --- | --- |
| `[0x002C6AA8,0x002C6B46)` | `smt4_worker_locale_query` |
| `[0x002C6B46,0x002C6BAA)` | `smt4_worker_locale_configure` |
| `[0x002C6BAA,0x002C6C3E)` | `smt4_worker_locale_set_name` |

The dispatcher accepts masks 1 through 31. Invalid masks return zero before
reading the name or touching state/output. A null name queries. A nonnull name
whose first byte is not `*` calls the ordinary setter. A leading `*` consumes
exactly eight bytes for each of five words, including unselected words. For each
byte `c`, the value becomes `(value << 4) | (c - (c < 58 ? 48 : 87))`, modulo
32 bits. This is **not** a validating hexadecimal parser: uppercase letters,
embedded zero, punctuation and high bytes retain their original arithmetic.
Selected words are published in increasing slot order before the final query.

The ordinary setter visits categories in order **2, 1, 4, 8, 16**. Category 2
uses selector `0x00138208`, publishing its result plus one. Category 8 uses
`0x0014D908`. Either zero selector result returns zero immediately; prior stores
remain visible and the output buffer is untouched. Categories 1, 4 and 16 store
the fixed pointer `0x0042A184`, regardless of the name. Disassembly contains NOPs
where the decompiler's presentation might suggest missing selection logic;
there are no executable selector calls for those three categories. The source
retains fixed-pointer zero checks, although that condition is unreachable in
the pinned image. Successful configuration returns the query result; the saved
decompiler's void setter prototype is misleading.

Query serializes **all five** context words for any multi-bit mask, not just
selected categories. It writes `*`, forty lowercase hexadecimal digits in word
order (most significant nibble first), and NUL: 42 bytes total. The direct helper
does this even for multi-bit masks rejected by the dispatcher. Singleton masks
1, 2, 4, 8 and 16 select the corresponding context word. A zero word returns
the private `C` name at `0x002C6C40`. Otherwise it masks off two pointer bits,
loads the relative word at base minus four and returns base plus that word,
with 32-bit wrapping arithmetic. Other masks return zero without output writes.

The context accessor, both selectors and their name comparison execute recovered
source. Original names, relative words and locale/mapping data remain private
reference dependencies. No original data is copied into tracked source.

## Integration and boundaries

New `--recover-locale-config` implies bootstrap and its connected dependency
chain. After bootstrap, the connected fixture executes either ordinary empty-name
configuration or encoded restoration for all five categories, then conversion,
open, read and cleanup. This extends the executed source contract; the older
bootstrap mode had no modeled configuration call to remove. Earlier direct
locale/path probes retain their documented initialization fixtures.

The private callback word still relocates to the rebuilt callback. Backend
open/close, OS read/size, diagnostics, raw allocation/registration, clearing,
locks and complete allocator ownership remain modeled or open. Synthetic prefix
table initialization remains a fixture. This package does not establish native
service replacements, binary matching, a full game build or live behavior.
G1/G2 live evidence and full ABI/provenance/transfer gates remain open.

The compared domain uses mapped 32-bit pointers, nonaliasing input/output/context
storage, terminated ordinary names and exactly 41 readable encoded bytes. A
singleton query requires a readable relative word after masking a nonzero value;
values 1 through 3 and arbitrary invalid pointers are outside that domain.
No synchronization, concurrent mutation or aliased-buffer claim is made.

## Build and validation

Primary evidence is
`local/validation/worker-config-20261008-dev4/COMPLETE.json`. The warning-clean
freestanding C11 ARMv6K image is **4,548 bytes**: 704 bytes more than bootstrap,
comprising 688 new compiled text bytes and 16 compiler-generated data bytes.
All **186** new original instructions were visited (1,056 in the combined run).
GCC is a behavioral toolchain, not an identified matching compiler.

The **4,024 direct pairs** cover every mask 0 through 33 and representative
high-bit/full-width masks; all four name alignments; empty, accepted, truncated,
extended, wrong-case and high-byte ordinary names; direct setter null names;
zero and tagged synthetic pointers with positive/negative relative words; and
every byte value at early, word-final and payload-final encoded positions.
The raw helpers and dispatcher's different mask domains are tested separately.
Multi-category masks expose partial failure after earlier stores and untouched
output on failure. Encoded probes verify the exact 41-byte readable footprint,
including embedded NUL and unselected categories. Invalid dispatch masks read no
name bytes. Every case checks exact r0, ordered context stores, bank/output/input
guards, immutable relative data, stack restoration and callee-saved registers.

Two persistent sequences (one per implementation) serialize nondefault state,
change it through ordinary configuration, then restore the saved representation
on the same storage. The **2,304 connected worker pairs** execute configuration
4,608 times, alternating ordinary empty-name setup and encoded restoration,
before real recovered conversion/open. All inherited direct probes remain
active. Instruction visitation does not imply every branch outcome or live
coverage; the fixed-pointer zero branches cannot occur with pinned data.

Audit: `local/validation/worker-config-20261008-audit/COMPLETE.json`.
Three compiled faults are rejected: admitting mask 32 (forbidden name read),
changing the encoded-byte threshold (wrong published word), and omitting a
category-4 store when category 8 is selected (wrong publication sequence).
`negative-checks.json` records their exact assertions and source/binary hashes.
The retained bootstrap and legacy I/O modes have identical binaries and complete
comparison objects to their accepted baselines (`regressions.json`). All **134**
public tests pass. The initial PowerShell-redirection run also printed OK but
reported shell exit 1 because unittest writes to stderr; the recorded audit
rerun captures both streams through Python and confirms actual process exit 0.
No test failure was hidden. `validation-jobs.json` records all audit commands,
statuses and elapsed times. Every launched command finished.

The final audit checks primary artifact identities, the unchanged original
executable, diff whitespace and package file hashes.

The build includes compiler-generated `.rodata` for this mode. The earlier
text-only exporter omitted a 16-byte table generated for singleton dispatch;
the first two development comparisons rejected an out-of-image read. This is
a build-image fix, not recovered game logic. The third run passed all new direct
checks, then found an uninitialized synthetic guard in connected setup. The
fixture was initialized, and the persistent round trip was strengthened to
restore distinct saved state after ordinary configuration changes it.

Run from `SMT4-decomp`, with fresh outputs and sequential Ghidra jobs:

```powershell
python tools/check_resource_worker_io.py --recover-locale-config --output local/validation/NEW-CONFIG
python tools/check_resource_worker_io.py --recover-locale-config --mutant config-byte --output local/validation/NEW-CONFIG-NEGATIVE
python tools/check_resource_worker_io.py --recover-locale-bootstrap --output local/validation/NEW-BOOTSTRAP-REGRESSION
python -m unittest discover -s tests
```

## Next independent milestone

Continuation: the subsequent [prefix mutation package](resource-worker-prefix.md)
implements and compares the contracts below.

Recover **prefix registration and removal**, ARM `0x002B5E70` and
`0x002C4054`, and integrate registration with the recovered resolver/open chain.
Their saved bodies are `[0x002B5E70,0x002B5FB8)` and
`[0x002C4054,0x002C41A4)`. The read-only continuation inspection saved
`local/validation/worker-config-20261008-audit/next-prefix-ghidra.txt` and
`next-function-2b5e70.c` / `next-function-2c4054.c`, including instruction bytes
and xrefs to the existing table at `0x004D43E0`. These are static findings, not
additional recovered contracts.

Registration normalizes a name terminated by NUL or colon within eight bytes,
constructs the same signed-byte 64-bit key as the recovered resolver, scans
32 sixteen-byte records, and publishes a key, backend pointer and two flags.
The scan tests vacancy before duplicate key equality; preserve this order.
Removal clears pointer/key before any optional backend virtual call at +0x30,
preserves flag bytes and conditionally clears a global backend pointer after
the call. Confirm literal statuses, signed-byte behavior, flag handling and
reload effects against instructions. Overlong names enter the already-known
diagnostic chain `0x002BCE9C`; do not presume normal return. Compare terminal
and explicitly modeled returning continuations separately if both are needed.

Next acceptance: guarded registration/removal and failure statuses, exact
vacancy/duplicate/full-table order, persistent register→resolve/open→remove/reuse
sequences, and backend-disposal side effects under an explicit model. Use the
existing 32-record fixture and `CompareResourceWorkerFileOpen` chain. Startup
constructor `0x003F36xx` and alternate lookup `0x003F7050` were inspected as
leads only; neither is a demonstrated prerequisite for this bounded mutation
milestone. The thin locale caller `0x00100238` was also exported as static
context; it is not counted as recovered in this package.
