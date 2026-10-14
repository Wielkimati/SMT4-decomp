# Resource descriptor creation

2026-10-13 update: [wait consumed-return extension](resource-wait-return.md)
establishes wait/arbitration r0/r2 and replaces wait/initializer models in
create/chain `--recover-result-diagnostic`. Earlier evidence below retains its
historical boundaries; lower locks and kernel outcomes remain modeled.

2026-10-06. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Entry `0x002B0494`, ARM; original virtual addresses throughout. Names describe
observed roles, not recovered original symbols. Source was reconstructed from
local instructions; no external implementation was copied.

## Recovered contract

[`resource_create.c`](../../src/resource_create.c) implements `smt4_file_create`,
the dependency called by the [synchronous loader](resource-sync.md). It:

1. Reads the handle at `0x00465010` and invokes `0x002C4350` with one handle,
   zero in r3 and two all-ones stack words. The C boundary represents those words
   as a 64-bit timeout. A result with bit 31 set calls `0x002C54BC` with that
   result and r1=1. The comparison models this handler returning.
2. Calls allocation `0x002C4BD8` with `(0x100, 0x100, 0, 0x144, 1)`; the fifth
   argument is on the stack. It clears all `0x144` bytes via `0x002C4B84`.
   The meanings of the allocator's other parameters remain unclassified.
3. Appends the new descriptor to the list headed by the word at `0x0046500C`.
   An empty list receives the new head. Otherwise it follows `+0x13C` links
   to the tail, sets the tail's next link, and stores the old tail at new
   descriptor `+0x140`. Insertion happens before path handling and field setup.
4. Calls the length dependency and examines at most the first eight characters
   for `:`. If found, it copies the path to `+0x2C`. Otherwise it formats
   `rom:/%s` using the path as an argument. A colon at offset 8 is too late;
   there is no general URI validation. The original uses signed length comparisons.
5. Writes state `+0`=0, byte `+0x20`=`mode & 255`, words `+0x0C/+0x10/+0x14/+0x18`=0,
   `+0x28`=`0x80`, `+0x12C`=0, `+4`=1 and `+8`=0. These explicit writes follow
   clearing; unspecified descriptor fields retain their cleared values.
6. **Rereads** the global handle and calls `0x002C54A4` with a stack output pointer
   and that handle. Bit 31 again gates `0x002C54BC`. Returns the descriptor.

No allocation-null guard is present in the original or introduced in the source.
Path storage spans `+0x2C..+0x12B` (256 bytes); this function itself does not
enforce a path length bound. The recovered code requires 32-bit addresses and
retains offsets rather than inventing complete application types.

## Explicit dependency models

| Address | Modeled boundary |
| --- | --- |
| `0x002C4350` | Handle operation; checks timeout/count/arguments and writes synthetic output |
| `0x002C54A4` | Release operation; checks freshly read handle and writes synthetic output |
| `0x002C54BC` | High-bit result handler, modeled as returning |
| `0x002C4BD8` | Allocation; returns a fresh nonnull descriptor |
| `0x002C4B84` | Clear all descriptor bytes |
| `0x002C32E4` | Path length |
| `0x002BF8C0` | Copy including NUL |
| `0x002BE850` | Formatting with fixed format at `0x002B066C` |

Independent disassembly shows SVC `0x25` in the acquire boundary and SVC `0x16`
in the release boundary. Their OS implementations, scheduling and actual handle
semantics are not recovered here. The result handler has returning and further
dispatch paths; executing those paths is outside this package. Returning from
a modeled error handler proves subsequent constructor behavior under that model,
not that every real error is recoverable. Allocation and file I/O remain unrecovered.

Validated inputs are NUL-terminated, nonoverlapping short paths, successful
allocation, and finite acyclic lists of distinct aligned descriptors. Relative
paths fit after the five-byte prefix; already prefixed paths fit with their NUL.
Oversized/invalid pointers, allocation failures, cyclic/aliased lists, signed
overflow-length results, concurrent mutation and nonreturning dependencies are
outside the comparison domain. Exact instruction/store ordering between dependency
boundaries is not a concurrency-equivalence claim.

## Evidence and reproduction

The existing read-only Ghidra export in
`local/analysis/sync-20261006/exports/` contains the complete constructor listing,
references and private pseudocode. `tools/inspect_resource_sync.py` reproduces it.
The new checker also saves independent GNU disassembly of the constructor and
the synchronization/result-handler boundaries.

With the saved Ghidra project closed, run from `SMT4-decomp/`:

```powershell
python tools/check_resource_create.py --output local/validation/create-next
python -m unittest discover -s tests -v
```

`tools/check_resource_create.py` checks the pinned reference/tool hashes, builds
a separate 388-byte freestanding ARMv6 unit, and runs the original and rebuilt
instructions in separate Ghidra PcodeEmulator machines. No original instructions
execute on the rebuilt path. The project is opened read-only. Fresh outputs must
be under ignored `local/`; success is written only after the full corpus passes.

Successful record: `local/validation/create-20261006/COMPLETE.json`.

| Check | Result |
| --- | ---: |
| Original/rebuilt/expected constructor comparisons | 10,080 passed |
| Original instruction addresses visited | All 103 |
| Maximum instructions per call | 163 |
| Modeled dependency calls, both paths combined | 137,088 |
| Public synthetic tests | 31 passed |

The corpus combines 84 path cases, list lengths 0/1/2/7, six full-width mode
values, and five acquire/release-result pairs including positive and high-bit
results. Paths cover lengths 0..10 with each possible colon position or none,
lengths 31/127/250 around the scan boundaries, and 255-byte prefixed paths.
Randomized existing nodes and dirty allocation storage expose unintended changes.
The handle model changes the global after acquire to verify the release reread.

Checks include dependency order/arguments, snapshots before string handling and
release, every descriptor and existing-list byte, input/global preservation,
external store addresses/values/multiplicity (including redundant zero stores),
stack alignment/restoration, r4-r11 preservation, initialized reads, allowed
memory accesses, permitted PCs and instruction budgets. Store comparison is
normalized to bytes to permit equivalent compiler grouping and ordering.
Instruction-address coverage includes predicated instructions; it is not exhaustive
proof over all inputs.

Local negative checks reject an omitted backlink, extending the scan to nine
characters, and storing a full mode word instead of one byte. Driver:
`local/validation/check-create-negatives.py`; records:
`local/validation/create-20261006-negative-{backlink,scan-bound,mode-width}/NEGATIVE.json`.
The mode-width mutant is rejected even for zero by store multiplicity/extent.
Mutated source stays local and no negative run produces a success marker.

## Next work

2026-10-13: the optional `--recover-strings` mode now executes recovered path
copy `0x002BF8C0` and reused length `0x002C32E4` inside this constructor.
The 664-byte unit passes all 10,080 constructor pairs plus 352 direct copy and
88 length pairs, with exact string access traces and 151 original sites.
See [path-copy recovery](resource-path-copy.md) and
`local/validation/path-copy-20261013-create-accepted/COMPLETE.json`.
The default mode and historical evidence above retain their models.
Allocation, clear, synchronization, result handling and formatting remain modeled
in the new mode. Its next source task is the synchronization/result boundary
at `0x002C4350`, `0x002C54A4` and `0x002C54BC`, as detailed in that report.

Subsequent [wait/delay recovery](resource-wait.md) now passes 191 wait and 14,479
delay comparisons in 120 bytes. `0x002BB4F0` is a delay selector, correcting the
earlier callback hypothesis. Signal/sleep/spin boundaries remain modeled. The subsequent [integrated chain](resource-chain.md) now passes 3,888 comparisons
in 868 bytes with constructor/wait/delay execution. Next: atomic signal/arbitration recovery.
The prior sync/bulk/lifecycle checkers retain their documented higher-level models.
This constructor package brought the total to twenty-one bounded contracts;
the subsequent wait/delay package raises it to twenty-three.
Live verification and G1/G2 remain deferred/unpassed. Compiler/ABI research,
host address boundaries, actual I/O/allocation and full 3DS rebuilding remain open.

## Constructor synchronization mode (2026-10-13)

`--recover-sync` now executes recovered acquire `0x002C4350`, release
`0x002C54A4` and result dispatcher `0x002C54BC`, and composes with
`--recover-strings`. See [synchronization recovery](resource-create-sync.md)
for exact SVC marshalling, failure publication, caller-address/r2 transport,
ABI and connected comparison evidence. Kernel outcomes, diagnostic delivery and
returning break policy remain explicit models. Allocation, clear and formatting
remain modeled in these modes; the chain retains outer-prefix and timing models.
The older default and string-only boundaries above remain unchanged.

## Result diagnostic producer mode (2026-10-13)

`--recover-result-diagnostic` implies `--recover-sync` and executes new producer
`0x001284A8..0x001284D8`, composing with `--recover-strings`. See
[result diagnostic recovery](resource-result-diagnostic.md) for record store
order/widths, type narrowing, unknown-byte preservation and the returned-r2
contract. The [delivery return extension](resource-delivery-return.md) now
executes `0x002AD7E8` and reused process/request/copy/connect/delay source in
this mode, replacing its original r0/r2 outcome model. Lower lock/wait returned
registers, TLS/kernel/sleep, break, allocation, clear, formatting and outer-chain
policies remain explicit boundaries. Earlier modes keep their historical models
and evidence.
