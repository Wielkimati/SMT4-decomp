# Worker state-zero I/O region

The subsequent [locale configuration package](resource-worker-locale-config.md)
adds `--recover-locale-config`, implying bootstrap and its connected chain.
It executes category configuration/query/restoration before conversion/open;
older modes retain their documented fixtures. This extension adds three entry
contracts separately from the historical adapted region described below.

The subsequent [prefix mutation package](resource-worker-prefix.md) adds
`--recover-prefix`, implying configuration and its connected chain. Registration
now supplies the matching record before worker conversion/open. Direct and
persistent probes also execute removal; initial registry storage, backend
disposal and diagnostic delivery remain explicit fixtures/models. This adds two
entry contracts; it does not broaden older mode evidence.

2026-10-07. EU base v0 expanded-code SHA-256
`834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd`.
Owner: decomp; dependencies: the worker static trace and
[original I/O probes](resource-worker-step.md).

`src/resource_worker_io.c` reconstructs the internal ARM region starting at
`0x00113E80`, ending on arrival at `0x00114070`, including allocation branches
`0x00114098` through `0x00114130`. Its C interface accepts one descriptor; the
original uses the containing worker's registers and stack. This adds a second
adapted region of the same partially recovered worker, **no entry-point
contract**. The entry-point count remains thirty-two.

2026-10-08: optional `--recover-allocation` now executes the recovered object,
aligned and data allocators inside this region, with guarded retained metadata.
See [object allocation and connected I/O](resource-worker-object-allocate.md).
The default 3,456-case corpus and historical dependency boundary below are
unchanged; the new bounded mode is separate evidence.

The subsequent `--recover-file-methods` mode executes size/seek/read adapters
`0x003DFC54`/`0x00354F70`/`0x00354F9C` with the allocation mode. The caller now
declares size's original 64-bit return and explicitly consumes its low word.
See [file methods](resource-worker-file-methods.md) for lower file/diagnostic
models and the size-failure boundary. Older modes retain their historical scope.

The [lower file position package](resource-worker-file-position.md) now executes
size/cache, seek dispatch and position through the optional
`--recover-file-position` mode, retaining OS size/read and diagnostic models.
This report retains its original I/O-mode evidence boundary.

The subsequent [read-loop package](resource-worker-file-read.md) adds optional
`--recover-file-read`, executing lower read `0x002BB864` with the position chain.
Scripted OS read responses supply actual bounded payload segments; zero requests,
partial success and errors now determine cursor/count effects through recovered
source. Older modes retain their original read models and payload fixtures.

The subsequent [open/path package](resource-worker-file-open.md) adds optional
`--recover-file-open`, executing prefix lookup, UTF-16 length and open dispatch
with a modeled backend virtual open.

The subsequent [cleanup/destruction package](resource-worker-file-cleanup.md)
adds optional `--recover-file-cleanup`. It executes close dispatch and deleting
destructor/cleanup/null release with valid synthetic backend objects. Backend
close and allocator release remain explicit models; returning tagged diagnostic
continuation is conditional, with separate terminal probes and original-only
execution to `SVC 0x3C`. Older modes retain their historical boundaries.

The subsequent [path package](resource-worker-path.md) adds optional
`--recover-path`. It executes the predicate, measurement/conversion/byte-decoder
chain and fixed accessors with bounded byte-table paths. Locale callbacks remain
scripted in direct probes; initialization remains unrecovered. The caller and
all builders now use `path_is_initial` for the former misleading `path_reset`
name. The historical model below still belongs to the older comparison modes.

The subsequent [locale package](resource-worker-locale.md) adds optional
`--recover-locale`, executing the default byte callback and mapping with private
hash-bound tables through conversion/open. Bootstrap remains a fixture; older
modes retain their original path/callback models and domains.

The [locale bootstrap package](resource-worker-locale-bootstrap.md) adds
`--recover-locale-bootstrap`, executing context publication before the connected
conversion/open chain. It implies locale recovery; older modes retain their
initialization fixtures and the private callback relocation remains explicit.

## Reconstructed behavior

The block allocates a 24-byte file object, clears its five non-vtable words,
installs the construction table's first vtable, reads the adjustment at vtable
minus 48, and writes the construction table's fourth word at that adjustment.
It publishes the object in descriptor `+0x12C` before conversion and opening.

Path conversion starts at descriptor `+0x2C`. It initializes an eight-byte state,
passes `0x105` to the length helper, and advances the input by the returned byte
count and the output by one 16-bit unit only after successful conversion.
Zero length or zero conversion result terminates the loop. A 16-bit zero is
stored at the current output position, including after a failed conversion.
The lower conversion routines remain models; no encoding implementation is claimed.

Opening uses object `+4`, converted path and mode 1. A negative open result
stores state 5 but does not bypass size, seek, allocation or read. The size
method's low 32-bit result word becomes descriptor `+0x18`; seek receives zero offset and
origin. A nonzero descriptor data pointer skips allocation. For allocation,
only exact flags 1/17 select type `0x10000`; other values select `0x100`.
Only exact flags 16/17 select direction 0; other values select 1. Alignment is
`0x100`, the third argument is zero, and descriptor `+0x28` is passed unchanged.
The returned data address is stored even when zero.

The block acquires the handle at `0x00465124`, sets busy at `0x00465004` to 1,
reads into the selected data address, clears busy, reloads the handle and
releases it. The read count output does not replace the requested size.
A negative read result stores state 5 after release.

Handle values 0 and 1 bypass close. Other odd handles first call preclose;
the handle is reloaded afterward, bit zero cleared, and that value closed.
The object handle is then cleared. The descriptor's object is reloaded before
the optional virtual destructor. The enclosing worker, outside this region,
subsequently stores state 3, clears the object field and stores state 4. Thus
this source preserves the previously observed error fall-through under normally
returning modeled dependencies; it does not establish real failure delivery.

## Build and controlled comparison

```powershell
python tools/check_resource_worker_io.py --output local/validation/worker-io-next
python -m unittest discover -s tests -v
```

Evidence: `local/validation/worker-io-20261007-dev2/COMPLETE.json`.
The pinned GCC builds a **548-byte ARMv6K unit**. All **3,456**
original/rebuilt/oracle comparisons pass, visiting all **163** selected original
instruction addresses. The maximum is 2,035 executed instructions per path;
372,096 lower calls are checked across both paths. The rebuilt path executes no
original instructions. The saved Ghidra project is read-only; manifests record
source, checker, reference and tool hashes, build commands, independent GNU
disassembly and the executed Ghidra listing.

The corpus crosses positive/negative open and read results, six handle values
(including high-bit and odd cases), eight exact/decoy flag values, three supplied
buffer cases and six conversion profiles. Profiles cover empty, one-unit,
multi-unit and 120-unit output, plus failure at the first and third conversion.
Modeled conversions consume one, two or three bytes, return both 1 and unsigned
maximum on success, mutate their state, and write output even on failure.
Size, allocation result and descriptor parameter vary across zero, high-bit,
unsigned-maximum and ordinary values. These large sizes are argument tests;
the lower model does not allocate or read corresponding files.

Additional scheduled effects vary the construction adjustment, change the lock
handle during read, replace the object handle during preclose, or clear the
descriptor object during close. These are dependency fixtures checking reloads,
not claims about real lower routines. Object allocation succeeds in this corpus;
data allocation may return zero.

Independent oracles check complete descriptor and object bytes, construction,
conversion output, state-store sequence, dependency order, call arguments, busy
and lock state. Dependency snapshots are also compared between paths. Checks
enforce stack alignment and guards, rebuilt callee-saved registers, stack
restoration, initialized memory, store/read bounds and no object accesses after
destruction. Lower calls poison caller-saved registers and flags. Three original
Thumb helper boundaries use synthetic ARM call addresses in the rebuilt unit;
only these addresses are normalized, and no lower conversion code executes.

Five deliberately faulty variants are rejected through `--mutant`:
`open-early-return`, `flags-bit-test`, `short-read-size`, `cached-close-handle`,
and `advance-failed-conversion`. Generated variants and rejection records stay
under `local/validation/worker-io-20261007-negative-*/`.
All 31 public synthetic tests pass.

## Boundaries and next work

This remains a separately reproducible internal-region comparison. Subsequent
[I/O/completion integration](resource-worker-io-completion.md) executes this
source inside retained worker/completion/release passes with `--recover-io`.
The default worker-step and completion modes still intercept this region.
Next recover the outer wake/stop/list loop.

Lower object/data allocation, conversion, open, size, seek, read, close,
destruction and recursive locks remain modeled. Null object allocation,
overlong/malformed converted paths, arbitrary lower-call reentrancy, real file
contents, allocation reuse, concurrent execution, timing and actual filesystem
failure behavior are unverified. Source retains the original lack of a useful
null-object recovery path; successful object allocation and bounded conversion
are comparison preconditions. No full worker, filesystem, binary matching or
native port is claimed. G1/G2 remain open and live gameplay stays deferred.
