# EU reference intake: 2026-10-06

This report records the reference inputs, extraction, executable map, and tool
setup. Intake facts below are
observations from 2026-10-06, not instructions to repeat completed preparation.

The user's dumps were inspected and extracted locally with pinned CTRTool 1.3.0.
Original files in the sibling `Game/` directory were read only. Their hashes were
checked before and after preparation and were unchanged.

## Confirmed inputs

| Input | Evidence |
| --- | --- |
| Base game | Title ID `0004000000141C00`, TMD version `0` (`0.0.0`), product code `CTR-N-AMXP`; two content records: executable application and manual |
| Region | ExeFS icon SMDH region mask `0x0000000C`: Europe and Australia; agrees with the user's EU identification |
| DLC | Title ID `0004008C00141C00`, TMD version `0`; 15 content records, indices `0000` through `000e`. These are content records, not a verified count of named DLC products. |
| Saves | `sdds4game1.sav` and `sdds4game2.sav`, each 151,088 bytes, each beginning with `DDS4GAME`; their SHA-256 hashes differ |
| Update/extdata | No separate update CIA or extdata backup was present in the supplied directory tree. This does not establish that an update or extdata is required. |

The executable ExHeader flags include `sd app`, consistent with the user's likely
eShop source. It does not independently establish purchase history. The save
backup directory is named `20361005-064435`; retain that name as provenance, not
as a reliable intake date or evidence of real-world play time.

Base CIA SHA-256:
`22b5f3a2ecb53d84315c1c0283407df03ff0231ba3ec2ccf40708efad0e39f46`

DLC CIA SHA-256:
`20f1d0f10b443684e6b7bd133b1b18261cbcc0db547171703d6f4149de13915e`

The complete input manifest, including save hashes and original relative paths,
is local at `local/reference-eu/inputs.json`.

## Verification and extraction

- Both CIA content sets and all 17 extracted NCCH contents are unencrypted.
  No console keys were needed for extraction.
- All 17 CIA content hashes verified. CTRTool's checked NCCH region hashes,
  ExeFS file hashes, and RomFS IVFC levels passed for the extracted contents.
- Ticket, TMD, and NCCH-header signature failures were reported. These are
  consistent with rebuilt/decrypted GodMode9 standard dumps. They are retained
  in the local command records, not presented as successful signature checks.
  Passing internal hashes establishes consistency, not retail authenticity.
- The main executable was selected from NCCH form/content metadata: base content
  `0000` is `Executable` / `Application`; `0001` is `Simple Content` / `Manual`.
- All base/manual/DLC contents were extracted separately, preserving their
  original content records. No update or DLC overlay was merged into the base.
- 20,423 output files were inventoried across content files, extracted regions,
  and filesystems, including 20,126 files in the main application's RomFS.
- This was one complete preparation run. A second raw-ExeFS decompression path
  was checked byte-for-byte against the NCCH-driven decompression. Both paths
  use the same pinned CTRTool implementation; this is not independent decoder
  validation or a second complete extraction run.

A09 update, 2026-10-08: a second complete preparation now exists at
`local/reference-eu-g3-20261008`. All 17 contents and 20,423 output files match;
both full output trees were rehashed, and input/output inventories are
byte-identical to G0. Selected executable, ExHeader and NKMSortIndex identities
also match. Both complete preparations still use the same pinned CTRTool 1.3.0.
See
[the repeatability report](recovery/reference-repeat.md) for exact evidence,
the reusable comparison command and data-free regression results.

Independent decoder update, 2026-10-08: the new project Python reverse-LZ decoder
reproduces every expanded executable byte and the pinned SHA-256 from the
compressed input. ExHeader compression bit 0 is set; the compressed footer
declares a 2,141,461-byte span, 11-byte footer, 1,491,600-byte growth and 91-byte
uncompressed prefix. The resulting 3,633,152 bytes agree with allocated segment
pages. See [the decoder report](recovery/code-decoder.md) and
`local/validation/code-decoder-20261008/COMPLETE.json`. This independently checks
executable expansion only; it did not validate container/filesystem decoding.

Independent table extraction update, 2026-10-08: a new project reader reproduces
all 50,400 NKMSortIndex bytes directly from preserved application NCCH
`base/content.0000.00000000` (SHA-256
`92d6feba05dbcacda8efb7d51dab6c2da35c079e4e2130848e9a56b1b96c824a`).
Independently read NCCH metadata confirms the executable/application identity,
version 2, 512-byte media units and NoCrypto flag. RomFS begins at `0x24C000`,
level 3 at `0x24D000`, and the table at NCCH offset `0x19D46C0`. The pinned
table hash remains `194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4`.
See [the extraction report](recovery/ncch-romfs.md) and
`local/validation/ncch-romfs-20261008-final/COMPLETE.json`. This checks NCCH
extents and the selected RomFS path; independent ExeFS/CIA decoding, IVFC hash
verification and full filesystem traversal remain unvalidated.

Tool provenance is pinned in [reference-eu.json](../config/reference-eu.json).
The official Windows x64 ZIP matched upstream SHA-256
`8031dff3be72d0adb250fae1f969f27627e12a89ebc6dd074a15a75f87ddc949`.
The extracted executable matched
`79021f283b2199950eb22cf3c459806b9c8aaaf68f65c80100107d3454a1c224`.
[Official release](https://github.com/3DSGuy/Project_CTR/releases/tag/ctrtool-v1.3.0).

## Executable and initial map

The application name in ExHeader is `sdds4`. Its code-compression flag is set.
CTRTool automatically expanded `.code` while processing the NCCH. Original
compressed bytes were separately extracted from the preserved ExeFS image.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Compressed code | 2,141,552 | `c9fafbf3a4e46e5f8b984e5b060d7cb90d12f4a0244bbe7440b2cfd97be4f2d9` |
| Expanded code | 3,633,152 | `834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd` |
| Full extracted ExHeader/access descriptor | 2,048 | `27305333aae9ce837964861a589ee3e44bb7ae234041d31bf97a20bba79cf29e` |

The following values come from ExHeader; file offsets follow the page allocations.
The sum of allocated segment sizes equals the expanded code length `0x377000`.

| Segment | Virtual address | Offset in expanded code | Initialized bytes | Allocated bytes |
| --- | --- | --- | --- | --- |
| `.text` | `0x00100000` | `0x00000000` | `0x002FE69C` | `0x002FF000` |
| `.rodata` | `0x003FF000` | `0x002FF000` | `0x0002BB78` | `0x0002C000` |
| `.data` | `0x0042B000` | `0x0032B000` | `0x0004B644` | `0x0004C000` |

BSS size is `0x000797F0`; stack size is `0x00004000`. Static startup analysis now
confirms a zero loop over `[0x00477000,0x004EFE34)` and zero-filled file padding
over `[0x00476644,0x00477000)`. See [startup-eu.md](startup-eu.md) for the explicit
Ghidra map and ExHeader arithmetic. Runtime clear-loop registers and before/after
memory now agree; the full initialized live image also matches the reference hash.

Useful local paths:

```text
local/reference-eu/base/content.0000.00000000  # preserved executable NCCH/CXI
local/reference-eu/base/0000/exheader.bin
local/reference-eu/base/0000/exefs.bin
local/reference-eu/base/0000/exefs-original/code.bin  # compressed
local/reference-eu/base/0000/exefs/code.bin           # expanded
local/reference-eu/base/0000/romfs/
local/reference-eu/base/0001/                        # manual
local/reference-eu/dlc/0000/ ... 000e/               # separate DLC contents
```

Metadata interpretation references:
[CTRTool NCCH processing](https://github.com/3DSGuy/Project_CTR/blob/ctrtool-v1.3.0/ctrtool/src/NcchProcess.cpp),
[Azahar code-set loading](https://github.com/azahar-emu/azahar/blob/master/src/core/loader/ncch.cpp),
[SMDH structure and region definitions](https://github.com/azahar-emu/azahar/blob/master/src/core/loader/smdh.h).

## Asset and save observations

The base RomFS includes 8,038 `.bcwav`, 368 `.bcstm`, 3,066 `.stex`, 1,170 `.mbm`,
386 `.tbb`, and 1,437 `.bf` files. These are filename-extension counts, not claims
that every file has been structurally decoded. Compression/archive formats remain
to be investigated.

Two concrete table candidates have a `TBCR` signature:

- `battle/NKMSortIndex.tbb`: 50,400 bytes.
- `item/ItemTable.tbb`: 202,544 bytes.

The observed TBCR/TBL1 corpus contains 404 accepted containers (386 `.tbb`,
18 `.bin`) and 768 sections. NKMSortIndex has four sections with 56, 1,201, 1,201,
and 1,201 exact entries. The wider corpus has 76 nondivisible payloads and three
zero entry-size fields; those bytes remain opaque and preserved. See
[the format specification](formats/tbcr.md) for the structural checks and limits.

No loose `.cro`, `.crs`, or `.crr` files were found in the base RomFS. Embedded
code or nonstandard module containers have not been ruled out. Do not infer
runtime use solely from the ExHeader's permitted-service list.

Both saves have readable game-specific headers, making them useful inputs for
save-format investigation. On 2026-10-06 the user confirmed that the supplied
saves load into gameplay in Azahar and that controls work. Their internal
structure, slot meaning, checksums, and player state have not been decoded.
Preserve the backups; use copies for testing. See the runtime report for limits.

## Reproduce preparation

Python 3.10+ and the pinned Windows x64 CTRTool binary are sufficient for this
pipeline. It performs no downloads. Keep the official binary at the default
local path below, or pass `--ctrtool` explicitly.

From `SMT4-decomp/`:

```powershell
python tools/prepare_reference.py --output local/reference-eu-repeat
python -m unittest discover -s tests -v
```

Defaults: inputs in `../Game`, tool at
`local/tools/ctrtool-v1.3.0/bin/ctrtool.exe`. The output directory must be new and
inside `local/`; existing output is never overwritten. Input packages must match
the configured hashes. Unidentified CIAs cause an error so another build cannot
silently replace the reference. Current extraction uses several GB of free space.

The tool writes `inputs.json`, `files.json`, `manifest.json`, and full local logs
with argument lists and retained signature exceptions. `COMPLETE.json` is written
only after extraction, checks, and final input-hash comparison succeed. A partial
directory without that marker is not a prepared reference. Logs may contain
ticket details, so keep the entire output private/ignored.

The intake package's seven synthetic tests passed, covering hash-failure
diagnostics despite zero exit status, unexpected errors, signature exception
recording, nonzero tool exit, access checks, output-file preservation, and
output-directory confinement.

## Emulator setup update: 2026-10-06

The user has extracted the selected Azahar Windows MSYS2 2126.1.2 distribution.
Filesystem inspection confirmed its actual executable location, relative to this
repository:

```text
local/tools/azahar-windows-msys2-2126.1.2/azahar.exe
```

The user linked `tools/` in chat, but the installation is under `local/tools/`.
It is already ignored by Git; no relocation was needed. The executable is
39,229,952 bytes, with locally measured SHA-256:
`21d4cd6b113f577fd6111e4919ac66f8aa7e4c62c425260f8e07765926306f86`.

The version/build identification comes from the selected distribution and folder
name. Windows file/product-version fields are absent. This hash records the local
executable; it is not a claim that its original ZIP was authenticated. The later
runtime log confirms the version/build recorded in the runtime-validation section.

During the initial installation check on 2026-10-06, the user reported a menu
boot; no agent runtime capture accompanied that report. The subsequent debugger
checks and save-load confirmation below supersede that initial evidence boundary.

## Ghidra setup and initial analysis: 2026-10-06

Ghidra 12.1.4 and Temurin JDK 21.0.12.1+1 are installed under `local/tools/`.
Official download hashes matched; pins and launcher hashes are recorded in
`config/analysis-tools.json`. The existing Java 8 installation was not changed.
The built-in raw loader plus `tools/ghidra/ImportSmt4.java` imports the already
expanded executable as ARM/Thumb v6 little endian with explicit segment permissions.

The saved project is `local/ghidra/smt4-eu/SMT4-EU.gpr`. Re-reading all initialized
bytes through Ghidra gives the pinned expanded-code hash. Initial automatic
analysis completed and found 8,786 function objects; these are not recovered or
validated functions. Logs and pseudocode are local only. Four reviewed labels and
additional startup leads are recorded in `config/symbols-eu.json`.

Confirmed static findings: entry at `0x00100000` in ARM mode; BSS clear routine
at `0x00100024`; a Thumb callback dispatcher at `0x00100CB8`, reached through BLX;
and a 636-entry relative callback table. `0x00101308` is a probable main-loop lead,
not a confirmed original symbol. Details and limits are in
[startup-eu.md](startup-eu.md); repeat/open instructions are in
[analysis-setup.md](analysis-setup.md).

## Runtime startup validation: 2026-10-06

Pinned xPack ARM GDB 16.3.90.20250906-git connected to the user-prepared Azahar
startup pause. The runtime log identifies **2126.1.2 | HEAD-9e6f523**, MSYS2, CPU
JIT enabled, 100% clock, OpenGL, and base program `0004000000141C00`. The initial
live initialized-memory capture exactly matched all 3,633,152 reference bytes.

BSS clear-entry, loop-begin, loop-end, ARM BLX, Thumb target, and final ARM startup
call breakpoints passed in a scripted repeat. Captured BSS was zero before and
after; the loop's start/end registers match the static bounds. Temporary traps
were removed, checked bytes restored, and detach/resume succeeded. The repeat
emulator remained responsive. Detailed evidence and limits, including the failed
first follow-up and successful recovery, are in [runtime-reference.md](runtime-reference.md).

Reproduce with `tools/debug_startup.py` against a fresh paused boot; all output stays
under `local/`. Cap GDB memory-read packets at 8192 and explicitly set each target's
ARM/Thumb breakpoint mode. Azahar's stub does not support single stepping.
The pinned Windows executable accepts `-g 24689` for a startup-paused launch;
`--gdbport` was rejected. Gameplay/save-load confirmation and its remaining
configuration/isolation limits are recorded below.

After debugging, the user confirmed on 2026-10-06 that a fresh normal launch
reached the main menu and that they closed the emulator after checking.
See the runtime report for the session distinction.

## Reference boundaries and recovery evidence

On 2026-10-06 the user followed the save-copy instructions and confirmed that
the supplied saves load into gameplay with working controls. This is a
user-reported successful restore, not an agent-captured run. The exact scene,
tested slots, current content configuration, and isolated-profile use remain
unrecorded; see [the runtime report](runtime-reference.md).

The static trace binds NKMSortIndex to registry slot 1 through initializer
`0x003F05F0`. Its two consumers are `0x002883E8` (section-2 u16 lookup) and
`0x001A0EA4` (section-3 u16 pairs); [consumer evidence](tbcr-consumers-eu.md)
records the addressing, fallback behavior, and independent disassembly checks.
The nonzero-policy loaded pointer at `0x00493840` is populated through bulk
loader `0x0033C8A0`; [lifecycle evidence](recovery/resource-lifecycle.md) records
the load/request/completion/release trace.

Detailed source/build/comparison history belongs to the existing recovery reports:

- Table consumers/helpers/division: [lookup](recovery/nkm-sort-index.md),
  [helpers](recovery/tbcr-access.md), [quotient](recovery/unsigned-quotient.md),
  and [section 3](recovery/nkm-section3.md).
- Registry loading and synchronous dependencies: [bulk](recovery/resource-bulk.md),
  [index/remainder](recovery/resource-order.md), [synchronous backend](recovery/resource-sync.md),
  [constructor](recovery/resource-create.md), [wait/delay](recovery/resource-wait.md),
  and [registry/chain integration](recovery/resource-registry-chain.md).
- Synchronization: [signal](recovery/resource-signal.md), [locks](recovery/resource-lock.md),
  [signal/locks](recovery/resource-signal-lock.md), [arbitration](recovery/resource-arbitration.md),
  and successive [chain](recovery/resource-chain.md),
  [chain/signal](recovery/resource-chain-signal.md), and
  [chain/SVC](recovery/resource-chain-svc.md) integrations.
- Asynchronous submission and retained cleanup: [request/completion](recovery/resource-request.md),
  [registry requests](recovery/resource-registry-request.md), and
  [release conversion](recovery/resource-release-convert.md).

Each report owns its corpus counts, build size, local `COMPLETE.json` paths,
mutation checks, and modeled dependencies. A modeled dependency in an earlier
checker remains that checker's boundary even after another package recovers it.
Controlled instruction comparisons do not establish live gameplay agreement.
Continue from the existing
extraction and saved analysis project.
