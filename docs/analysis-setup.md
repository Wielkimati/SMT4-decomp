# Ghidra analysis setup

Started 2026-10-06, G1 tasks A01/A02. This setup uses the completed EU extraction;
it does not repeat CIA intake. This document owns setup and import reproduction instructions.

## Pinned tools

| Tool | Selected build | Repository-relative installation |
| --- | --- | --- |
| Ghidra | 12.1.4 PUBLIC, 20260921 | `local/tools/ghidra_12.1.4_PUBLIC/` |
| JDK | Eclipse Temurin 21.0.12.1+1-LTS, Windows x64 HotSpot | `local/tools/jdk-21.0.12.1+1/` |
| Python | Existing 3.10.5 | `python` on PATH |
| ARM GDB | xPack 15.2.1-1.1 distribution, GDB 16.3.90.20250906-git | `local/tools/xpack-arm-none-eabi-gcc-15.2.1-1.1/bin/arm-none-eabi-gdb.exe` |

Both downloaded ZIPs matched their upstream SHA-256 values. URLs, archive hashes,
and local launcher fingerprints are in [analysis-tools.json](../config/analysis-tools.json).
Archives remain in `local/tools/downloads/`. Ghidra is Apache-2.0 with bundled
component notices; Temurin includes GPLv2 with Classpath Exception notices. Their
licenses remain in the local distributions; no external loader code was copied.

The [12.1.4 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build)
and its [Getting Started guide](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md)
specify a 64-bit JDK 21. The existing PATH Java 8 is unsuitable. Our wrapper invokes
the selected JDK directly, using the release's `launch.properties` VM options and
the same `ghidra.Ghidra` launcher class as `support/launch.bat`. It leaves system
Java/PATH unchanged and places Ghidra settings, caches, and temporary files under
`local/ghidra-state/`.

### Loader choice

Reviewed the [Raikaru fork](https://github.com/Raikaru/ghidra-ctr-loader), which
identifies [Martmists-GH](https://github.com/Martmists-GH/ghidra-ctr-loader) as its
upstream and preserves BSD-3-Clause terms. Its documentation advertises ExHeader
mapping and BSS handling, but CIA import selects the first NCCH. Its Gradle build
requires a Ghidra installation and Kotlin dependencies. Neither fork was built,
installed, or compatibility-tested here.

For this already-extracted reference, use Ghidra's built-in BinaryLoader plus the
small project-owned `ImportSmt4.java` script. This makes the exact file-to-address
mapping explicit and avoids redoing container selection/decompression. This is a
deliberate bounded import, not a claim that the third-party loader is incompatible.
The script accepts only the pinned expanded executable.

## Repeat the import

If tools are absent, download the two official ZIP URLs in the config, verify
their SHA-256 values with `Get-FileHash -Algorithm SHA256`, then extract into
`local/tools/` without overwriting an existing installation. The archived top-level
directory names must match the config. Python 3.10+ and these distributions suffice;
no pip packages or Ghidra extensions are required.

From `SMT4-decomp/`:

```powershell
python tools/ghidra_reference.py
```

The default destination is `local/ghidra/smt4-eu/SMT4-EU.gpr`. An existing destination
is refused, including an incomplete earlier attempt. For a repeat run:

```powershell
python tools/ghidra_reference.py --project-dir local/ghidra/smt4-eu-repeat
```

The wrapper verifies the expanded `.code`, ExHeader, JDK executable, and Ghidra
launcher hashes. The import uses `ARM:LE:32:v6`, compiler spec `default`, base
`0x00100000`; its pre-script maps segments before automatic analysis. The `default`
ABI is provisional and does not identify the original compiler. Four analysis
workers, 2 GiB Java heap, and a 600-second per-file analysis timeout are selected.
The original dumps and extraction are read only.

Keep all generated files local. The destination contains the project database,
exact launcher argument list (`command.json`), console/analysis/script logs, and
`exports/` with the memory map, user-defined symbols, function inventory including TMode, startup listing,
and selected decompiler output. `exports/COMPLETE.txt` records a successful mapped-byte
hash check. The wrapper also requires the pre-script success marker and saved-project
confirmation; inspect the logs if it reports a failure.

The export re-reads all `0x377000` file-backed bytes through Ghidra's memory API and
checks the original expanded-code SHA-256, all nine startup transfer targets/modes,
and the BSS-bound literals. Ghidra warnings, function discovery,
and generated pseudocode are analysis observations, not verified recovered source.

The 2026-10-06 saved-project review ran the strengthened exporter in read-only mode
into `local/ghidra/smt4-eu/exports-reviewed/`; its checks all passed. The initial
`exports/` remains as the first-pass artifact. `review-command.json` and review logs
preserve the exact invocation. Nine synthetic tooling tests passed using
`python -m unittest discover -s tests -v` (no game data required).

## Open the project

Double-click `Open Ghidra.cmd` in the repository root to open the saved project
with the pinned JDK. Alternatively, run:

```powershell
python tools/ghidra_reference.py --open
```

On the first GUI launch, Ghidra shows its user agreement before opening the
project. The user accepted that agreement on 2026-10-06. A fresh installation may
show it again. Headless import and saved-project verification completed independently.

Open `code.bin` in the project window. In CodeBrowser, press **G** and enter
`00100000` for startup or `00100024` for the BSS clear loop. The Listing shows the
instructions and the Decompiler shows generated pseudocode. Use **Window > Memory
Map** to inspect the segment boundaries. Labels are project descriptions, not
recovered original symbol names.

For another destination, append the same `--project-dir` used to create it. Close
the GUI project before headless processing that project. A fresh import does not
include subsequent manual GUI edits; export meaningful annotations into source
metadata and scripts as work proceeds.

## Evidence and remaining checks

No application data structures
or original function prototypes were claimed by the initial startup import.

The ARM debugger now passes startup breakpoint/read/continue/detach checks,
including BSS bounds and ARM/Thumb transitions. See
[runtime-reference.md](runtime-reference.md) for its pin, workarounds, and repeatable
checker. The user confirms saves load into gameplay with working controls.
G1 still needs A03's reproducible checkpoint/current configuration and isolation
evidence, plus final review.
