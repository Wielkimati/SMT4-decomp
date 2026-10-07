"""Validate startup through a locally running, paused-at-entry Azahar GDB stub."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from ghidra_reference import ROOT, CODE_HASH, check_hash, local_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="Fresh output directory under local/")
    args = parser.parse_args()
    output = local_path(args.output)
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output}")
    pin = json.loads((ROOT / "config/analysis-tools.json").read_text())["gdb"]
    gdb = ROOT / pin["directory"] / "bin/arm-none-eabi-gdb.exe"
    check_hash(gdb, pin["executable_sha256"])
    reference_path = ROOT / "local/reference-eu/base/0000/exefs/code.bin"
    check_hash(reference_path, CODE_HASH)
    reference = reference_path.read_bytes()
    command = [str(gdb), "--nx", "--quiet", "--batch", "-x",
               str(ROOT / "tools/gdb/check-startup.gdb")]
    output.mkdir(parents=True)
    (output / "command.json").write_text(json.dumps(command, indent=2) + "\n")
    print(f"Connecting to paused Azahar; transcript: {output / 'gdb-session.txt'}", flush=True)
    with (output / "gdb-session.txt").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=output, stdout=log, stderr=subprocess.STDOUT)
    transcript = (output / "gdb-session.txt").read_text(encoding="utf-8", errors="replace")
    if result.returncode or "SMT4_STARTUP_CHECK_COMPLETE" not in transcript:
        raise RuntimeError("Startup check failed; inspect gdb-session.txt. No COMPLETE.json written.")
    comparisons = {"entry.bin": (0, 0x1000), "startup-restored.bin": (0, 0x48),
                   "thumb-restored.bin": (0xcb8, 0xcdc),
                   "game-entry-restored.bin": (0x1308, 0x1318)}
    for name, (start, end) in comparisons.items():
        if (output / name).read_bytes() != reference[start:end]:
            raise ValueError(f"Runtime/reference bytes differ: {name}")
    after = (output / "bss-after.bin").read_bytes()
    before = (output / "bss-before.bin").read_bytes()
    if len(after) != 0x78e34 or len(before) != 0x78e34 or any(after):
        raise ValueError("BSS capture length or zero-state mismatch")
    manifest = {
        "expanded_code_sha256": CODE_HASH,
        "checkpoints": ["entry", "clear_entry", "clear_begin", "clear_end", "thumb_entry", "game_entry"],
        "runtime_byte_comparisons": list(comparisons),
        "bss_before_nonzero_bytes": sum(x != 0 for x in before),
        "bss_after_nonzero_bytes": sum(x != 0 for x in after),
        "detached_and_resumed": True,
        "menu_gameplay_save_validation": "Not established by this script",
        "captures": {p.name: {"bytes": p.stat().st_size,
                              "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in sorted(output.glob("*.bin"))},
    }
    with (output / "COMPLETE.json").open("x", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print("Startup breakpoints, modes, BSS, and restored instruction bytes verified; detached/resumed.")


if __name__ == "__main__":
    main()
