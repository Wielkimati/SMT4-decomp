"""Bounded table-unit ABI research; no recovered source or runtime replacement."""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from check_nkm_lookup import digest, run
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from unsigned_quotient_cases import division_cases


def validate_results(path: Path, abi: dict, corpus=None) -> dict:
    """Independent completeness/value checks on the emitted machine observations."""
    if corpus is None:
        corpus = division_cases()
    expected = {(kind, profile, 0, a, b) for a, b, _ in corpus
                for kind in range(4) for profile in range(2)}
    expected.update((kind, profile, header, 17, 0 if header == 0 else 5)
                    for kind in (2, 3) for profile in range(2) for header in range(3))
    seen = set()
    r1_differences = 0
    with path.open(newline="", encoding="ascii") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            values = {key: int(value) for key, value in row.items()}
            key = tuple(values[n] for n in ("kind", "profile", "header", "dividend", "divisor"))
            if key not in expected or key in seen:
                raise ValueError("Unexpected or duplicate ABI observation")
            seen.add(key)
            kind, _, header, a, b = key
            result = 0 if header or not b else a // b
            if values["r0"] != result:
                raise ValueError("Incorrect quotient observation")
            if kind == 0 and values["r1"] != a % b:
                raise ValueError("Incorrect original remainder observation")
            if kind == 1:
                if values["r1"] != b:
                    raise ValueError("Changed GCC artifact r1 observation")
                r1_differences += values["r1"] != a % b
            if values["stack_depth"] != (8 if kind % 2 and header == 0 and b else 0):
                raise ValueError("Changed stack-depth observation")
    if seen != expected or abi["calls"] != len(expected):
        raise ValueError("Incomplete ABI observations")
    return {"independently_checked_rows": len(seen),
            "direct_original_rebuilt_r1_differences": r1_differences}


def fingerprint(code: bytes) -> dict:
    """Record a narrow, reproducible ASCII-marker search, not compiler detection."""
    patterns = {
        "compiler": r"compiler|ARM Ltd|ARM C|GCC:|RVCT|armcc|Metrowerks|Microsoft",
        "runtime_names": r"__aeabi|__rt_",
        "middleware": r"Nintendo|NW4C|CTR SDK|SDK[-_ ]",
    }
    hits = {key: [] for key in patterns}
    for match in re.finditer(rb"[\x20-\x7e]{5,}", code):
        value = match.group().decode("ascii")
        for key, pattern in patterns.items():
            if re.search(pattern, value, re.I):
                hits[key].append({"file_offset": match.start(),
                                  "virtual_address": match.start() + 0x100000,
                                  "text": value})
    return {"patterns": patterns, "ascii_minimum_length": 5, "hits": hits,
            "elf_header_present": code.startswith(b"\x7fELF"),
            "compiler_identity": "unresolved",
            "limits": "ASCII markers only; absence is not evidence of compiler absence"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--unit", help="Reuse an unchanged completed --recover-pairs unit under local/")
    args = parser.parse_args()
    output = local_path(args.output)
    if output.exists():
        raise FileExistsError("Choose a fresh output directory under local/")
    code = ROOT / "local/reference-eu/base/0000/exefs/code.bin"
    check_hash(code, CODE_HASH)
    output.mkdir(parents=True)
    (output / "fingerprint.json").write_text(json.dumps(fingerprint(code.read_bytes()), indent=2) + "\n")
    # Reuse the unchanged build and its complete consumer regression. This job
    # finishes before the ABI job opens the same authoritative Ghidra project.
    unit = local_path(args.unit) if args.unit else output / "unit"
    if args.unit:
        previous = json.loads((unit / "COMPLETE.json").read_text())
        if previous["reference_sha256"] != CODE_HASH or previous["comparison"]["pair_cases"] != 236:
            raise ValueError("Expected the complete pinned --recover-pairs comparison")
        check_hash(unit / "nkm-sort-index.bin", previous["binary_sha256"])
        for key in ("source_files_sha256", "validation_files_sha256"):
            for name, sha256 in previous[key].items():
                check_hash(ROOT / name, sha256)
        (output / "reused-unit.json").write_text(json.dumps({
            "path": str(unit.relative_to(ROOT)), "complete_sha256": digest(unit / "COMPLETE.json"),
            "source_validation_and_binary_identities_checked": True}, indent=2) + "\n")
    else:
        run([sys.executable, str(ROOT / "tools/check_nkm_lookup.py"), "--recover-pairs",
             "--output", str(unit)], output, "unit-regression")
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    tool_dir = ROOT / pins["directory"] / "bin"
    readelf = tool_dir / "arm-none-eabi-readelf.exe"
    run([str(readelf), "-h", "-A", str(unit / "nkm-sort-index.elf")], output, "elf-attributes")
    objdump = tool_dir / "arm-none-eabi-objdump.exe"
    for name, start, end in [("count", 0x2c0ea0, 0x2c0ef0),
                             ("worker", 0x2c61b0, 0x2c62d4),
                             ("quotient", 0x2c6c64, 0x2c6c94)]:
        run([str(objdump), "-D", "-b", "binary", "-m", "arm", "--adjust-vma=0x100000",
             f"--start-address={start}", f"--stop-address={end}", str(code)], output, name + "-objdump")
    log = run([*java_command(), "ghidra.app.util.headless.AnalyzeHeadless",
               str(ROOT / "local/ghidra/smt4-eu"), "SMT4-EU", "-process", "code.bin",
               "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareTableAbi.java", str(output), str(unit),
               "-log", str(output / "ghidra.log")], output, "abi")
    if "SMT4_TABLE_ABI_OK" not in log or not (output / "abi.json").is_file():
        raise RuntimeError("ABI comparison failed; inspect abi.log")
    abi = json.loads((output / "abi.json").read_text())
    observations = validate_results(output / "abi-results.tsv", abi)
    unit_result = json.loads((unit / "COMPLETE.json").read_text())
    check_hash(code, CODE_HASH)
    manifest = {"status": "validated", "scope": "Bounded table quotient/count ABI research",
                "reference_sha256": CODE_HASH, "inputs_unchanged": True,
                "abi": abi, "observations": observations,
                "unit_comparison": unit_result["comparison"],
                "readelf_sha256": digest(readelf),
                "files_sha256": {str(p.relative_to(ROOT)): digest(p) for p in [
                    ROOT / "tools/check_table_abi.py", ROOT / "tools/ghidra/CompareTableAbi.java",
                    output / "abi.json", output / "abi-results.tsv", output / "abi-listing.txt",
                    output / "fingerprint.json", output / "elf-attributes.log",
                    unit / "COMPLETE.json", unit / "nkm-sort-index.bin"]},
                "new_recovered_entry_points": 0, "compiler_identity": "unresolved",
                "full_abi": False, "binary_matching": False, "live_validation": False}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": manifest["status"], "abi": abi}))


if __name__ == "__main__":
    main()
