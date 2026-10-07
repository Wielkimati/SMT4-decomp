"""Build the recovered ARM unit and compare it to the pinned original in Ghidra."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess

from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from tbcr import read
from tbcr_access_cases import ORIGINALS, write_helper_cases
from unsigned_quotient_cases import write_division_cases
from nkm_pair_cases import write_pair_cases

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic_table(words: list[int], *, entry_size: int = 4,
                    declared_size: int | None = None) -> bytes:
    """Three sections with deliberately distinct decoys in sections 0 and 1."""
    sections = []
    for values in ([0xBEEF3210], [0xCAFE7654], words):
        payload = struct.pack(f"<{len(values)}I", *values)
        size = len(payload) if declared_size is None or values is not words else declared_size
        stride = entry_size if values is words else 4
        sections.append(struct.pack("<4sIII", b"TBL1", size, stride, 0xA5A51234) + payload)
    offsets = [0, len(sections[0]), len(sections[0]) + len(sections[1])]
    return struct.pack("<4sII3I", b"TBCR", 24, 3, *offsets) + b"".join(sections)


def write_cases(output: Path, table: Path) -> dict:
    container = read(table)
    section = container.sections[2]
    if section.entry_size != 4 or section.entry_count != 1201 or section.remainder_size:
        raise ValueError("Unexpected reference section 2 layout")
    fixtures = [("reference", container.raw, section.payload.tobytes(), 1201)]
    for name, words, stride, size in [
        ("one_entry", [0xABCD8123], 4, None),
        ("halfwords", [0xDEADFFFF, 0xBEEF8000, 0xFFFF0000, 0x12340102], 4, None),
        ("floor_count", [0xCAFE1234, 0xBEEF5678], 4, 7),
        ("zero_count_readable", [0xF00DABCD], 4, 0),
        ("zero_divisor_readable", [0xBEEF4321], 0, None),
        ("fixed_stride", [0x1234AA55, 0xABCD55AA, 0xFFFF0123, 0xFFFF4567], 8, None),
    ]:
        raw = synthetic_table(words, entry_size=stride, declared_size=size)
        count = (len(words) * 4 if size is None else size) // stride if stride else 0
        fixtures.append((name, raw, struct.pack(f"<{len(words)}I", *words), count))
    rng = random.Random(0x2883E8)
    words = [rng.getrandbits(32) for _ in range(257)]
    fixtures.append(("random_halfwords", synthetic_table(words),
                     struct.pack("<257I", *words), len(words)))
    rows = ["fixture\tindex\texpected"]
    counts = {}
    for name, raw, payload, count in fixtures:
        (output / f"{name}.bin").write_bytes(raw)
        indices = list(range(count)) + [count, count + 1, 0x7FFFFFFF, 0x80000000,
                                       0xFFFFFFFE, 0xFFFFFFFF]
        indices += [rng.getrandbits(32) for _ in range(32)]
        indices = list(dict.fromkeys(indices))
        for index in indices:
            offset = 4 * index if index < count else 0
            expected = struct.unpack_from("<H", payload, offset)[0]
            rows.append(f"{name}\t{index}\t{expected}")
        counts[name] = len(indices)
    (output / "cases.tsv").write_text("\n".join(rows) + "\n", encoding="ascii")
    return counts


def run(command: list[str], output: Path, label: str) -> str:
    (output / f"{label}-command.json").write_text(json.dumps(command, indent=2) + "\n")
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=600)
    (output / f"{label}.log").write_text(result.stdout, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"{label} failed; inspect {output / (label + '.log')}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--recover-helpers", action="store_true",
                        help="Build and compare the four recovered table helpers too")
    parser.add_argument("--recover-quotient", action="store_true",
                        help="Also rebuild unsigned quotient; implies --recover-helpers")
    parser.add_argument("--recover-pairs", action="store_true",
                        help="Also recover section-3 consumer; implies --recover-quotient")
    args = parser.parse_args()
    args.recover_quotient |= args.recover_pairs
    args.recover_helpers |= args.recover_quotient
    output = local_path(args.output)
    project = local_path(args.project_dir)
    if output.exists():
        raise FileExistsError("Choose a new output directory under local/")
    if not (project / "SMT4-EU.gpr").is_file():
        raise FileNotFoundError("Saved SMT4-EU Ghidra project is required")
    code = ROOT / "local/reference-eu/base/0000/exefs/code.bin"
    table = ROOT / "local/reference-eu/base/0000/romfs/battle/NKMSortIndex.tbb"
    check_hash(code, CODE_HASH)
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    check_hash(table, pins["nkm_sort_index_sha256"])
    tool_dir = ROOT / pins["directory"] / "bin"
    for name, expected in pins["executables"].items():
        check_hash(tool_dir / name, expected)
    java = java_command()
    output.mkdir(parents=True)
    fixtures = output / "fixtures"
    fixtures.mkdir()
    counts = write_cases(fixtures, table)
    helper_counts = write_helper_cases(fixtures) if args.recover_helpers else {}
    division_count = write_division_cases(fixtures)
    pair_counts = write_pair_cases(fixtures, table) if args.recover_pairs else {}
    elf = output / "nkm-sort-index.elf"
    binary = output / "nkm-sort-index.bin"
    source = ROOT / "src/nkm_sort_index.c"
    gcc = str(tool_dir / "arm-none-eabi-gcc.exe")
    flags = ["-std=c11", "-O2", "-march=armv6", "-marm", "-mfloat-abi=soft",
             "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
             "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib"]
    sources = [source]
    if args.recover_pairs:
        sources.append(ROOT / "src/nkm_section3.c")
    if args.recover_helpers:
        sources.append(ROOT / "src/tbcr_access.c")
        bindings = ["-Wl,--defsym,smt4_table_resource_registry=0x49382c"]
        if args.recover_quotient:
            sources.append(ROOT / "src/unsigned_quotient.c")
        else:
            bindings.append("-Wl,--defsym,smt4_unsigned_quotient=0x2c6c64")
    else:
        bindings = ["-Wl,--defsym,resource_select_tbcr_section=0x2c0f18",
                    "-Wl,--defsym,tbl1_payload=0x2c0ef0",
                    "-Wl,--defsym,tbl1_entry_count=0x2c0ea0"]
    run([gcc, *flags, *map(str, sources), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=nkm_sort_index_lookup", "-Wl,--build-id=none",
         *bindings, "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if "00600000 T nkm_sort_index_lookup" not in symbols or " U " in symbols:
        raise RuntimeError("Unexpected entry point or unresolved symbols")
    if args.recover_helpers:
        rebuilt_symbols = {row.split()[2]: int(row.split()[0], 16)
                           for row in symbols.splitlines() if len(row.split()) == 3
                           and row.split()[1] == "T"}
        entries = ["helper\toriginal\trebuilt"]
        for name, address in ORIGINALS.items():
            rebuilt = rebuilt_symbols[name]
            if not 0x600000 <= rebuilt < 0x600000 + binary.stat().st_size:
                raise RuntimeError(f"Helper not rebuilt: {name}")
            entries.append(f"{name}\t{address}\t{rebuilt}")
        (output / "helper-entries.tsv").write_text("\n".join(entries) + "\n", encoding="ascii")
        if args.recover_quotient:
            quotient = rebuilt_symbols["smt4_unsigned_quotient"]
            if not 0x600000 <= quotient < 0x600000 + binary.stat().st_size:
                raise RuntimeError("Quotient not rebuilt")
            (output / "quotient-entry.txt").write_text(str(quotient), encoding="ascii")
        if args.recover_pairs:
            pair_entry = rebuilt_symbols["nkm_section3_pair_lookup"]
            if not 0x600000 <= pair_entry < 0x600000 + binary.stat().st_size:
                raise RuntimeError("Section-3 consumer not rebuilt")
            (output / "pair-entry.txt").write_text(str(pair_entry), encoding="ascii")
    command = [*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareNkmLookup.java",
               str(output), "-log", str(output / "ghidra.log")]
    log = run(command, output, "comparison")
    report = output / "comparison.json"
    if "SMT4_NKM_COMPARE_OK" not in log or not report.is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads(report.read_text())
    if comparison["lookup_cases"] != sum(counts.values()):
        raise RuntimeError("Incomplete case coverage")
    if comparison["helper_cases"] != sum(helper_counts.values()):
        raise RuntimeError("Incomplete helper coverage")
    if comparison["division_cases"] != division_count:
        raise RuntimeError("Incomplete quotient coverage")
    if comparison["recovered_quotient"] != args.recover_quotient:
        raise RuntimeError("Unexpected quotient comparison mode")
    if comparison["pair_cases"] != sum(pair_counts.values()):
        raise RuntimeError("Incomplete section-3 comparison coverage")
    manifest = {"reference_sha256": CODE_HASH, "table_sha256": digest(table),
                "source_sha256": digest(source),
                "header_sha256": digest(ROOT / "src/nkm_sort_index.h"),
                "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                "fixtures": counts, "comparison": comparison,
                "helper_cases": helper_counts,
                "pair_cases": pair_counts,
                "method": "Ghidra ARM p-code execution; " + (
                    "recovered table helpers and quotient" if args.recover_quotient else
                    "recovered table helpers, original quotient" if args.recover_helpers
                    else "original helpers retained"),
                "rebuilt_path_original_code_required": not args.recover_quotient,
                "live_gameplay_validation": False, "binary_matching": False}
    manifest["source_files_sha256"] = {str(p.relative_to(ROOT)): digest(p) for p in
                                      [*sources, ROOT / "src/nkm_sort_index.h", ROOT / "src/tbcr_access.h",
                                       ROOT / "src/unsigned_quotient.h",
                                       ROOT / "src/resource_lifecycle.h"]}
    manifest["validation_files_sha256"] = {
        name: digest(ROOT / name) for name in (
            "tools/check_nkm_lookup.py", "tools/ghidra/CompareNkmLookup.java",
            "tools/tbcr_access_cases.py",
            "tools/unsigned_quotient_cases.py",
            "tools/nkm_pair_cases.py",
            "config/recovery-tools.json", "config/analysis-tools.json")}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
