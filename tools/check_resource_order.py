"""Compare consumed index/remainder and bulk loading with only file I/O modeled."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run
from resource_order_cases import write_cases

NAMES = ["resource_load_bulk", "smt4_resource_order_index", "smt4_resource_order_remainder"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    args = parser.parse_args()
    output, project = local_path(args.output), local_path(args.project_dir)
    if output.exists():
        raise FileExistsError("Choose new output under local/")
    if not (project / "SMT4-EU.gpr").is_file():
        raise FileNotFoundError("Saved EU project required")
    code = ROOT / "local/reference-eu/base/0000/exefs/code.bin"
    check_hash(code, CODE_HASH)
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    tool_dir = ROOT / pins["directory"] / "bin"
    for name, expected in pins["executables"].items():
        check_hash(tool_dir / name, expected)
    java = java_command()
    output.mkdir(parents=True)
    remainder_count, index_count = write_cases(output)
    elf, binary = output / "resource-order.elf", output / "resource-order.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         *[str(ROOT / name) for name in ("src/resource_bulk.c", "src/resource_order.c", "src/resource_order_remainder.c")],
         "-Wl,-Ttext=0x600000", "-Wl,--entry=resource_load_bulk", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_table_resource_registry=0x49382c",
         "-Wl,--defsym,smt4_resource_load=0x2c3344",
         "-Wl,--defsym,smt4_resource_order_state=0x4651c0", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x2c61b0", "--stop-address=0x2c62f0",
         str(code)], output, "original-remainder-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in NAMES))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceOrder.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if "SMT4_ORDER_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["remainder_cases"], comparison["index_cases"], comparison["bulk_cases"]) != (remainder_count, index_count, 2520):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "backend_implemented": False,
                "index_implemented": True, "remainder_abi": "Original r1 adapted to C r0; consumed positive domain only",
                "method": "Original/rebuilt ARM execution; only synchronous file backend intercepted",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_bulk.c", "src/resource_lifecycle.h", "src/resource_order.c",
                    "src/resource_order.h", "src/resource_order_remainder.c",
                    "tools/check_resource_order.py", "tools/resource_order_cases.py",
                    "tools/ghidra/CompareResourceOrder.java", "tools/ghidra/CompareResourceBulk.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
