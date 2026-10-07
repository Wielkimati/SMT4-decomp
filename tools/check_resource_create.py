"""Build/compare descriptor creation with modeled allocation/synchronization/string dependencies."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

NAMES = ["smt4_file_create"]


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
    check_hash(ROOT / "local/reference-eu/base/0000/exefs/code.bin", CODE_HASH)
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    tool_dir = ROOT / pins["directory"] / "bin"
    for name, expected in pins["executables"].items():
        check_hash(tool_dir / name, expected)
    java = java_command()
    output.mkdir(parents=True)
    elf, binary = output / "resource-create.elf", output / "resource-create.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(ROOT / "src/resource_create.c"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_file_create", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_file_sync_handle=0x465010",
         "-Wl,--defsym,smt4_file_list_head=0x46500c",
         "-Wl,--defsym,smt4_file_path_format=0x2b066c",
         "-Wl,--defsym,smt4_file_acquire=0x2c4350",
         "-Wl,--defsym,smt4_file_release=0x2c54a4",
         "-Wl,--defsym,smt4_file_check_result=0x2c54bc",
         "-Wl,--defsym,smt4_file_allocate=0x2c4bd8",
         "-Wl,--defsym,smt4_file_clear=0x2c4b84",
         "-Wl,--defsym,smt4_file_path_length=0x2c32e4",
         "-Wl,--defsym,smt4_file_path_copy=0x2bf8c0",
         "-Wl,--defsym,smt4_resource_format=0x2be850",
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    # Independent disassembler evidence for every recovered original entry.
    for start, stop in ((0x2b0494, 0x2b0630), (0x2c4350, 0x2c4374), (0x2c54a4, 0x2c552c)):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start}", f"--stop-address={stop}",
             str(ROOT / "local/reference-eu/base/0000/exefs/code.bin")],
            output, f"original-{start:08x}-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in NAMES))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceCreate.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if "SMT4_CREATE_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if comparison["create_cases"] != 10080 or comparison["original_instruction_addresses"] != 103:
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "descriptor_creation_implemented": True,
                "file_io_allocation_implemented": False,
                "method": "Original/rebuilt ARM execution; allocation/synchronization/strings modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_create.c", "src/resource_create.h", "src/resource_sync.h",
                    "tools/check_resource_create.py", "tools/ghidra/CompareResourceCreate.java",
                    "tools/ghidra/CompareResourceLifecycle.java",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
