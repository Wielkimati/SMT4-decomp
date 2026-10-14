"""Build/compare synchronous resource loading with modeled create/wait/string dependencies."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

NAMES = ["smt4_resource_load_sync", "smt4_resource_load", "smt4_file_mark_cleanup",
         "smt4_file_set_flags", "smt4_file_set_parameter", "smt4_file_failed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--recover-prefix", action="store_true", help="Execute the recovered prefix and existing length source")
    parser.add_argument("--mutant", choices=("prefix-limit", "prefix-return", "prefix-order"))
    args = parser.parse_args()
    if args.mutant and not args.recover_prefix:
        parser.error("--mutant requires --recover-prefix")
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
    prefix_source = ROOT / "src/resource_path_prefix.c"
    if args.mutant:
        source = prefix_source.read_text()
        old, new = {
            "prefix-limit": ("length > 8)\n        length = 8", "length > 9)\n        length = 9"),
            "prefix-return": ("return 1;", "return UINT32_MAX;"),
            "prefix-order": ("    uint32_t length =", "    if (*(const volatile unsigned char *)(uintptr_t)path == ':') return 1;\n    uint32_t length ="),
        }[args.mutant]
        if source.count(old) != 1:
            raise RuntimeError("Mutant anchor changed")
        prefix_source = output / "mutant-prefix.c"
        prefix_source.write_text(source.replace(old, new))
    prefix_build = ([str(prefix_source), str(ROOT / "src/resource_worker_service_acquire.c"),
                     "-I" + str(ROOT / "src"), "-ffunction-sections", "-Wl,--gc-sections",
                     *("-Wl,--undefined=" + name for name in NAMES)]
                    if args.recover_prefix else ["-Wl,--defsym,smt4_resource_path_has_prefix=0x2b0674"])
    elf, binary = output / "resource-sync.elf", output / "resource-sync.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(ROOT / "src/resource_sync.c"), str(ROOT / "src/resource_descriptor.c"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_resource_load_sync", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_path_mode=0x465040",
         "-Wl,--defsym,smt4_resource_path_format=0x409740",
         "-Wl,--defsym,smt4_resource_clear=0x2c3b98",
         *prefix_build,
         "-Wl,--defsym,smt4_resource_format=0x2be850",
         "-Wl,--defsym,smt4_file_create=0x2b0494",
         "-Wl,--defsym,smt4_file_wait=0x1181b0",
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    # Independent disassembler evidence for every recovered original entry.
    for start, stop in ((0x2c5e90, 0x2c5fa4), (0x2c3344, 0x2c334c),
                        (0x2b0468, 0x2b0494), (0x14e634, 0x14e648),
                        (0x14e744, 0x14e760)):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start}", f"--stop-address={stop}",
             str(ROOT / "local/reference-eu/base/0000/exefs/code.bin")],
            output, f"original-{start:08x}-disassembly")
    if args.recover_prefix:
        for start, stop in ((0x2b0674, 0x2b0700), (0x2c32e4, 0x2c3344)):
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
    if args.recover_prefix:
        (output / "prefix-entry.txt").write_text(str(entries["smt4_resource_path_has_prefix"]) + "\n")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceSync.java",
               str(output), *(["prefix"] if args.recover_prefix else []), "-log", str(output / "ghidra.log")], output, "comparison")
    if "SMT4_SYNC_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if comparison["sync_cases"] != 2520 or comparison["helper_cases"] != 768 or comparison["original_instruction_addresses"] != (150 if args.recover_prefix else 92):
        raise RuntimeError("Incomplete comparison corpus")
    if args.recover_prefix:
        prefix = json.loads((output / "prefix-comparison.json").read_text())
        if (not prefix["ordered_reads_checked"] or prefix["direct_pairs"] != 440
                or prefix["integrated_calls_both_paths"] != 1680 or prefix["new_and_reused_sites"] != 58):
            raise RuntimeError("Missing concrete prefix evidence")
    manifest = {"path_prefix_recovered": args.recover_prefix,
                "length_source_reused": args.recover_prefix,
                "mutant": args.mutant, "reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "synchronous_orchestration_implemented": True, "file_io_allocation_implemented": False,
                "method": "Original/rebuilt ARM execution; create/wait/clear/prefix/format explicitly modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_sync.c", "src/resource_sync.h", "src/resource_descriptor.c",
                    "tools/check_resource_sync.py", "tools/ghidra/CompareResourceSync.java",
                    "tools/ghidra/CompareResourceLifecycle.java",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    if args.recover_prefix:
        manifest["prefix_comparison"] = prefix
        manifest["method"] = "Original/rebuilt ARM execution; create/wait/clear/format modeled; prefix and length execute recovered source (UQSUB8 host instruction support)"
        for name in ("src/resource_path_prefix.c", "src/resource_worker_service_acquire.c",
                     "src/resource_worker_service_acquire.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.mutant:
        raise RuntimeError("Mutant unexpectedly passed")
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
