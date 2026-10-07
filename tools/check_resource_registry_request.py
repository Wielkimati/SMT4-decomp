"""Compare registry async submission/constructor/completion with modeled worker dispatch."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

NAMES = ["resource_request_if_dynamic", "resource_load_complete",
         "smt4_resource_request_complete", "smt4_file_create"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--recover-release", action="store_true",
                        help="Execute release routing through modeled allocator dependencies")
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
    elf, binary = output / "registry-request.elf", output / "registry-request.bin"
    sources = ["src/resource_lifecycle.c", "src/resource_request.c",
               "src/resource_create.c", "src/resource_descriptor.c"]
    definitions = {
        "smt4_table_resource_registry": 0x49382c,
        "smt4_resource_path_mode": 0x465040, "smt4_resource_path_format": 0x409740,
        "smt4_file_clear": 0x2c4b84, "smt4_file_allocate": 0x2c4bd8,
        "smt4_resource_release": 0x2c43b4, "smt4_resource_path_has_prefix": 0x2b0674,
        "smt4_resource_format": 0x2be850, "smt4_file_sync_handle": 0x465010,
        "smt4_file_list_head": 0x46500c, "smt4_file_acquire": 0x2c4350,
        "smt4_file_release": 0x2c54a4, "smt4_file_check_result": 0x2c54bc,
        "smt4_file_path_length": 0x2c32e4, "smt4_file_path_copy": 0x2bf8c0,
        "smt4_file_path_format": 0x2b066c,
    }
    names = list(NAMES)
    if args.recover_release:
        sources.append("src/resource_release.c")
        names.append("smt4_resource_release")
        del definitions["smt4_resource_release"]
        definitions.update({"smt4_resource_allocator_state": 0x465120,
                            "smt4_resource_heap_acquire": 0x2c3afc,
                            "smt4_resource_heap_release": 0x2c3a78,
                            "smt4_resource_release_convert": 0x1245f0,
                            "smt4_resource_heap_free": 0x1244e8})
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections",
         "-Wall", "-Wextra", "-Werror", "-nostdlib", *[str(ROOT / s) for s in sources],
         "-Wl,-Ttext=0x600000", "-Wl,--entry=resource_request_if_dynamic",
         "-Wl,--gc-sections", "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}=0x{value:x}" for name, value in definitions.items()],
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for start, stop in ((0x33c844, 0x33c898), (0x19f990, 0x19f99c),
                        (0x2ae72c, 0x2ae878), (0x2b6820, 0x2b6840), (0x155b30, 0x155bd8),
                        (0x2b0468, 0x2b0630), (0x14e634, 0x14e648), (0x14e744, 0x14e760)):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start}", f"--stop-address={stop}",
             str(ROOT / "local/reference-eu/base/0000/exefs/code.bin")], output, f"original-{start:08x}")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if args.recover_release:
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", "--start-address=0x2c43b4", "--stop-address=0x2c4424",
             str(ROOT / "local/reference-eu/base/0000/exefs/code.bin")], output, "original-release")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in names))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceRegistryRequest.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if "SMT4_REGISTRY_REQUEST_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    expected_counts = {"scenarios": 1163, "submissions_both_paths": 1484,
                       "completions_both_paths": 1484, "skipped_calls_both_paths": 1580,
                       "original_instruction_addresses": 266}
    if args.recover_release:
        expected_counts.update({"scenarios": 1271, "submissions_both_paths": 1700,
                                "completions_both_paths": 1700,
                                "original_instruction_addresses": 294,
                                "release_executions_both_paths": 1700})
    if any(comparison[key] != value for key, value in expected_counts.items()):
        raise RuntimeError("Incomplete comparison corpus")
    files = sources + ["src/resource_lifecycle.h", "src/resource_request.h", "src/resource_create.h",
                       "src/resource_sync.h", "tools/check_resource_registry_request.py",
                       "tools/ghidra/CompareResourceRegistryRequest.java",
                       "tools/ghidra/CompareResourceSync.java", "tools/ghidra/CompareResourceLifecycle.java",
                       "tools/ghidra/CompareResourceCreate.java", "config/recovery-tools.json", "config/analysis-tools.json"]
    files += ["tools/check_nkm_lookup.py", "tools/ghidra_reference.py"]
    if args.recover_release:
        files.append("src/resource_release.h")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "worker_dispatch_implemented": False,
                "release_routing_implemented": args.recover_release,
                "original_binary_helpers_required": False,
                "method": ("Original/rebuilt registry request, constructor, completion and release routing; allocation/synchronization/strings/dispatch/metadata/free modeled"
                           if args.recover_release else
                           "Original/rebuilt registry request, constructor and completion; allocation/synchronization/strings/dispatch/release modeled"),
                "files_sha256": {name: digest(ROOT / name) for name in files}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
