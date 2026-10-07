"""Build/compare EU heap selection without intercepted dependencies."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "exclusive-start": ("raw >= start", "raw > start"),
    "exclusive-end": ("raw <= (uint32_t)", "raw < (uint32_t)"),
    "wide-end": ("(uint32_t)(start + smt4_resource_allocator_state[11 + index])", "((uint64_t)start + smt4_resource_allocator_state[11 + index])"),
    "signed-start": ("raw >= start", "(int32_t)raw >= (int32_t)start"),
    "reverse-priority": ("uint32_t index = 0; index < 4u; ++index", "uint32_t index = 3; index < 4u; --index"),
    "wrong-fallback": ("    return 0;", "    return 3;"),
    "skip-fourth": ("index < 4u", "index < 3u"),
}



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mutant", choices=MUTATIONS)
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
    elf, binary = output / "resource-heap-index.elf", output / "resource-heap-index.bin"
    source = ROOT / "src/resource_heap_index.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "resource_heap_index.c"
        source.write_text(content.replace(old, new))
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_resource_heap_index", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_allocator_state=0x465120",
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x2b3340", "--stop-address=0x2b33d0",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text(f"{entries['smt4_resource_heap_index']}\n")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceHeapIndex.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_HEAP_INDEX_COMPARE_OK" in log or "Heap index case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source)}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_HEAP_INDEX_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if comparison["selector_cases"] != 17740 or comparison["original_instruction_addresses"] != 35:
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt ARM heap selector; stable state, no modeled calls",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_heap_index.c", "src/resource_lifecycle.h",
                    "src/resource_create.h", "src/resource_sync.h", "src/resource_release.h",
                    "tools/check_resource_heap_index.py", "tools/ghidra/CompareResourceHeapIndex.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py",
                    "tools/ghidra_reference.py", "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
