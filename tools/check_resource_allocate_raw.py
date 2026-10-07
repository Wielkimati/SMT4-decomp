"""Build/compare EU raw allocation routing with explicit heap and lock models."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "zero-size": ("if (size == 0) return 0;", "if (size == 1) return 0;"),
    "alignment-101": ("case 0x101: alignment = 128;", "case 0x101: alignment = 64;"),
    "alignment-default": ("uint32_t alignment = 8;", "uint32_t alignment = 4;"),
    "direction-byte": ("if (fifth == 0)", "if ((fifth & 255u) == 0)"),
    "heap-offset": ("0x1cu : 0x88u", "0x1cu : 0x84u"),
    "sixth-word": ("alignment, 0, 0, 0)", "alignment, 0, 0, 1)"),
    "reload-lock": ("smt4_resource_heap_release(lock);", "smt4_resource_heap_release(smt4_resource_raw_state[1] + (first == 0x100 ? 0x74u : 0xe0u));"),
    "fixed-object": ("0x4e4100u : 0x4e411cu", "0x4e4100u : 0x4e4100u"),
    "selector-mask": ("if (first == 0x100 ||", "if ((first & 0xffffu) == 0x100 ||"),
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
    elf, binary = output / "resource-allocate-raw.elf", output / "resource-allocate-raw.bin"
    source = ROOT / "src/resource_allocate_raw.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "resource_allocate_raw.c"
        source.write_text(content.replace(old, new))
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_resource_allocate_raw", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_raw_state=0x465170",
         "-Wl,--defsym,smt4_resource_heap_acquire=0x2c3afc",
         "-Wl,--defsym,smt4_resource_heap_release=0x2c3a78",
         "-Wl,--defsym,smt4_resource_heap_allocate=0x2c3a98",
         "-Wl,--defsym,smt4_resource_fixed_allocate=0x144978", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x2b26f0", "--stop-address=0x2b2868",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text(f"{entries['smt4_resource_allocate_raw']}\n")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceAllocateRaw.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_ALLOCATE_RAW_COMPARE_OK" in log or "Raw router case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source)}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_ALLOCATE_RAW_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["router_cases"] != 8824 or comparison["original_instruction_addresses"] != 85
            or comparison["signed_alignments"] != 10 or comparison["null_results"] == 0
            or comparison["dependency_calls_both_paths"] != 6 * comparison["locked_cases"] + 2 * comparison["fixed_cases"]):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt ARM raw allocation router; lower allocation and locks modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_allocate_raw.c", "src/resource_allocate.h", "src/resource_lifecycle.h",
                    "src/resource_create.h", "src/resource_sync.h", "src/resource_release.h",
                    "tools/check_resource_allocate_raw.py", "tools/ghidra/CompareResourceAllocateRaw.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py",
                    "tools/ghidra_reference.py", "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
