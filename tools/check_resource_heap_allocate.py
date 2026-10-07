"""Build/compare EU six-word heap allocation wrapper with four explicit lower models."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "subobject": ("heap + 0x18u", "heap + 0x1cu"),
    "fourth-word": ("configure_fourth(subobject, fourth)", "configure_fourth(subobject, fifth)"),
    "fifth-word": ("configure_fifth(subobject, fifth)", "configure_fifth(subobject, sixth)"),
    "sixth-word": ("configure_sixth(subobject, sixth)", "configure_sixth(subobject, 0)"),
    "call-order": ("smt4_resource_heap_configure_fourth(subobject, fourth);\n    smt4_resource_heap_configure_fifth(subobject, fifth);", "smt4_resource_heap_configure_fifth(subobject, fifth);\n    smt4_resource_heap_configure_fourth(subobject, fourth);"),
    "size-alignment": ("allocate_inner(subobject, size, alignment)", "allocate_inner(subobject, alignment, size)"),
    "null-count": ("if (result != 0)", "if (result == 0)"),
    "counter-offset": ("heap + 0x54u", "heap + 0x50u"),
    "increment": ("*count + 1u", "*count + 2u"),
    "early-count": ("    void *result =", "    uint32_t saved = *(volatile uint32_t *)(uintptr_t)(heap + 0x54u);\n    void *result ="),
    "return": ("return result;", "return 0;"),
    "zero-size": ("    uint32_t subobject", "    if (size == 0) return 0;\n    uint32_t subobject"),
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
    elf, binary = output / "resource-heap-allocate.elf", output / "resource-heap-allocate.bin"
    source = ROOT / "src/resource_heap_allocate.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "resource_heap_allocate.c"
        content = content.replace(old, new)
        if args.mutant == "early-count":
            content = content.replace("*count = *count + 1u;", "*count = saved + 1u;")
        # Keep wrong forwarding mutants buildable even when one input is unused.
        content = content.replace("    uint32_t subobject =", "    (void)fourth; (void)fifth; (void)sixth;\n    uint32_t subobject =")
        source.write_text(content)
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_resource_heap_allocate", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_heap_configure_fourth=0x146ce0",
         "-Wl,--defsym,smt4_resource_heap_configure_fifth=0x146cf0",
         "-Wl,--defsym,smt4_resource_heap_configure_sixth=0x146d10",
         "-Wl,--defsym,smt4_resource_heap_allocate_inner=0x146ad8", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x2c3a98", "--stop-address=0x2c3afc",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text(f"{entries['smt4_resource_heap_allocate']}\n")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceHeapAllocate.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_HEAP_ALLOCATE_COMPARE_OK" in log or "Heap wrapper case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines()
                                 if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_HEAP_ALLOCATE_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["wrapper_cases"] != 16144 or comparison["original_instruction_addresses"] != 25
            or comparison["null_results"] == 0 or comparison["overflow_cases"] == 0
            or comparison["wrapping_heap_addresses"] == 0 or comparison["zero_size_cases"] == 0
            or comparison["dependency_calls_both_paths"] != 8 * comparison["wrapper_cases"]):
        raise RuntimeError("Incomplete comparison corpus")
    callers = [int(line.split()[1], 16) for line in (output / "caller-ghidra.txt").read_text().splitlines()
               if line.startswith("CALL ")]
    for address in callers:
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={address-48:#x}", f"--stop-address={address+24:#x}",
             str(code)], output, f"caller-{address:08x}")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt ARM six-word heap wrapper; four lower dependencies modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_heap_allocate.c", "src/resource_allocate.h", "src/resource_lifecycle.h",
                    "src/resource_create.h", "src/resource_sync.h", "src/resource_release.h",
                    "tools/check_resource_heap_allocate.py", "tools/ghidra/CompareResourceHeapAllocate.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py",
                    "tools/ghidra_reference.py", "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
