"""Build/compare EU three heap configuration leaves without modeled calls."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "fourth-offset": ("subobject + 0x34u", "subobject + 0x32u"),
    "fourth-byte": ("*field = (uint16_t)value;", "*(volatile uint8_t *)field = (uint8_t)value;"),
    "fourth-return-new": ("return previous;", "return value;"),
    "fifth-clobber": ("(previous & 0xfffeu) | (value & 1u)", "value & 1u"),
    "fifth-boolean": ("(value & 1u)", "(value != 0)"),
    "fifth-return-word": ("return previous & 1u;", "return previous;"),
    "sixth-offset": ("subobject + 0x38u", "subobject + 0x39u"),
    "sixth-unsigned": ("return (previous & 0x80u) != 0 ? previous | 0xffffff00u : previous;", "return previous;"),
    "sixth-wide-store": ("*field = (uint8_t)value;", "*(volatile uint16_t *)field = (uint16_t)value;"),
    "sixth-skip-same": ("*field = (uint8_t)value;", "if (previous != (uint8_t)value) *field = (uint8_t)value;"),
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
    elf, binary = output / "resource-heap-configure.elf", output / "resource-heap-configure.bin"
    source = ROOT / "src/resource_heap_configure.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "resource_heap_configure.c"
        content = content.replace(old, new)
        content = content.replace("    return value;", "    (void)previous;\n    return value;")
        source.write_text(content)
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_resource_heap_configure_fourth", "-Wl,--build-id=none",
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x146ce0", "--stop-address=0x146d20",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text("".join(f"{entries['smt4_resource_heap_configure_'+name]}\n" for name in ("fourth", "fifth", "sixth")))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceHeapConfigure.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_HEAP_CONFIGURE_COMPARE_OK" in log or "Heap configuration case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines()
                                 if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_HEAP_CONFIGURE_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["configuration_cases"] != 200976 or comparison["original_instruction_addresses"] != 16
            or comparison["modeled_calls"] != 0 or comparison["negative_byte_returns"] == 0
            or comparison["wrapping_addresses"] == 0 or comparison["unchanged_field_stores"] == 0):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt ARM configuration leaves; no modeled dependencies",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_heap_configure.c", "src/resource_allocate.h", "src/resource_lifecycle.h",
                    "src/resource_create.h", "src/resource_sync.h", "src/resource_release.h",
                    "tools/check_resource_heap_configure.py", "tools/ghidra/CompareResourceHeapConfigure.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py",
                    "tools/ghidra_reference.py", "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
