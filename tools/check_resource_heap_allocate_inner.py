"""Build/compare EU inner block selection and its recovered wrapper/setters."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "zero-size": ("size == 0 ? 1u : size", "size"),
    "rounding": ("+ 3u) & ~3u", "+ 7u) & ~7u"),
    "fit-equality": ("capacity >= needed", "capacity > needed"),
    "last-tie": ("capacity < smallest", "capacity <= smallest"),
    "reverse-sign": ("((candidate - start) & 0x80000000u) == 0", "candidate >= start"),
    "first-fit": ("if (first_fit || capacity == rounded)", "if (!first_fit || capacity == rounded)"),
    "direction": ("payload, rounded, reverse", "payload, rounded, 0"),
    "return": ("return smt4_resource_heap_commit_block", "(void)smt4_resource_heap_commit_block"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mutant", choices=MUTATIONS)
    args = parser.parse_args()
    output = local_path(args.output)
    if output.exists():
        raise FileExistsError("Choose new output under local/")
    project = ROOT / "local/ghidra/smt4-eu"
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
    source = ROOT / "src/resource_heap_allocate_inner.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if old not in content:
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        if args.mutant == "return":
            content = content.replace("payload, rounded, reverse);", "payload, rounded, reverse);\n    return 0;")
        source = output / source.name
        source.write_text(content)
    elf, binary = output / "resource-heap-inner.elf", output / "resource-heap-inner.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), str(ROOT / "src/resource_heap_allocate.c"), str(ROOT / "src/resource_heap_configure.c"),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_resource_heap_allocate_inner",
         "-Wl,--build-id=none", "-Wl,--defsym,smt4_resource_heap_commit_block=0x14f608", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for label, start, end in (("inner", 0x146ad8, 0x146c20), ("commit", 0x14f608, 0x14f7ec),
                              ("wrapper", 0x2c3a98, 0x2c3afc), ("setters", 0x146ce0, 0x146d20)):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}",
             str(code)], output, f"original-{label}")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in
        ("smt4_resource_heap_allocate_inner", "smt4_resource_heap_allocate")))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceHeapAllocateInner.java", str(output),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_HEAP_INNER_COMPARE_OK" in log or "Heap inner case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_HEAP_INNER_COMPARE_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["cases"] != 23616 or comparison["direct_cases"] != 11808
            or comparison["integrated_cases"] != 11808 or comparison["original_instruction_addresses"] != 123
            or any(comparison[key] == 0 for key in ("no_fit", "null_commit_returns", "counter_overflows",
                    "first_fit", "best_fit", "later_selections", "equal_capacity_observations", "zero_rounded"))):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt inner block selection, direct and wrapper/setter integration; 0x0014F608 modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_heap_allocate_inner.c", "src/resource_heap_allocate.c", "src/resource_heap_configure.c",
                    "src/resource_allocate.h", "src/resource_create.h", "src/resource_sync.h", "src/resource_release.h",
                    "src/resource_lifecycle.h", "tools/check_resource_heap_allocate_inner.py",
                    "tools/ghidra/CompareResourceHeapAllocateInner.java", "tools/ghidra/CompareResourceLifecycle.java",
                    "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"binary_bytes": manifest["binary_bytes"], "comparison": comparison}))


if __name__ == "__main__":
    main()
