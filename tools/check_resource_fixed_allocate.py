"""Build/compare EU fixed-pool allocation and allocation-produced lifetimes."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "rounded-fit": ("available >= size", "available >= ((size + 127u) & ~127u)"),
    "rounding": ("(size + 127u) & ~127u", "(size + 63u) & ~63u"),
    "exact-unlink": ("read_word(object + 20u) - 1u", "read_word(object + 20u) + 1u"),
    "cached-size": ("read_word(node + 4u) - rounded", "available - rounded"),
    "metadata-argument": ("0x100, 0x100, 0, 0x10, 1", "0x100, 0x100, 0, 0x20, 1"),
    "accounting": ("bytes - allocated_size", "bytes + allocated_size"),
    "fit-equality": ("available >= size", "available > size"),
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
    source = ROOT / "src/resource_fixed_allocate.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if old not in content:
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        source = output / source.name
        source.write_text(content)
    elf, binary = output / "resource-fixed-allocate.elf", output / "resource-fixed-allocate.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), str(ROOT / "src/resource_fixed_free.c"),
         str(ROOT / "src/resource_allocate_raw.c"), str(ROOT / "src/resource_free_raw.c"),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_resource_fixed_free",
         "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_allocate_lower=0x2c5544",
         "-Wl,--defsym,smt4_resource_heap_allocate=0x2c3a98",
         "-Wl,--defsym,smt4_resource_raw_state=0x465170",
         "-Wl,--defsym,smt4_resource_heap_acquire=0x2c3afc",
         "-Wl,--defsym,smt4_resource_heap_release=0x2c3a78",
         "-Wl,--defsym,smt4_resource_release=0x2c43b4",
         "-Wl,--defsym,smt4_resource_heap_free_counted=0x2b33d8", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for label, start, end in (("fixed-allocate", 0x144978, 0x144ab8), ("allocate-router", 0x2b26f0, 0x2b2868), ("fixed-free", 0x138354, 0x1384b8), ("insert", 0x2c3928, 0x2c39bc), ("router", 0x1244e8, 0x1245f0)):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}",
             str(code)], output, f"original-{label}")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in
        ("smt4_resource_fixed_free", "smt4_resource_fixed_insert", "smt4_resource_heap_free", "smt4_resource_fixed_allocate", "smt4_resource_allocate_raw")))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceFixedAllocate.java", str(output),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_FIXED_ALLOCATE_COMPARE_OK" in log or "Fixed allocation case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_FIXED_ALLOCATE_COMPARE_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if comparison["new_instruction_addresses"] != 79 or not comparison["persistent_lifetimes"]:
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt fixed-pool allocation/free and both routers; metadata allocation/release modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_fixed_allocate.c", "src/resource_fixed_free.c", "src/resource_allocate_raw.c", "src/resource_free_raw.c", "src/resource_allocate.h",
                    "src/resource_release.h", "src/resource_lifecycle.h", "src/resource_create.h", "src/resource_sync.h",
                    "tools/check_resource_fixed_allocate.py", "tools/check_resource_fixed_free.py", "tools/ghidra/CompareResourceFixedAllocate.java",
                    "tools/ghidra/CompareResourceFixedFree.java", "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java",
                    "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"binary_bytes": manifest["binary_bytes"], "comparison": comparison}))


if __name__ == "__main__":
    main()
