"""Build/compare EU raw-free routing and connected arena lifetimes."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "end-inclusive": ("address < start +", "address <= start +"),
    "start-exclusive": ("start <= address", "start < address"),
    "null-guard": ("uint32_t base = smt4_resource_raw_state[1];", "if (address == 0) return;\n    uint32_t base = smt4_resource_raw_state[1];"),
    "range-priority": ("contains(base, 0x14u, address)", "contains(base, 0x80u, address)"),
    "heap-offset": ("heap = base + 0x88u", "heap = base + 0x84u"),
    "fixed-object": ("smt4_resource_fixed_free(0x4e411cu", "smt4_resource_fixed_free(0x4e4100u"),
    "reload-lock": ("smt4_resource_heap_release(lock);", "smt4_resource_heap_release(smt4_resource_raw_state[1] + (lock - base));"),
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
    source = ROOT / "src/resource_free_raw.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if old not in content:
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        source = output / source.name
        source.write_text(content)
    elf, binary = output / "resource-free-raw.elf", output / "resource-free-raw.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), str(ROOT / "src/resource_heap_free.c"), str(ROOT / "src/resource_heap_commit_block.c"), str(ROOT / "src/resource_heap_allocate_inner.c"), str(ROOT / "src/resource_heap_allocate.c"), str(ROOT / "src/resource_heap_configure.c"),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_resource_heap_free_inner",
         "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_raw_state=0x465170",
         "-Wl,--defsym,smt4_resource_heap_acquire=0x2c3afc",
         "-Wl,--defsym,smt4_resource_heap_release=0x2c3a78",
         "-Wl,--defsym,smt4_resource_fixed_free=0x138354", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for label, start, end in (("router", 0x1244e8, 0x1245f0), ("free-inner", 0x14699c, 0x146ad8), ("free-wrapper", 0x2b33d8, 0x2b33f8), ("inner", 0x146ad8, 0x146c20), ("commit", 0x14f608, 0x14f7ec),
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
        ("smt4_resource_heap_commit_block", "smt4_resource_heap_allocate", "smt4_resource_heap_free_inner", "smt4_resource_heap_free_counted", "smt4_resource_heap_free")))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceFreeRaw.java", str(output),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_FREE_RAW_COMPARE_OK" in log or "Raw free case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_FREE_RAW_COMPARE_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["router_instruction_addresses"] != 63 or comparison["arena_scenarios"] == 0
            or any(x == 0 for x in comparison["routes"])):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt raw-free routing; locks and fixed-pool free modeled; counted free modeled only in direct range probes",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_free_raw.c", "src/resource_heap_free.c", "src/resource_heap_commit_block.c", "src/resource_heap_allocate_inner.c", "src/resource_heap_allocate.c", "src/resource_heap_configure.c",
                    "src/resource_allocate.h", "src/resource_create.h", "src/resource_sync.h", "src/resource_release.h",
                    "src/resource_lifecycle.h", "tools/check_resource_free_raw.py", "tools/check_resource_heap_free.py",
                    "tools/ghidra/CompareResourceFreeRaw.java", "tools/ghidra/CompareResourceHeapFree.java", "tools/ghidra/CompareResourceHeapCommitBlock.java", "tools/ghidra/CompareResourceLifecycle.java",
                    "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"binary_bytes": manifest["binary_bytes"], "comparison": comparison}))


if __name__ == "__main__":
    main()
