"""Build/compare EU worker data allocation, with direct probes and recovered raw/registration/conversion integration."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "signed-minimum": ("alignment < 128u", "(int32_t)alignment < 128"),
    "early-truncate": ("uint32_t raw_size =", "alignment = (uint16_t)alignment;\n    uint32_t raw_size ="),
    "wrong-size": ("+ 0x3bu", "+ 0x3au"),
    "full-user-mask": ("uint32_t low = (uint16_t)alignment;", "uint32_t low = alignment;"),
    "fifth-forwarding": ("raw_size, direction)", "raw_size, ((void)direction, alignment))"),
    "backlink": ("user - 4u", "user - 8u"),
    "clear-size": ("user, size)", "user, raw_size)"),
    "cached-lock": ("smt4_resource_heap_acquire(smt4_resource_allocator_state[1]);", "uint32_t lock = smt4_resource_allocator_state[1];\n    smt4_resource_heap_acquire(lock);"),
}



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recover-clear", action="store_true", help="Execute recovered clearing in mapped bounded fixtures")
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
    elf, binary = output / "resource-worker-data-allocate.elf", output / "resource-worker-data-allocate.bin"
    source = ROOT / "src/resource_worker_data_allocate.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "resource_worker_data_allocate.c"
        content = content.replace(old, new)
        if args.mutant == "cached-lock":
            content = content.replace("smt4_resource_heap_release(smt4_resource_allocator_state[1]);", "smt4_resource_heap_release(lock);")
        source.write_text(content)
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         *([str(ROOT / "src/resource_clear.c")] if args.recover_clear else []),
         str(source), *[str(ROOT / "src" / name) for name in (
             "resource_allocate_raw.c", "resource_allocate_register.c", "resource_heap_index.c", "resource_release_convert.c")], "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_worker_data_allocate", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_allocator_state=0x465120",
         "-Wl,--defsym,smt4_resource_raw_state=0x465170",
         "-Wl,--defsym,smt4_resource_heap_acquire=0x2c3afc",
         "-Wl,--defsym,smt4_resource_heap_release=0x2c3a78",
         "-Wl,--defsym,smt4_resource_heap_allocate=0x2c3a98",
         "-Wl,--defsym,smt4_resource_fixed_allocate=0x144978",
         * ([] if args.recover_clear else ["-Wl,--defsym,smt4_resource_allocate_zero=0x2c3b9c"]), "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x2bf7ec", "--stop-address=0x2bf8b0",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    if args.recover_clear:
        (output / "clear-entry.txt").write_text(str(entries["smt4_resource_allocate_zero"]))
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in (
        "smt4_worker_data_allocate", "smt4_resource_allocate_raw", "smt4_resource_allocate_register",
        "smt4_resource_heap_index", "smt4_resource_release_convert")))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceWorkerDataAllocate.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_WORKER_DATA_ALLOCATE_COMPARE_OK" in log or "Worker data case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_WORKER_DATA_ALLOCATE_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if args.recover_clear:
        comparison["storage_locks_modeled"] = comparison.pop("storage_locks_zero_modeled")
        comparison["clearing_recovered"] = True
        (output / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
    if comparison["new_instruction_addresses"] != 48 or not comparison["integrated_cases"] or not comparison["direct_cases"]:
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt ARM worker data allocation; direct dependency models plus recovered raw routing, registration, selector and conversion; heap/fixed storage, locks and zero modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_worker_data_allocate.c", "src/resource_worker_io.h", "src/resource_allocate_raw.c",
                    "src/resource_allocate_register.c", "src/resource_heap_index.c", "src/resource_release_convert.c", "src/resource_allocate.h", "src/resource_lifecycle.h",
                    "src/resource_create.h", "src/resource_sync.h", "src/resource_release.h",
                    "tools/check_resource_worker_data_allocate.py", "tools/ghidra/CompareResourceWorkerDataAllocate.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py",
                    "tools/ghidra_reference.py", "config/recovery-tools.json", "config/analysis-tools.json")}}
    if args.recover_clear:
        manifest["recovered_clear"] = json.loads((output / "clear.json").read_text())
        manifest["method"] += "; optional recovered-clear mode replaces clearing (see recovered_clear)"
        for name in ("src/resource_clear.c", "src/resource_clear.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"binary_bytes": manifest["binary_bytes"], "comparison": comparison}))


if __name__ == "__main__":
    main()
