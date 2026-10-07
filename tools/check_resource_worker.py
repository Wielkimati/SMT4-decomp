"""Build/compare EU bounded worker step with explicit I/O, synchronization and callback models."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--mutant", choices=("terminal-callback", "unsigned-retain", "null-context", "error-survives", "clear-cleanup", "next-after-free"))
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
    source = ROOT / "src/resource_worker.c"
    if args.mutant:
        edits = {
            "terminal-callback": ("if (d[0] == 4 || d[0] == 5)", "if (0)"),
            "unsigned-retain": ("remaining == 0 || remaining >= UINT32_C(0x80000000)", "remaining == 0"),
            "null-context": ("context ? context : (uint32_t)(uintptr_t)d", "context"),
            "error-survives": ("d[0] = 3;", "if (d[0] != 5) d[0] = 3;"),
            "clear-cleanup": ("d[1] = remaining;", "d[1] = remaining; d[2] = 0;"),
            "next-after-free": ("return next; /* Captured", "return (uint32_t *)(uintptr_t)((volatile uint32_t *)d)[0x13c / 4]; /* Captured"),
        }
        old, new = edits[args.mutant]
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "mutant.c"
        source.write_text(text.replace(old, new))
    elf, binary = output / "resource-worker.elf", output / "resource-worker.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_file_worker_step", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_file_sync_handle=0x465010",
         "-Wl,--defsym,smt4_file_list_head=0x46500c",
         "-Wl,--defsym,smt4_file_acquire=0x2c4350",
         "-Wl,--defsym,smt4_worker_unlock=0x2c54a4",
         "-Wl,--defsym,smt4_file_check_result=0x2c54bc",
         "-Wl,--defsym,smt4_resource_release=0x2c43b4",
         "-Wl,--defsym,smt4_worker_state0_io=0x710000", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x113d58", "--stop-address=0x114374",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text(f"{entries['smt4_file_worker_step']}\n")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceWorker.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_WORKER_COMPARE_OK" in log:
            raise RuntimeError("Mutant survived")
        if "Worker case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Failure was not an asserted corpus rejection")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source)}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_WORKER_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["worker_cases"] != 3472 or comparison["state0_probes"] != 160
            or comparison["region_original_instruction_addresses"] != 153
            or comparison["state0_original_instruction_addresses"] != 159):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Adapted worker node region; state-0 block/synchronization/callback/release modeled; separate original I/O probes",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_worker.c", "src/resource_worker.h", "src/resource_create.h", "src/resource_release.h",
                    "src/resource_sync.h", "src/resource_lifecycle.h",
                    "tools/check_resource_worker.py", "tools/ghidra/CompareResourceWorker.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java", "tools/check_nkm_lookup.py",
                    "tools/ghidra_reference.py", "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
