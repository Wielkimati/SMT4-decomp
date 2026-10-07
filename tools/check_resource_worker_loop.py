"""Compare the EU worker outer loop with scheduled lower calls and node-region models."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

MUTANTS = {
    "stop-before-wait": ("smt4_worker_event_wait(smt4_worker_event);", "if (smt4_worker_stop) return;\n        smt4_worker_event_wait(smt4_worker_event);"),
    "cached-handle": ("&previous, smt4_file_sync_handle, 1", "&previous, handle, 1"),
    "head-after-unlock": ("uint32_t *node = (uint32_t *)(uintptr_t)smt4_file_list_head;", "uint32_t *node;"),
    "ignore-node-stop": ("if (smt4_worker_stop)\n                return;", "if (0)\n                return;"),
    "skip-reset": ("smt4_worker_event_reset(smt4_worker_event);", "(void)0;"),
    "wrong-delay": ("INT64_C(3000000)", "INT64_C(3000)"),
    "positive-is-error": ("if (result >> 31)", "if (result != 0)"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--mutant", choices=MUTANTS)
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
    source = ROOT / "src/resource_worker_loop.c"
    if args.mutant:
        content = source.read_text()
        old, new = MUTANTS[args.mutant]
        if content.count(old) != (2 if args.mutant == "positive-is-error" else 1):
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        if args.mutant == "head-after-unlock":
            content = content.replace("        for (;;) {", "        node = (uint32_t *)(uintptr_t)smt4_file_list_head;\n        for (;;) {")
        source = output / "mutant.c"
        source.write_text(content)
    definitions = {
        "smt4_file_sync_handle": 0x465010, "smt4_file_list_head": 0x46500c,
        "smt4_worker_stop": 0x465000, "smt4_worker_event": 0x465024,
        "smt4_file_acquire": 0x2c4350, "smt4_worker_unlock": 0x2c54a4,
        "smt4_file_check_result": 0x2c54bc, "smt4_file_worker_step": 0x710000,
        "smt4_worker_event_wait": 0x2c367c, "smt4_worker_event_reset": 0x138f5c,
        "smt4_file_delay": 0x2bb4f0,
    }
    elf, binary = output / "worker-loop.elf", output / "worker-loop.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_file_worker", "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}=0x{value:x}" for name, value in definitions.items()],
         "-o", str(elf)], output, "build")
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
    (output / "entries.txt").write_text(f"{entries['smt4_file_worker']}\n")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceWorkerLoop.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_WORKER_LOOP_OK" in log:
            raise RuntimeError("Mutant survived")
        if "Worker loop case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Failure was not an asserted corpus rejection")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source)}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_WORKER_LOOP_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if comparison["cases"] != 3456 or comparison["original_instruction_addresses"] != 53:
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Outer worker entry/loop; node region and lower calls modeled; scheduled stop/head/handle mutations",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_worker_loop.c", "src/resource_worker_loop.h", "src/resource_worker.h",
                    "src/resource_create.h", "src/resource_sync.h", "src/resource_lifecycle.h", "src/resource_wait.h",
                    "tools/check_resource_worker_loop.py", "tools/ghidra/CompareResourceWorkerLoop.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java",
                    "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
