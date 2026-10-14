"""Compare retained node passes or the continuous worker with completion/publication/release."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

NAMES = ["smt4_file_worker_step", "smt4_resource_request_complete",
         "resource_load_complete", "smt4_file_failed", "smt4_file_mark_cleanup",
         "smt4_resource_release"]
RANGES = [(0x113de8, 0x113e70), (0x114070, 0x114098), (0x114134, 0x1142e8),
          (0x155b30, 0x155bbc), (0x19f990, 0x19f99c), (0x14e634, 0x14e648),
          (0x2b0468, 0x2b0478), (0x2c43b4, 0x2c4424)]
MUTANTS = {
    "terminal-callback": ("resource_worker.c", "if (d[0] == 4 || d[0] == 5)", "if (0)"),
    "clear-cleanup": ("resource_worker.c", "d[1] = remaining;", "d[1] = remaining; d[2] = 0;"),
    "retain-success-data": ("resource_request.c", "descriptor[3] = 0;", "descriptor[3] = descriptor[3];"),
    "release-before-cleanup": ("resource_request.c",
        "smt4_file_mark_cleanup(packet->descriptor);\n    smt4_resource_release((uint32_t)(uintptr_t)packet);",
        "smt4_resource_release((uint32_t)(uintptr_t)packet);\n    smt4_file_mark_cleanup(packet->descriptor);"),
    "exclusive-endpoint": ("resource_release.c", "address <= first +", "address < first +"),
    "short-read-size": ("resource_worker_io.c", "smt4_worker_io_busy = 0;", "d[6] = bytes_read;\n    smt4_worker_io_busy = 0;"),
    "cached-close-handle": ("resource_worker_io.c",
        "if (o[1] & 1)\n            smt4_worker_file_preclose(o[1], 0, break_payload);\n        smt4_worker_file_close(o[1] & ~UINT32_C(1));",
        "uint32_t saved = o[1];\n        if (saved & 1)\n            smt4_worker_file_preclose(saved, 0, break_payload);\n        smt4_worker_file_close(saved & ~UINT32_C(1));"),
    "skip-io": ("resource_worker.c", "smt4_worker_state0_io(d);", "(void)d;"),
    "restart-head": ("resource_worker_loop.c", "node = smt4_file_worker_step(node);", "smt4_file_worker_step(node); node = (uint32_t *)(uintptr_t)smt4_file_list_head;"),
    "skip-reset": ("resource_worker_loop.c", "smt4_worker_event_reset(smt4_worker_event);", "(void)0;"),
    "wrong-delay": ("resource_worker_loop.c", "INT64_C(3000000)", "INT64_C(3000)"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--recover-io", action="store_true")
    parser.add_argument("--recover-loop", action="store_true", help="Execute the outer loop continuously with recovered I/O and retained traversal")
    parser.add_argument("--mutant", choices=MUTANTS)
    args = parser.parse_args()
    if args.recover_loop:
        args.recover_io = True
    if args.mutant in ("restart-head", "skip-reset", "wrong-delay") and not args.recover_loop:
        parser.error("This mutant requires --recover-loop")
    if args.mutant in ("short-read-size", "cached-close-handle", "skip-io") and not args.recover_io:
        parser.error("This mutant requires --recover-io")
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
    sources = ["src/resource_worker.c", "src/resource_request.c", "src/resource_lifecycle.c",
               "src/resource_descriptor.c", "src/resource_release.c"]
    if args.recover_io:
        sources.append("src/resource_worker_io.c")
    if args.recover_loop:
        sources.append("src/resource_worker_loop.c")
    paths = [ROOT / name for name in sources]
    mutant = None
    if args.mutant:
        filename, old, new = MUTANTS[args.mutant]
        original = ROOT / "src" / filename
        content = original.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        mutant = output / filename
        mutant.write_text(content.replace(old, new))
        paths[paths.index(original)] = mutant
    definitions = {
        "smt4_file_sync_handle": 0x465010, "smt4_file_list_head": 0x46500c,
        "smt4_file_acquire": 0x2c4350, "smt4_worker_unlock": 0x2c54a4,
        "smt4_file_check_result": 0x2c54bc, "smt4_worker_state0_io": 0x710000,
        "smt4_resource_allocator_state": 0x465120,
        "smt4_resource_heap_acquire": 0x2c3afc, "smt4_resource_heap_release": 0x2c3a78,
        "smt4_resource_release_convert": 0x1245f0, "smt4_resource_heap_free": 0x1244e8,
    }
    if args.recover_io:
        del definitions["smt4_worker_state0_io"]
        definitions.update({
            "smt4_worker_file_construction": 0x420870,
            "smt4_worker_io_lock_handle": 0x465124, "smt4_worker_io_busy": 0x465004,
            "smt4_worker_object_allocate": 0x2c244c,
            "smt4_worker_path_is_initial": 0x710000, "smt4_worker_path_measure": 0x710004,
            "smt4_worker_path_convert": 0x710008, "smt4_worker_file_open": 0x2bb944,
            "smt4_worker_data_allocate": 0x2bf7ec, "smt4_worker_io_acquire": 0x2c3afc,
            "smt4_worker_io_release": 0x2c3a78, "smt4_worker_file_preclose": 0x2bce9c,
            "smt4_worker_file_close": 0x2b9450,
        })
    elf, binary = output / "worker-completion.elf", output / "worker-completion.bin"
    if args.recover_loop:
        definitions.update({"smt4_worker_stop": 0x465000, "smt4_worker_event": 0x465024,
                            "smt4_worker_event_wait": 0x2c367c, "smt4_worker_event_reset": 0x138f5c,
                            "smt4_file_delay": 0x2bb4f0})
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections",
         "-Wall", "-Wextra", "-Werror", "-nostdlib", *map(str, paths), "-I", str(ROOT / "src"),
         "-Wl,-Ttext=0x600000", "-Wl,--entry=" + ("smt4_file_worker" if args.recover_loop else "smt4_file_worker_step"), "-Wl,--gc-sections",
         "-Wl,--undefined=smt4_resource_request_complete", "-Wl,--undefined=resource_load_complete",
         *(["-Wl,--undefined=smt4_worker_state0_io"] if args.recover_io else []),
         "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}=0x{value:x}" for name, value in definitions.items()],
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for start, stop in RANGES + ([(0x113e80, 0x114070), (0x114098, 0x114134)] if args.recover_io else []) + ([(0x113d58, 0x113de8), (0x114340, 0x114370)] if args.recover_loop else []):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start}", f"--stop-address={stop}",
             str(code)], output, f"original-{start:08x}")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    names = NAMES + (["smt4_worker_state0_io"] if args.recover_io else [])
    if args.recover_loop:
        names.append("smt4_file_worker")
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in names))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceWorkerCompletion.java",
               str(output), str(args.recover_io).lower(), str(args.recover_loop).lower(), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_WORKER_COMPLETION_OK" in log or "Worker completion scenario " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(mutant)}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_WORKER_COMPLETION_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    expected_counts = {"scenarios": 1728, "worker_passes": 6048,
                       "completions_both_paths": 3456, "publications_both_paths": 2304,
                       "releases_both_paths": 7296, "converted_both_paths": 2880,
                       "lower_allocator_calls": 24768, "original_instruction_addresses": 219}
    if args.recover_io:
        expected_counts = {"scenarios": 4608, "worker_passes": 16128,
                           "completions_both_paths": 9216, "publications_both_paths": 6144,
                           "releases_both_paths": 18816, "original_instruction_addresses": 382,
                           "io_executions_both_paths": 6912, "state0_io_modeled": False,
                           "converted_both_paths": 7200, "lower_allocator_calls": 63648,
                           "lower_io_calls_both_paths": 372096}
    if args.recover_loop:
        expected_counts.update(worker_passes=20736, outer_loop_recovered=True,
                               original_instruction_addresses=439,
                               node_visits_both_paths=73728, outer_calls_both_paths=133632)
    if any(comparison[key] != value for key, value in expected_counts.items()):
        raise RuntimeError("Incomplete comparison corpus")
    files = sources + ["src/resource_worker.h", "src/resource_request.h", "src/resource_sync.h",
                       "src/resource_create.h", "src/resource_lifecycle.h", "src/resource_release.h",
                       "tools/check_resource_worker_completion.py", "tools/ghidra/CompareResourceWorkerCompletion.java",
                       "tools/ghidra/CompareResourceWorker.java", "tools/ghidra/CompareResourceSync.java",
                       "tools/ghidra/CompareResourceLifecycle.java", "tools/check_nkm_lookup.py",
                       "tools/ghidra_reference.py", "config/recovery-tools.json", "config/analysis-tools.json"]
    if args.recover_io:
        files += ["src/resource_worker_io.h", "src/resource_worker_path.h", "src/resource_break.h"]
    if args.recover_loop:
        files += ["src/resource_worker_loop.h", "src/resource_wait.h"]
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": ("Continuous outer worker/node/I/O/completion/publication/release instructions with retained list traversal; lower calls modeled" if args.recover_loop else "Worker region/I/O/completion/publication/release instructions; lower file, conversion, allocation, synchronization and path callback modeled" if args.recover_io else
                           "Worker region/completion/publication/release instructions; I/O, path callback, synchronization, metadata conversion and lower free modeled"),
                "files_sha256": {name: digest(ROOT / name) for name in files}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
