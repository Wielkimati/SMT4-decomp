"""Build/compare concrete backend ownership with prefix/open integration."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "pool-count": ("pool[0x2c / 4] += 1u;", "pool[0x2c / 4] -= 1u;"),
    "factory-capture": ("object[1] = service;", "object[1] = smt4_worker_backend_state[4];"),
    "teardown-clear": ("object[3] = 0;", "object[3] = 1;"),
    "accessor-reload": ("return object[1];", "return 0;"),
}
TARGETS = (
    ("smt4_worker_backend_pool_take", 0x2b5d6c, 0x2b5dd0),
    ("smt4_worker_backend_create", 0x3568c8, 0x356974),
    ("smt4_worker_backend_service", 0x23a004, 0x23a028),
    ("smt4_worker_backend_teardown", 0x35674c, 0x3567a0),
    ("smt4_worker_backend_dispose", 0x3562d0, 0x35631c),
    ("smt4_worker_backend_register", 0x354dec, 0x354e60),
    ("smt4_worker_prefix_register", 0x2b5e70, 0x2b5fb8),
    ("smt4_worker_prefix_remove", 0x2c4054, 0x2c41a4),
    ("smt4_worker_file_open", 0x2bb944, 0x2bb9d4),
    ("smt4_worker_path_backend", 0x2b5ca0, 0x2b5d68),
    ("smt4_worker_utf16_length", 0x2b5c8c, 0x2b5c9e),
)




def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recover-clear", action="store_true", help="Execute recovered clearing in mapped bounded fixtures")
    parser.add_argument("--recover-locks", action="store_true", help="Execute recursive and base locks with scheduled TLS/exclusives")
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
    source = ROOT / "src/resource_worker_backend.c"
    if args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if old not in content:
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        source = output / source.name
        source.write_text(content)
    elf, binary = output / "resource-worker-backend.elf", output / "resource-worker-backend.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         *([str(ROOT / "src/resource_clear.c")] if args.recover_clear else []),
         *([str(ROOT / "src/resource_recursive_lock.c"), str(ROOT / "src/resource_lock.c")] if args.recover_locks else []),
         str(source), str(ROOT / "src/resource_worker_prefix.c"), str(ROOT / "src/resource_worker_file_open.c"),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_worker_backend_create",
         "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}={address:#x}" for name, address in {
             "smt4_worker_backend_state": 0x44e650, "smt4_worker_backend_pool": 0x4d431c,
             "smt4_worker_backend_vtable": 0x4209f8, "smt4_worker_prefix_table": 0x4d43e0,
             "smt4_worker_prefix_fallback": 0x407fbc, "smt4_worker_prefix_diagnostic": 0x2bce9c,
             "smt4_worker_backend_archive_open": 0x2adbe8, "smt4_worker_backend_archive_close": 0x2adbb8,
             **({"smt4_arbitration_handle": 0x471b58, "smt4_signal_arbitrate": 0x2a88fc} if args.recover_locks else
                {"smt4_worker_backend_acquire": 0x2c3afc, "smt4_worker_backend_release": 0x2c3a78}),
             **({} if args.recover_clear else {"smt4_worker_backend_clear": 0x139f54}), "smt4_worker_backend_diagnostic": 0x2bbd70,
         }.items()], "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for label, start, end in TARGETS[:6]:
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}",
             str(code)], output, f"original-{label}")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    if args.recover_clear:
        (output / "clear-entry.txt").write_text(str(entries["smt4_worker_backend_clear"]))
    if args.recover_locks:
        (output / "lock-entries.txt").write_text("".join(f"{entries[n]}\n" for n in
            ("smt4_worker_backend_acquire", "smt4_worker_backend_release")))
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in
        (target[0] for target in TARGETS)))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceWorkerBackend.java", str(output),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_BACKEND_COMPARE_OK" in log or "Backend case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_BACKEND_COMPARE_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if args.recover_clear:
        comparison["services_locks_diagnostics_modeled"] = comparison.pop("services_locks_clear_diagnostics_modeled")
        comparison["clearing_recovered"] = True
        (output / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
    if comparison["new_instruction_addresses"] != 146 or comparison["persistent_sequences"] == 0:
        raise RuntimeError("Incomplete comparison corpus")
    if args.recover_locks:
        comparison.pop("services_locks_diagnostics_modeled" if args.recover_clear else "services_locks_clear_diagnostics_modeled")
        comparison["services_diagnostics_modeled"] = True
        comparison["clearing_modeled"] = not args.recover_clear
        comparison["tls_exclusives_modeled"] = True
        comparison["recursive_and_base_locks_recovered"] = True
        (output / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt backend lifetime with executed prefix registration/removal and open dispatch; archive services, locks, clearing and diagnostics modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_worker_backend.c", "src/resource_worker_backend.h", "src/resource_recursive_lock.h",
                    "src/resource_worker_prefix.c", "src/resource_worker_prefix.h", "src/resource_break.h",
                    "src/resource_worker_file_open.c", "src/resource_worker_file_open.h",
                    "tools/check_resource_worker_backend.py", "tools/ghidra/CompareResourceWorkerBackend.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java",
                    "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    if args.recover_clear:
        manifest["recovered_clear"] = json.loads((output / "clear.json").read_text())
        manifest["method"] += "; optional recovered-clear mode replaces clearing (see recovered_clear)"
        for name in ("src/resource_clear.c", "src/resource_clear.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    if args.recover_locks:
        manifest["recovered_locks"] = json.loads((output / "locks.json").read_text())
        if args.recover_clear:
            manifest["recovered_clear"]["other_models_unchanged"] = False
            (output / "clear.json").write_text(json.dumps(manifest["recovered_clear"], indent=2) + "\n")
        manifest["method"] += "; optional recovered-locks mode replaces wrapper/base lock calls (see recovered_locks)"
        for name in ("src/resource_recursive_lock.c", "src/resource_recursive_lock.h", "src/resource_lock.c", "src/resource_signal.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"binary_bytes": manifest["binary_bytes"], "comparison": comparison}))


if __name__ == "__main__":
    main()
