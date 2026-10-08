"""Build/compare concrete file ownership with persistent backend/prefix integration."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "length-limit": ("descriptor[2] > 512u", "descriptor[2] >= 512u"),
    "teardown-clear": ("object[1] = 0;", "object[1] = 1;"),
    "dispose-reload": ("    if (object[1] != 0) {\n        uint32_t handle", "    const uint32_t *saved = (const uint32_t *)(uintptr_t)object[0];\n    if (object[1] != 0) {\n        uint32_t handle"),
}
SERVICE_MUTATIONS = {
    "ipc-descriptor": ("(bytes << 14) | 2u", "(bytes << 13) | 2u"),
    "ipc-publish": ("    *handle = command[3];", "    if (!(command[1] >> 31)) *handle = command[3];"),
    "ipc-kernel": ("if (result >> 31)", "if (result != 0)"),
}
ARCHIVE_MUTATIONS = {
    "archive-descriptor": ("(bytes << 14) | 2u", "(bytes << 13) | 2u"),
    "archive-high": ("uint32_t high = command[3];", "uint32_t high = command[2];"),
    "archive-kernel": ("if (result >> 31)", "if (result != 0)"),
    "archive-publish": ("    *(volatile uint64_t *)handle = ((uint64_t)high << 32) | low;", "    if (!(command[1] >> 31)) *(volatile uint64_t *)handle = ((uint64_t)high << 32) | low;"),
}
ARCHIVE_TARGETS = (
    ("smt4_worker_backend_archive_open", 0x2adbe8, 0x2adc44),
    ("smt4_worker_backend_archive_close", 0x2adbb8, 0x2adbe4),
)
SERVICE_TARGETS = (
    ("smt4_worker_file_service_open", 0x356c28, 0x356c98),
    ("smt4_worker_file_service_close", 0x356d5c, 0x356d84),
)
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
    ("smt4_worker_backend_file_open", 0x3565a0, 0x356660),
    ("smt4_worker_file_handle", 0x239cd0, 0x239cf4),
    ("smt4_worker_file_teardown", 0x356578, 0x3565a0),
    ("smt4_worker_file_dispose", 0x356438, 0x3564a4),
    ("smt4_worker_file_close", 0x2b9450, 0x2b9468),
)




def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recover-clear", action="store_true", help="Execute recovered clearing in mapped bounded fixtures")
    parser.add_argument("--output", required=True)
    parser.add_argument("--mutant", choices=(*MUTATIONS, *SERVICE_MUTATIONS, *ARCHIVE_MUTATIONS))
    parser.add_argument("--recover-services", action="store_true")
    parser.add_argument("--recover-archive-services", action="store_true", help="Implies --recover-services")
    args = parser.parse_args()
    if args.recover_archive_services:
        args.recover_services = True
    if args.mutant in ARCHIVE_MUTATIONS and not args.recover_archive_services:
        parser.error("Archive mutations require --recover-archive-services")
    if args.mutant in SERVICE_MUTATIONS and not args.recover_services:
        parser.error("IPC mutations require --recover-services")
    targets = TARGETS + SERVICE_TARGETS if args.recover_services else TARGETS
    if args.recover_archive_services:
        targets += ARCHIVE_TARGETS
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
    source = ROOT / "src/resource_worker_file_owner.c"
    service_source = ROOT / "src/resource_worker_file_service.c"
    archive_source = ROOT / "src/resource_worker_archive_service.c"
    if args.mutant in ARCHIVE_MUTATIONS:
        old, new = ARCHIVE_MUTATIONS[args.mutant]
        content = archive_source.read_text()
        if old not in content:
            raise RuntimeError("Archive mutation anchor")
        archive_source = output / archive_source.name
        archive_source.write_text(content.replace(old, new))
    elif args.mutant in SERVICE_MUTATIONS:
        old, new = SERVICE_MUTATIONS[args.mutant]
        content = service_source.read_text()
        if old not in content:
            raise RuntimeError("IPC mutation anchor")
        service_source = output / service_source.name
        service_source.write_text(content.replace(old, new))
    elif args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if old not in content:
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        if args.mutant == "dispose-reload":
            content = content.replace("(const uint32_t *)(uintptr_t)object[0];\n    ((void", "saved;\n    ((void")
        source = output / source.name
        source.write_text(content)
    elf, binary = output / "resource-worker-file-owner.elf", output / "resource-worker-file-owner.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         *([str(ROOT / "src/resource_clear.c")] if args.recover_clear else []),
         str(source), str(ROOT / "src/resource_worker_backend.c"), str(ROOT / "src/resource_worker_file_cleanup.c"), str(ROOT / "src/resource_worker_prefix.c"), str(ROOT / "src/resource_worker_file_open.c"),
         *([str(service_source)] if args.recover_services else []),
         *([str(archive_source)] if args.recover_archive_services else []),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_worker_backend_create",
         "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}={address:#x}" for name, address in {
             "smt4_worker_file_pool": 0x4d4358, "smt4_worker_file_vtable": 0x420998,
             **({} if args.recover_services else {"smt4_worker_file_service_open": 0x356c28, "smt4_worker_file_service_close": 0x356d5c}),
             "smt4_worker_file_preclose": 0x2bce9c, "smt4_resource_release": 0x2c43b4,
             "smt4_worker_backend_state": 0x44e650, "smt4_worker_backend_pool": 0x4d431c,
             "smt4_worker_backend_vtable": 0x4209f8, "smt4_worker_prefix_table": 0x4d43e0,
             "smt4_worker_prefix_fallback": 0x407fbc, "smt4_worker_prefix_diagnostic": 0x2bce9c,
             **({} if args.recover_archive_services else {"smt4_worker_backend_archive_open": 0x2adbe8, "smt4_worker_backend_archive_close": 0x2adbb8}),
             "smt4_worker_backend_acquire": 0x2c3afc, "smt4_worker_backend_release": 0x2c3a78,
             **({} if args.recover_clear else {"smt4_worker_backend_clear": 0x139f54}), "smt4_worker_backend_diagnostic": 0x2bbd70,
         }.items()], "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for label, start, end in (*TARGETS[11:15], *(SERVICE_TARGETS if args.recover_services else ()), *(ARCHIVE_TARGETS if args.recover_archive_services else ())):
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
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in
        (target[0] for target in targets)))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceWorkerFileOwner.java", str(output),
               *(["archives"] if args.recover_archive_services else ["services"] if args.recover_services else []),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_FILE_OWNER_COMPARE_OK" in log or "File owner case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(archive_source if args.mutant in ARCHIVE_MUTATIONS else service_source if args.mutant in SERVICE_MUTATIONS else source),
                  "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_FILE_OWNER_COMPARE_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if args.recover_clear:
        comparison["services_svc_locks_diagnostics_modeled"] = comparison.pop("services_svc_locks_clear_diagnostics_modeled")
        comparison["clearing_recovered"] = True
        (output / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
    if comparison["new_instruction_addresses"] != 94 or comparison["persistent_sequences"] == 0:
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Original/rebuilt file ownership with concrete backend/prefix/open/close execution; archive/file services, SVC 0x23, locks, clearing and diagnostics modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_worker_file_owner.c", "src/resource_worker_file_owner.h",
                    "src/resource_worker_file_cleanup.c", "src/resource_worker_file_cleanup.h",
                    "src/resource_worker_backend.c", "src/resource_worker_backend.h", "src/resource_recursive_lock.h",
                    "src/resource_worker_prefix.c", "src/resource_worker_prefix.h",
                    "src/resource_worker_file_open.c", "src/resource_worker_file_open.h",
                    "tools/check_resource_worker_file_owner.py", "tools/ghidra/CompareResourceWorkerFileOwner.java",
                    "tools/ghidra/CompareResourceWorkerBackend.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java",
                    "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    if args.recover_services:
        manifest["services"] = json.loads((output / "services.json").read_text())
        if manifest["services"]["original_instruction_sites"] != (72 if args.recover_archive_services else 38):
            raise RuntimeError("Incomplete service coverage")
        manifest["files_sha256"]["src/resource_worker_file_service.c"] = digest(ROOT / "src/resource_worker_file_service.c")
        manifest["method"] = "Original/rebuilt file IPC wrappers through ownership lifetimes; TLS, SVC, archive services, locks, clearing and diagnostics modeled"
    if args.recover_archive_services:
        manifest["archive_services"] = json.loads((output / "archive-services.json").read_text())
        manifest["files_sha256"]["src/resource_worker_archive_service.c"] = digest(ROOT / "src/resource_worker_archive_service.c")
        manifest["method"] = "Original/rebuilt archive and file IPC wrappers through ownership lifetimes; TLS, SVC, locks, clearing and diagnostics modeled"
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
