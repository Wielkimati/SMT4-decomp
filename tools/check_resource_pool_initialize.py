"""Build/compare pool and lock initialization with initialized backend lifetimes."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "rounding": ("element_bytes + alignment - 1u", "element_bytes"),
    "reload": ("uint32_t next_stride = words[0x18 / 4];", "uint32_t next_stride = stride;"),
    "init-order": ("smt4_resource_base_lock_initialize(lock);\n    words[1] = 0;\n    words[2] = 0;",
                   "words[1] = 0;\n    words[2] = 0;\n    smt4_resource_base_lock_initialize(lock);"),
}
GLOBAL_MUTATIONS = {
    "global-storage": ("0x004307c0", "0x004307c4"),
    "global-tail": ("pool[0x38 / 4] = UINT32_MAX;", "pool[0x38 / 4] = 0;"),
    "global-service": ("UINT32_C(0x0044e660) = 0", "UINT32_C(0x0044e660) = 1"),
}
GLOBAL_TARGETS = (("smt4_resource_global_startup", 0x3f3568, 0x3f36f0),
                  ("startup_noop_tail", 0x225e68, 0x225e6c))
DISPATCH_MUTATIONS = {
    "dispatch-relative-bound": ("while (cursor != end)", "while (cursor < end)"),
    "dispatch-relative-target": ("(cursor + offset)", "(offset)"),
    "dispatch-absolute-bound": ("while (cursor < end)", "while (cursor != end)"),
}
TABLE_MUTATIONS = {
    "table-policy": ("0x003f0930), 1", "0x003f0930), 0"),
    "table-reserved": ("bytes[12] = initial[i].policy;", "bytes[12] = initial[i].policy; bytes[13] = 0;"),
    "table-ancillary": ("ancillary[1] = UINT32_MAX;", "ancillary[1] = 0;"),
}
INIT_TARGETS = (("smt4_resource_pool_initialize", 0x2a4eb4, 0x2a4f54),
                ("smt4_resource_recursive_lock_initialize", 0x2c3b54, 0x2c3b70),
                ("smt4_resource_base_lock_initialize", 0x138f44, 0x138f5c))
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
    parser.add_argument("--output", required=True)
    parser.add_argument("--mutant", choices=(*MUTATIONS, *GLOBAL_MUTATIONS, *DISPATCH_MUTATIONS, *TABLE_MUTATIONS))
    parser.add_argument("--recover-global-startup", action="store_true")
    parser.add_argument("--recover-startup-dispatch", action="store_true")
    parser.add_argument("--recover-table-registry", action="store_true")
    args = parser.parse_args()
    if args.recover_table_registry:
        args.recover_startup_dispatch = True
    if args.mutant in TABLE_MUTATIONS and not args.recover_table_registry:
        parser.error("Table mutation requires --recover-table-registry")
    if args.recover_startup_dispatch:
        args.recover_global_startup = True
    if args.mutant in DISPATCH_MUTATIONS and not args.recover_startup_dispatch:
        parser.error("Dispatch mutation requires --recover-startup-dispatch")
    if args.mutant in GLOBAL_MUTATIONS and not args.recover_global_startup:
        parser.error("Global mutation requires --recover-global-startup")
    args.recover_clear = args.recover_locks = True
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
    source = ROOT / "src/resource_pool_initialize.c"
    global_source = ROOT / "src/resource_global_startup.c"
    dispatch_source = ROOT / "src/startup_dispatch.c"
    table_source = ROOT / "src/table_resource_initialize.c"
    if args.mutant in TABLE_MUTATIONS:
        old, new = TABLE_MUTATIONS[args.mutant]
        content = table_source.read_text()
        assert content.count(old) == 1
        table_source = output / table_source.name
        table_source.write_text(content.replace(old, new))
    elif args.mutant in DISPATCH_MUTATIONS:
        old, new = DISPATCH_MUTATIONS[args.mutant]
        content = dispatch_source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Dispatch mutation anchor")
        dispatch_source = output / dispatch_source.name
        dispatch_source.write_text(content.replace(old, new))
    elif args.mutant:
        target_global = args.mutant in GLOBAL_MUTATIONS
        if target_global:
            source = global_source
        old, new = (GLOBAL_MUTATIONS if target_global else MUTATIONS)[args.mutant]
        content = source.read_text()
        if old not in content:
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        source = output / source.name
        source.write_text(content)
        if target_global:
            global_source = source
            source = ROOT / "src/resource_pool_initialize.c"
    elf, binary = output / "resource-worker-backend.elf", output / "resource-worker-backend.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         *([str(ROOT / "src/resource_clear.c")] if args.recover_clear else []),
         *([str(ROOT / "src/resource_recursive_lock.c"), str(ROOT / "src/resource_lock.c")] if args.recover_locks else []),
         *([str(global_source), str(ROOT / "src/resource_array_initialize.c"), str(ROOT / "src/resource_worker_prefix_initialize.c")] if args.recover_global_startup else []),
         *([str(dispatch_source)] if args.recover_startup_dispatch else []),
         *([str(table_source), str(ROOT / "src/resource_lifecycle.c"), str(ROOT / "src/resource_bulk.c")] if args.recover_table_registry else []),
         str(source), str(ROOT / "src/unsigned_quotient.c"), str(ROOT / "src/resource_worker_backend.c"), str(ROOT / "src/resource_worker_prefix.c"), str(ROOT / "src/resource_worker_file_open.c"),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_worker_backend_create",
         "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}={address:#x}" for name, address in {
             **({"smt4_startup_relative_begin": 0x42a188, "smt4_startup_relative_end": 0x42ab78,
                 "smt4_startup_absolute_begin": 0x42ab78, "smt4_startup_absolute_end": 0x42ab78} if args.recover_startup_dispatch else {}),
             **({"smt4_table_resource_registry": 0x49382c, "smt4_resource_load": 0x2c3344,
                 "smt4_resource_request": 0x2b6820, "smt4_resource_release": 0x2c43b4,
                 "smt4_resource_order_index": 0x29706c} if args.recover_table_registry else {}),
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
    for label, start, end in (*INIT_TARGETS, *(GLOBAL_TARGETS if args.recover_global_startup else ())):
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
    (output / "init-entries.txt").write_text("".join(f"{entries[n]}\n" for n, _, _ in INIT_TARGETS))
    if args.recover_global_startup:
        (output / "global-entry.txt").write_text(str(entries["smt4_resource_global_startup"]))
    if args.recover_startup_dispatch:
        names = [f"smt4_startup_dispatch_{kind}{suffix}" for suffix in ("", "_range") for kind in ("relative", "absolute")]
        (output / "dispatch-entries.txt").write_text("".join(f"{entries[n]}\n" for n in names))
        for kind, start, end in (("relative", 0x100cb8, 0x100cdc), ("absolute", 0x102338, 0x10236c)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
                 *(["-M", "force-thumb"] if kind == "relative" else []), "--adjust-vma=0x100000",
                 f"--start-address={start:#x}", f"--stop-address={end:#x}", str(code)], output, f"original-dispatch-{kind}")
    script = "CompareResourceGlobalStartup.java" if args.recover_global_startup else "CompareResourcePoolInitialize.java"
    success = "SMT4_GLOBAL_STARTUP_COMPARE_OK" if args.recover_global_startup else "SMT4_POOL_INIT_COMPARE_OK"
    if args.recover_startup_dispatch:
        script, success = "CompareStartupDispatch.java", "SMT4_STARTUP_DISPATCH_COMPARE_OK"
    if args.recover_table_registry:
        (output / "table-entries.txt").write_text("".join(f"{entries[n]}\n" for n in
            ("smt4_table_resource_initialize", "resource_load_bulk", "resource_load_if_dynamic", "resource_release_if_dynamic")))
        script, success = "CompareTableResourceInitialize.java", "SMT4_TABLE_REGISTRY_COMPARE_OK"
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", script, str(output),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        case_label = "Table registry case" if args.recover_table_registry else "Startup dispatch case" if args.recover_startup_dispatch else "Global startup case" if args.recover_global_startup else "Pool initialization case"
        if success in log or case_label not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by initialization assertion")
        marker = {"mutant": args.mutant, "rejected": True, "binary_sha256": digest(binary),
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if success not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    paths = ["src/resource_pool_initialize.c", "src/resource_pool_initialize.h", "src/unsigned_quotient.c", "src/unsigned_quotient.h",
             "src/resource_worker_backend.c", "src/resource_worker_backend.h", "src/resource_recursive_lock.c", "src/resource_recursive_lock.h",
             "src/resource_lock.c", "src/resource_signal.h", "src/resource_clear.c", "src/resource_clear.h",
             "src/resource_worker_prefix.c", "src/resource_worker_prefix.h", "src/resource_break.h", "src/resource_worker_file_open.c", "src/resource_worker_file_open.h",
             "tools/check_resource_pool_initialize.py", "tools/ghidra/CompareResourcePoolInitialize.java",
             "tools/ghidra/CompareResourceWorkerBackend.java", "tools/ghidra/CompareResourceSync.java", "tools/ghidra/CompareResourceLifecycle.java",
             "tools/check_nkm_lookup.py", "tools/ghidra_reference.py", "config/analysis-tools.json", "config/recovery-tools.json"]
    if args.recover_global_startup:
        paths += ["src/resource_global_startup.c", "src/resource_global_startup.h", "src/resource_array_initialize.c", "src/resource_array_initialize.h", "src/resource_worker_prefix_initialize.c", "tools/ghidra/CompareResourceGlobalStartup.java"]
    if args.recover_startup_dispatch:
        paths += ["src/startup_dispatch.c", "src/startup_dispatch.h", "tools/ghidra/CompareStartupDispatch.java"]
    if args.recover_table_registry:
        paths += ["src/table_resource_initialize.c", "src/table_resource_initialize.h", "src/resource_lifecycle.c",
                  "src/resource_lifecycle.h", "src/resource_bulk.c", "tools/ghidra/CompareTableResourceInitialize.java"]
    marker = {"reference_sha256": CODE_HASH, "binary_bytes": binary.stat().st_size, "binary_sha256": digest(binary),
              "comparison": comparison, "binary_matching": False, "original_binary_helpers_required": False,
              "files_sha256": {n: digest(ROOT / n) for n in paths}}
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(marker, indent=2) + "\n")
    print(json.dumps({"binary_bytes": marker["binary_bytes"], "comparison": comparison}))

if __name__ == "__main__":
    main()
