"""Build/compare pooled-resource ownership with concrete allocation and construction."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "publish": ("*output = object;", "*output = 0;"),
    "cleanup": ("dispose(file, 0x2c);", "dispose(file, 0x30);"),
    "constructor": ("w[60] = UINT32_MAX;", "w[60] = 0;"),
}
REQUEST_MUTATIONS = {
    "request-descriptor": ("(size1 << 14) | 0x802u", "(size1 << 14) | 2u"),
    "request-publish": ("if (result & 0x80000000u)", "if ((result | command[1]) & 0x80000000u)"),
    "request-kernel": ("return result;", "return command[1];"),
}
OBJECT_INIT_MUTATIONS = {
    "init-capacity": ("if (required > capacity)", "if (required >= capacity)"),
    "init-offset": ("offset += received;", "offset += header[2 + 2*i];"),
    "init-slot": ("value < -8 ? 0", "value <= -8 ? 0"),
    "init-query-publish": ("if (result >> 31)\n        return result;\n    *output", "if ((result | command[1]) >> 31)\n        return result;\n    *output"),
}
TEARDOWN_MUTATIONS = {
    "teardown-slot": ("cmp r5, #5", "cmp r5, #4"),
    "teardown-link": ("str r0, [r2, #4]", "str r1, [r2, #4]"),
    "teardown-count": ("sub r0, r0, #1\\n", "add r0, r0, #1\\n"),
    "teardown-reload": ("ldr r6, [r0, #4]", "ldr r6, =0x004d42e0"),
    "teardown-entry-r2": ("ldr r0, =0x00420bc0", "mov r2, #0\\nldr r0, =0x00420bc0"),
    "teardown-return-r2": ('blne smt4_worker_prefix_diagnostic\\n"\n    "ldr r0, [r4, #16]', 'beq 3f\\npush {r2, r3}\\nbl smt4_worker_prefix_diagnostic\\npop {r2, r3}\\n3: ldr r0, [r4, #16]'),
}
ALTERNATE_MUTATIONS = {
    "alternate-layout": ("0, 3, 1, &data, 1, 2, descriptor, 12, 1, 0", "0, 3, 1, &data, 4, 2, descriptor, 12, 1, 0"),
    "alternate-self-reference": ("uint32_t data = (uint32_t)(uintptr_t)&data;", "uint32_t data = 1;"),
    "alternate-forward": ("object, file, a, b, c, d, e", "object, file, b, a, c, d, e"),
    "wrap-publish": ("if (file == 0) {", "if (file == 0) {\n        *output = 0;"),
    "wrap-handle": ("w[1] = handle;", "w[1] = 0;"),
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
    parser.add_argument("--mutant", choices=(*MUTATIONS, *REQUEST_MUTATIONS, *OBJECT_INIT_MUTATIONS, *TEARDOWN_MUTATIONS, *ALTERNATE_MUTATIONS))
    parser.add_argument("--recover-request", action="store_true")
    parser.add_argument("--recover-initialize", action="store_true")
    parser.add_argument("--recover-teardown", action="store_true")
    parser.add_argument("--recover-alternate", action="store_true")
    parser.add_argument("--recover-teardown-break", action="store_true")
    args = parser.parse_args()
    if args.recover_alternate and args.recover_teardown_break:
        parser.error("Select alternate or connected teardown mode")
    if args.recover_alternate or args.recover_teardown_break:
        args.recover_teardown = True
    if args.mutant in ALTERNATE_MUTATIONS and not args.recover_alternate:
        parser.error("Alternate mutants require --recover-alternate")
    if args.recover_teardown:
        args.recover_initialize = True
    if args.recover_initialize:
        args.recover_request = True
    if args.mutant in OBJECT_INIT_MUTATIONS and not args.recover_initialize:
        parser.error("Initializer mutants require --recover-initialize")
    if args.mutant in TEARDOWN_MUTATIONS and not args.recover_teardown:
        parser.error("Teardown mutants require --recover-teardown")
    if args.mutant in {"teardown-entry-r2", "teardown-return-r2"} and not args.recover_teardown_break:
        parser.error("Register-transport mutants require --recover-teardown-break")
    if args.mutant in REQUEST_MUTATIONS and not args.recover_request:
        parser.error("Request mutants require --recover-request")
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
    source = ROOT / "src/resource_pool_owner.c"
    request_source = ROOT / "src/resource_pool_request.c"
    init_source = ROOT / "src/resource_pool_object_initialize.c"
    query_source = ROOT / "src/resource_pool_query.c"
    teardown_source = ROOT / "src/resource_pool_object_teardown.c"
    alternate_source = ROOT / "src/resource_pool_alternate.c"
    if args.mutant in ALTERNATE_MUTATIONS:
        old, new = ALTERNATE_MUTATIONS[args.mutant]
        content = alternate_source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        alternate_source = output / alternate_source.name
        alternate_source.write_text(content.replace(old, new))
    if args.mutant in TEARDOWN_MUTATIONS:
        old, new = TEARDOWN_MUTATIONS[args.mutant]
        content = teardown_source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        teardown_source = output / teardown_source.name
        teardown_source.write_text(content.replace(old, new))
    if args.mutant in OBJECT_INIT_MUTATIONS:
        old, new = OBJECT_INIT_MUTATIONS[args.mutant]
        mutation_source = query_source if args.mutant == "init-query-publish" else init_source
        content = mutation_source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        mutation_output = output / mutation_source.name
        mutation_output.write_text(content.replace(old, new))
        if args.mutant == "init-query-publish":
            query_source = mutation_output
        else:
            init_source = mutation_output
    if args.mutant in REQUEST_MUTATIONS:
        old, new = REQUEST_MUTATIONS[args.mutant]
        content = request_source.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        request_source = output / request_source.name
        request_source.write_text(content.replace(old, new))
    if args.mutant in MUTATIONS:
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
         *([str(request_source)] if args.recover_request else []),
         *([str(init_source), str(query_source)] if args.recover_initialize else []),
         *([str(teardown_source), str(ROOT / "src/resource_worker_file_owner.c"),
            str(ROOT / "src/resource_worker_file_service.c")] if args.recover_teardown else []),
         *([str(alternate_source)] if args.recover_alternate else []),
         *([str(ROOT / "src/resource_break.c")] if args.recover_teardown_break else []),
         str(source), str(ROOT / "src/resource_lazy_pool.c"), str(ROOT / "src/resource_pool_initialize.c"), str(ROOT / "src/unsigned_quotient.c"), str(ROOT / "src/resource_worker_backend.c"), str(ROOT / "src/resource_worker_prefix.c"), str(ROOT / "src/resource_worker_file_open.c"),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_worker_backend_create",
         "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}={address:#x}" for name, address in {
             **({} if args.recover_request else {"smt4_resource_pool_owner_request": 0x2b5dd0}), **({"smt4_resource_pool_initialize_diagnostic": 0x2bbd70} if args.recover_initialize else {"smt4_resource_pool_owner_initialize": 0x145e9c}),
             "smt4_worker_backend_state": 0x44e650, "smt4_worker_backend_pool": 0x4d431c,
             **({"smt4_worker_file_pool": 0x4d4358, "smt4_worker_file_vtable": 0x420998} if args.recover_teardown else {}),
             "smt4_worker_backend_vtable": 0x4209f8, "smt4_worker_prefix_table": 0x4d43e0,
             "smt4_worker_prefix_fallback": 0x407fbc,
             **({"smt4_break_callback_slot": 0x44e450} if args.recover_teardown_break else {"smt4_worker_prefix_diagnostic": 0x2bce9c}),
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
    for label, start, end in (("query-service", 0x2bbd3c, 0x2bbd70), ("query-ipc", 0x14f42c, 0x14f464), ("object-init", 0x145e7c, 0x146284), ("request", 0x2b5dd0, 0x2b5e70), ("owner", 0x2adcd8, 0x2ade98), ("construct", 0x14636c, 0x146450), ("aligned-zero", 0x2c4b84, 0x2c4bd8)):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}",
             str(code)], output, f"original-{label}")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if args.recover_teardown:
        for label, start, end in (("object-teardown", 0x3567f0, 0x3568c8), ("pool-base-teardown", 0x2a458c, 0x2a45ec)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
                 "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}",
                 str(code)], output, f"original-{label}")
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
    (output / "lazy-entry.txt").write_text(str(entries["smt4_resource_lazy_pool_take"]))
    (output / "owner-entries.txt").write_text("".join(f"{entries[n]}\n" for n in
        ("smt4_resource_pool_owner_create", "smt4_resource_pool_object_construct", "smt4_resource_aligned_zero")))
    if args.recover_request:
        (output / "request-entry.txt").write_text(str(entries["smt4_resource_pool_owner_request"]))
    if args.recover_initialize:
        (output / "object-init-entries.txt").write_text("".join(f"{entries[n]}\n" for n in
            ("smt4_resource_pool_owner_initialize", "smt4_resource_pool_object_query",
             "smt4_resource_pool_query_service", "smt4_resource_pool_query_value")))
    if args.recover_teardown:
        (output / "teardown-entries.txt").write_text("".join(f"{entries[n]}\n" for n in
            ("smt4_resource_pool_object_dispose", "smt4_resource_pool_object_teardown",
             "smt4_resource_pool_base_teardown", "smt4_worker_file_dispose",
             "smt4_worker_file_teardown", "smt4_worker_file_service_close")))
    if args.recover_alternate:
        (output / "alternate-entries.txt").write_text("".join(f"{entries[n]}\n" for n in
            ("smt4_resource_pool_alternate_create", "smt4_resource_pool_wrap_handle")))
        for label, start, end in (("alternate", 0x1270c4, 0x127220), ("wrap", 0x3567a4, 0x3567f0)):
            run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
                 "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}",
                 str(code)], output, f"original-{label}")
    if args.recover_teardown_break:
        (output / "break-entry.txt").write_text(str(entries["smt4_worker_prefix_diagnostic"]))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", ("CompareResourcePoolTeardownBreak.java" if args.recover_teardown_break else "CompareResourcePoolAlternate.java" if args.recover_alternate else "CompareResourcePoolObjectTeardown.java" if args.recover_teardown else "CompareResourcePoolObjectInitialize.java" if args.recover_initialize else "CompareResourcePoolOwner.java"), str(output),
               "-log", str(output / "ghidra.log")], output, "comparison")
    success = "SMT4_POOL_TEARDOWN_BREAK_COMPARE_OK" if args.recover_teardown_break else "SMT4_POOL_OWNER_COMPARE_OK"
    if args.mutant:
        if success in log or "Pool owner case" not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by initialization assertion")
        marker = {"mutant": args.mutant, "rejected": True, "binary_sha256": digest(binary),
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if success not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    paths = ["src/resource_pool_owner.c", "src/resource_pool_owner.h", "tools/check_resource_pool_owner.py", "tools/ghidra/CompareResourcePoolOwner.java", "src/resource_lazy_pool.c", "src/resource_lazy_pool.h", "src/resource_pool_initialize.c", "src/resource_pool_initialize.h", "src/unsigned_quotient.c", "src/unsigned_quotient.h",
             "src/resource_worker_backend.c", "src/resource_worker_backend.h", "src/resource_recursive_lock.c", "src/resource_recursive_lock.h",
             "src/resource_lock.c", "src/resource_signal.h", "src/resource_clear.c", "src/resource_clear.h",
             "src/resource_worker_prefix.c", "src/resource_worker_prefix.h", "src/resource_break.h", "src/resource_worker_file_open.c", "src/resource_worker_file_open.h",
             "tools/check_resource_lazy_pool.py", "tools/ghidra/CompareResourceLazyPool.java",
             "tools/ghidra/CompareResourceWorkerBackend.java", "tools/ghidra/CompareResourceSync.java", "tools/ghidra/CompareResourceLifecycle.java",
             "tools/check_nkm_lookup.py", "tools/ghidra_reference.py", "config/analysis-tools.json", "config/recovery-tools.json"]
    if args.recover_request:
        paths.append("src/resource_pool_request.c")
    if args.recover_initialize:
        paths.extend(["src/resource_pool_object_initialize.c", "src/resource_pool_query.c", "tools/ghidra/CompareResourcePoolObjectInitialize.java"])
    if args.recover_teardown:
        paths.extend(["src/resource_pool_object_teardown.c", "src/resource_worker_file_owner.c", "src/resource_worker_file_owner.h",
                      "src/resource_worker_file_service.c", "tools/ghidra/CompareResourcePoolObjectTeardown.java"])
    if args.recover_teardown_break:
        paths.extend(["src/resource_break.c", "tools/ghidra/CompareResourcePoolTeardownBreak.java"])
    if args.recover_alternate:
        paths.extend(["src/resource_pool_alternate.c", "tools/ghidra/CompareResourcePoolAlternate.java"])
    marker = {"reference_sha256": CODE_HASH, "binary_bytes": binary.stat().st_size, "binary_sha256": digest(binary),
              "comparison": comparison, "binary_matching": False, "original_binary_helpers_required": False,
              "files_sha256": {n: digest(ROOT / n) for n in paths}}
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(marker, indent=2) + "\n")
    print(json.dumps({"binary_bytes": marker["binary_bytes"], "comparison": comparison}))

if __name__ == "__main__":
    main()
