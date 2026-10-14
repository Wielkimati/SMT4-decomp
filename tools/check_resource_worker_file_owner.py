"""Build/compare concrete file ownership with persistent backend/prefix integration."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


MUTATIONS = {
    "length-limit": ("descriptor[2] > 512u", "descriptor[2] >= 512u"),
    "teardown-clear": ("mov r0, #0", "mov r0, #1"),
    "dispose-reload": ("mov r5, r0", "mov r5, r0\\nldr r7, [r0]"),
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
WAIT_TARGETS = (("smt4_diagnostic_wait_initialize", 0x2c5470, 0x2c54a4),
                ("smt4_diagnostic_wait", 0x2c367c, 0x2c373c))
WAIT_REUSED = (("smt4_resource_base_lock_initialize", 0x138f44, 0x138f5c),
               ("smt4_signal_arbitrate", 0x2a88fc, 0x2a8914))
WAIT_MUTATIONS = {
    "wait-r2-incoming": ("((uint64_t)payload << 32) | 1u", "((uint64_t)(payload & 0u) << 32) | 1u"),
    "wait-r2-svc": ("state) >> 32)", "state) & UINT32_MAX)"),
    "wait-mode": ("mode != 0", "mode == 1"),
    "wait-return": ("return observed;", "return value;"),
    "wait-transition": ('"r" (UINT32_MAX)', '"r" (1u)'),
    "wait-clrex": ('__asm__ volatile ("clrex" : : : "memory");', '/* deliberately omitted CLREX */'),
    "wait-direct": ("if (value == UINT32_MAX - 1u)", "if (value == UINT32_MAX)"),
}
DIAGNOSTIC_TARGETS = (("smt4_worker_diagnostic", 0x2bbd70, 0x2bbd98),
                      ("smt4_diagnostic_deliver", 0x2ad7e8, 0x2ad8f0),
                      ("smt4_diagnostic_process", 0x144900, 0x144918),
                      ("smt4_diagnostic_request", 0x146964, 0x14699c),
                      ("smt4_diagnostic_copy", 0x2bcfac, 0x2bd020))
DIAGNOSTIC_MUTATIONS = {
    "diagnostic-record": ("smt4_diagnostic_global.magic = UINT16_C(0xBCA3)", "smt4_diagnostic_global.magic = UINT16_C(0xBCA2)"),
    "diagnostic-reload": ("= smt4_diagnostic_handle;\n            if (closing", "= handle;\n            if (closing"),
    "diagnostic-retry": ("record->type == 2", "record->type == 5"),
    "diagnostic-publish": ("    *output = value;", "    if (!(result >> 31)) *output = value;"),
    "diagnostic-copy": ("record, 128);", "record, 124);"),
}
SETUP_MUTATIONS = {
    "setup-signed": ("(int32_t)count > 0", "count > 0u"),
    "setup-retry": ("(result & 1023u) != 1018u", "(result & 1023u) != 1019u"),
    "setup-increment": ("smt4_service_manager_count = (int32_t)((uint32_t)smt4_service_manager_count + 1u);", "if (!(result >> 31)) smt4_service_manager_count = (int32_t)((uint32_t)smt4_service_manager_count + 1u);"),
    "setup-publish": ("    *output = handle;", "    if (!(result >> 31)) *output = handle;"),
}
SETUP_TARGETS = (("smt4_worker_service_setup", 0x2c15c4, 0x2c161c),
                 ("smt4_service_manager_connect", 0x11cd48, 0x11cdd8),
                 ("smt4_service_manager_register", 0x129510, 0x129544),
                 ("smt4_service_connect_port", 0x1382cc, 0x1382e4))
ACQUISITION_MUTATIONS = {
    "acquire-signed": ("(int32_t)length > 8", "length > 8u"),
    "acquire-publish": ("    *output = command[3];", "    if (!(command[1] >> 31)) *output = command[3];"),
    "acquire-copy": ("uint32_t high = source[1];", "uint32_t high = source[0];"),
    "length-lane": ("cursor - start + lane", "cursor - start + 3 - lane"),
}
ACQUISITION_TARGETS = (("smt4_worker_service_acquire", 0x2c1590, 0x2c15b8),
                       ("smt4_service_name_copy", 0x2adba4, 0x2adbb8),
                       ("smt4_worker_service_name_length", 0x2c32e4, 0x2c3340))
STARTUP_MUTATIONS = {
    "startup-pointer": ("&smt4_worker_service_state[2]", "&smt4_worker_service_state[0]"),
    "startup-reload": ("smt4_worker_service_initialize(smt4_worker_service_state[1]);", "smt4_worker_service_initialize(result);"),
    "startup-header": ("0x08620040", "0x08620041"),
    "startup-accessor": ("smt4_resource_pool_query_service()", "smt4_worker_service_state[1]"),
}
STARTUP_TARGETS = (("smt4_worker_service_startup", 0x10f5b8, 0x10f664),
                   ("smt4_worker_service_state_request", 0x11ba80, 0x11baac),
                   ("smt4_worker_service_publish", 0x11bab0, 0x11babc),
                   ("smt4_resource_pool_query_service", 0x2bbd3c, 0x2bbd64))
INITIALIZE_MUTATIONS = {
    "initialize-header": ("0x08610042", "0x08610043"),
    "initialize-kernel": ("if (result >> 31)", "if (result != 0)"),
    "initialize-return": ("    return 0;", "    return 1;"),
    "initialize-global": ("state[4] = service", "state[3] = service"),
}
INITIALIZE_TARGETS = (("smt4_worker_service_request", 0x1272d4, 0x127308),
                      ("smt4_worker_service_initialize", 0x11ba54, 0x11ba78))
DESCRIPTOR_MUTATIONS = {
    "descriptor-size": ("7, 2, descriptor, 12", "7, 2, descriptor, 8"),
    "descriptor-capture": ("object[1] = service;", "object[1] = smt4_worker_backend_state[4];"),
    "descriptor-failure": ("if (result >> 31)\n        return result;", "if (result >> 31) { *output = 0; return result; }"),
    "descriptor-layout": ("output->selector = (uint8_t)selector;", "output->selector = (uint8_t)(selector >> 8);"),
    "descriptor-rollback": ("vtable[0x30 / 4]", "vtable[0x34 / 4]"),
    "descriptor-high": ("object[3] = (uint32_t)(handle >> 32);", "object[3] = (uint32_t)handle;"),
}
DESCRIPTOR_TARGETS = (
    ("smt4_worker_backend_create_descriptor", 0x127220, 0x1272c4),
    ("smt4_worker_archive_descriptor_make", 0x2b5fcc, 0x2b5fe4),
    ("smt4_worker_backend_register_descriptor", 0x11b860, 0x11b8d0),
)
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
    parser.add_argument("--mutant", choices=(*MUTATIONS, *SERVICE_MUTATIONS, *ARCHIVE_MUTATIONS, *DESCRIPTOR_MUTATIONS, *INITIALIZE_MUTATIONS, *STARTUP_MUTATIONS, *ACQUISITION_MUTATIONS, *SETUP_MUTATIONS, *DIAGNOSTIC_MUTATIONS, *WAIT_MUTATIONS))
    parser.add_argument("--recover-services", action="store_true")
    parser.add_argument("--recover-archive-services", action="store_true", help="Implies --recover-services")
    parser.add_argument("--recover-descriptor", action="store_true", help="Recover descriptor archive factory; implies archive services and clear")
    parser.add_argument("--recover-initialize", action="store_true", help="Service publication/request; implies descriptor recovery")
    parser.add_argument("--recover-startup", action="store_true", help="Connected service startup; implies initialize recovery")
    parser.add_argument("--recover-acquisition", action="store_true", help="Replace startup acquisition/length models; implies startup recovery")
    parser.add_argument("--recover-setup", action="store_true", help="Recover setup/connect/register; implies acquisition recovery")
    parser.add_argument("--recover-diagnostic", action="store_true", help="Diagnostic record/delivery/request/copy; implies setup recovery; lower waits remain modeled")
    parser.add_argument("--recover-diagnostic-wait", action="store_true", help="Recover lower wait/init; implies diagnostic; kernel arbitration remains modeled")
    args = parser.parse_args()
    if args.recover_diagnostic_wait:
        args.recover_diagnostic = True
    if args.mutant in WAIT_MUTATIONS and not args.recover_diagnostic_wait:
        parser.error("Wait mutations require --recover-diagnostic-wait")
    if args.recover_diagnostic:
        args.recover_setup = True
    if args.mutant in DIAGNOSTIC_MUTATIONS and not args.recover_diagnostic:
        parser.error("Diagnostic mutations require --recover-diagnostic")
    if args.recover_setup:
        args.recover_acquisition = True
    if args.mutant in SETUP_MUTATIONS and not args.recover_setup:
        parser.error("Setup mutations require --recover-setup")
    if args.recover_acquisition:
        args.recover_startup = True
    if args.mutant in ACQUISITION_MUTATIONS and not args.recover_acquisition:
        parser.error("Acquisition mutations require --recover-acquisition")
    if args.recover_startup:
        args.recover_initialize = True
    if args.mutant in STARTUP_MUTATIONS and not args.recover_startup:
        parser.error("Startup mutations require --recover-startup")
    if args.recover_initialize:
        args.recover_descriptor = True
    if args.mutant in INITIALIZE_MUTATIONS and not args.recover_initialize:
        parser.error("Initialization mutations require --recover-initialize")
    if args.recover_descriptor:
        args.recover_archive_services = args.recover_clear = True
    if args.mutant in DESCRIPTOR_MUTATIONS and not args.recover_descriptor:
        parser.error("Descriptor mutations require --recover-descriptor")
    if args.recover_archive_services:
        args.recover_services = True
    if args.mutant in ARCHIVE_MUTATIONS and not args.recover_archive_services:
        parser.error("Archive mutations require --recover-archive-services")
    if args.mutant in SERVICE_MUTATIONS and not args.recover_services:
        parser.error("IPC mutations require --recover-services")
    targets = TARGETS + SERVICE_TARGETS if args.recover_services else TARGETS
    if args.recover_archive_services:
        targets += ARCHIVE_TARGETS
    if args.recover_descriptor:
        targets += DESCRIPTOR_TARGETS
    if args.recover_initialize:
        targets += INITIALIZE_TARGETS
    if args.recover_startup:
        targets += STARTUP_TARGETS
    if args.recover_acquisition:
        targets += ACQUISITION_TARGETS
    if args.recover_setup:
        targets += SETUP_TARGETS
    if args.recover_diagnostic:
        targets += DIAGNOSTIC_TARGETS
    if args.recover_diagnostic_wait:
        targets += WAIT_TARGETS
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
    descriptor_source = ROOT / "src/resource_worker_archive_descriptor.c"
    initialize_source = ROOT / "src/resource_worker_service_initialize.c"
    startup_source = ROOT / "src/resource_worker_service_startup.c"
    acquisition_source = ROOT / "src/resource_worker_service_acquire.c"
    setup_source = ROOT / "src/resource_worker_service_setup.c"
    diagnostic_source = ROOT / "src/resource_worker_diagnostic.c"
    wait_source = ROOT / "src/resource_diagnostic_wait.c"
    if args.mutant in WAIT_MUTATIONS:
        old, new = WAIT_MUTATIONS[args.mutant]
        content = wait_source.read_text()
        if old not in content: raise RuntimeError("Wait mutation anchor")
        wait_source = output / wait_source.name
        wait_source.write_text(content.replace(old, new))
    elif args.mutant in DIAGNOSTIC_MUTATIONS:
        old, new = DIAGNOSTIC_MUTATIONS[args.mutant]
        content = diagnostic_source.read_text()
        if old not in content: raise RuntimeError("Diagnostic mutation anchor")
        diagnostic_source = output / diagnostic_source.name
        diagnostic_source.write_text(content.replace(old, new))
    elif args.mutant in SETUP_MUTATIONS:
        old, new = SETUP_MUTATIONS[args.mutant]
        content = setup_source.read_text()
        if old not in content: raise RuntimeError("Setup mutation anchor")
        setup_source = output / setup_source.name
        setup_source.write_text(content.replace(old, new))
    elif args.mutant in ACQUISITION_MUTATIONS:
        old, new = ACQUISITION_MUTATIONS[args.mutant]
        content = acquisition_source.read_text()
        if old not in content: raise RuntimeError("Acquisition mutation anchor")
        acquisition_source = output / acquisition_source.name
        acquisition_source.write_text(content.replace(old, new))
    elif args.mutant in STARTUP_MUTATIONS:
        old, new = STARTUP_MUTATIONS[args.mutant]
        content = startup_source.read_text()
        if old not in content: raise RuntimeError("Startup mutation anchor")
        startup_source = output / startup_source.name
        startup_source.write_text(content.replace(old, new))
    elif args.mutant in INITIALIZE_MUTATIONS:
        old, new = INITIALIZE_MUTATIONS[args.mutant]
        content = initialize_source.read_text()
        if old not in content: raise RuntimeError("Initialize mutation anchor")
        initialize_source = output / initialize_source.name
        initialize_source.write_text(content.replace(old, new))
    elif args.mutant in DESCRIPTOR_MUTATIONS:
        old, new = DESCRIPTOR_MUTATIONS[args.mutant]
        content = descriptor_source.read_text()
        if old not in content:
            raise RuntimeError("Descriptor mutation anchor")
        descriptor_source = output / descriptor_source.name
        descriptor_source.write_text(content.replace(old, new))
    elif args.mutant in ARCHIVE_MUTATIONS:
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
        content = content.replace(old, new)
        if args.mutant == "ipc-kernel":
            # Retain the old fault in both open C and close assembly bodies:
            # only zero kernel status may select the service result.
            anchor = "cmp r1, #0\\n\"\n    \"ldrge r0, [r4, #4]"
            if content.count(anchor) != 1:
                raise RuntimeError("Close IPC mutation anchor")
            content = content.replace(anchor, "cmp r0, #0\\n\"\n    \"ldreq r0, [r4, #4]")
        service_source.write_text(content)
    elif args.mutant:
        old, new = MUTATIONS[args.mutant]
        content = source.read_text()
        if old not in content:
            raise RuntimeError("Mutation anchor")
        content = content.replace(old, new)
        if args.mutant == "dispose-reload":
            content = content.replace("1: ldr r0, [r5]", "1: mov r0, r7")
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
         *([str(descriptor_source)] if args.recover_descriptor else []),
         *([str(initialize_source)] if args.recover_initialize else []),
         *([str(startup_source), str(ROOT / "src/resource_pool_query.c")] if args.recover_startup else []),
         *([str(acquisition_source)] if args.recover_acquisition else []),
         *([str(setup_source), str(ROOT / "src/resource_wait.c")] if args.recover_setup else []),
         *([str(diagnostic_source), str(ROOT / "src/resource_aligned_copy.c")] if args.recover_diagnostic else []),
         *([str(wait_source), str(ROOT / "src/resource_pool_initialize.c"),
            str(ROOT / "src/unsigned_quotient.c"), str(ROOT / "src/resource_arbitration.c")] if args.recover_diagnostic_wait else []),
         "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000", "-Wl,--entry=smt4_worker_backend_create",
         "-Wl,--build-id=none",
         *([f"-Wl,--defsym,{name}=smt4_worker_diagnostic" for name in
            ("smt4_worker_backend_diagnostic", "smt4_worker_service_diagnostic", "smt4_resource_pool_initialize_diagnostic")] if args.recover_diagnostic else []),
         *[f"-Wl,--defsym,{name}={address:#x}" for name, address in {
             **({"smt4_diagnostic_global": 0x4d4200, "smt4_diagnostic_handle": 0x44e608,
                 "smt4_diagnostic_constants": 0x407f9c, "smt4_diagnostic_lock": 0x4d4280,
                 **({"smt4_arbitration_handle": 0x471b58} if args.recover_diagnostic_wait else {"smt4_diagnostic_wait_initialize": 0x2c5470, "smt4_diagnostic_wait": 0x2c367c})} if args.recover_diagnostic else {}),
             **({"smt4_worker_service_state": 0x44e640, "smt4_worker_service_pointer": 0x471a68,
                 "smt4_worker_service_name": 0x407fb3,
                 **({"smt4_service_manager_lock": 0x4e9ba8, "smt4_service_manager_name": 0x40b6e4,
                     "smt4_file_sleep": 0x1382e4, "smt4_file_spin": 0x1382bc,
                     "smt4_file_wait_signal": 0x465024, "smt4_file_signal": 0x2c4298} if args.recover_setup else {"smt4_worker_service_setup": 0x2c15c4}),
                 **({"smt4_service_manager_count": 0x471b90, "smt4_service_manager_handle": 0x471ba4} if args.recover_acquisition else
                    {"smt4_worker_service_name_length": 0x2c32e4, "smt4_worker_service_acquire": 0x2c1590}),
                 **({} if args.recover_diagnostic else {"smt4_worker_service_diagnostic": 0x2bbd70, "smt4_resource_pool_initialize_diagnostic": 0x2bbd70})} if args.recover_startup else {}),
             "smt4_worker_file_pool": 0x4d4358, "smt4_worker_file_vtable": 0x420998,
             **({} if args.recover_services else {"smt4_worker_file_service_open": 0x356c28, "smt4_worker_file_service_close": 0x356d5c}),
             "smt4_worker_file_preclose": 0x2bce9c, "smt4_resource_release": 0x2c43b4,
             "smt4_worker_backend_state": 0x44e650, "smt4_worker_backend_pool": 0x4d431c,
             "smt4_worker_backend_vtable": 0x4209f8, "smt4_worker_prefix_table": 0x4d43e0,
             "smt4_worker_prefix_fallback": 0x407fbc, "smt4_worker_prefix_diagnostic": 0x2bce9c,
             **({} if args.recover_archive_services else {"smt4_worker_backend_archive_open": 0x2adbe8, "smt4_worker_backend_archive_close": 0x2adbb8}),
             "smt4_worker_backend_acquire": 0x2c3afc, "smt4_worker_backend_release": 0x2c3a78,
             **({} if args.recover_clear else {"smt4_worker_backend_clear": 0x139f54}),
             **({} if args.recover_diagnostic else {"smt4_worker_backend_diagnostic": 0x2bbd70}),
         }.items()], "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    for label, start, end in (*TARGETS[11:15], *(SERVICE_TARGETS if args.recover_services else ()), *(ARCHIVE_TARGETS if args.recover_archive_services else ()), *(DESCRIPTOR_TARGETS if args.recover_descriptor else ()), *(INITIALIZE_TARGETS if args.recover_initialize else ()), *(STARTUP_TARGETS if args.recover_startup else ()), *(ACQUISITION_TARGETS + (("acquisition_tail", 0x12954c, 0x1295a0),) if args.recover_acquisition else ()), *(SETUP_TARGETS + (("delay", 0x2bb4f0, 0x2bb518),) if args.recover_setup else ()), *(DIAGNOSTIC_TARGETS if args.recover_diagnostic else ()), *(WAIT_TARGETS + WAIT_REUSED if args.recover_diagnostic_wait else ())):
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
               *(["diagnostic-wait"] if args.recover_diagnostic_wait else ["diagnostic"] if args.recover_diagnostic else ["setup"] if args.recover_setup else ["acquisition"] if args.recover_acquisition else ["startup"] if args.recover_startup else ["initialize"] if args.recover_initialize else ["descriptor"] if args.recover_descriptor else ["archives"] if args.recover_archive_services else ["services"] if args.recover_services else []),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_FILE_OWNER_COMPARE_OK" in log or "File owner case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(wait_source if args.mutant in WAIT_MUTATIONS else diagnostic_source if args.mutant in DIAGNOSTIC_MUTATIONS else setup_source if args.mutant in SETUP_MUTATIONS else acquisition_source if args.mutant in ACQUISITION_MUTATIONS else startup_source if args.mutant in STARTUP_MUTATIONS else initialize_source if args.mutant in INITIALIZE_MUTATIONS else descriptor_source if args.mutant in DESCRIPTOR_MUTATIONS else archive_source if args.mutant in ARCHIVE_MUTATIONS else service_source if args.mutant in SERVICE_MUTATIONS else source),
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
                    "src/resource_worker_prefix.c", "src/resource_worker_prefix.h", "src/resource_break.h",
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
    if args.recover_descriptor:
        manifest["descriptor_factory"] = json.loads((output / "descriptor-factory.json").read_text())
        manifest["files_sha256"]["src/resource_worker_archive_descriptor.c"] = digest(ROOT / "src/resource_worker_archive_descriptor.c")
        manifest["method"] += "; descriptor factory recovered with concrete archive IPC and backend lifetime"
    if args.recover_initialize:
        manifest["service_initialize"] = json.loads((output / "service-initialize.json").read_text())
        manifest["files_sha256"]["src/resource_worker_service_initialize.c"] = digest(ROOT / "src/resource_worker_service_initialize.c")
        manifest["method"] += "; service publication and initialization request recovered"
    if args.recover_startup:
        manifest["service_startup"] = json.loads((output / "service-startup.json").read_text())
        for name in ("src/resource_worker_service_startup.c", "src/resource_worker_service_startup.h", "src/resource_worker_service_acquire.h", "src/resource_worker_service_setup.h", "src/resource_pool_query.c", "src/resource_pool_owner.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
        manifest["method"] += "; connected service startup recovered; setup, name length and acquisition modeled"
    if args.recover_acquisition:
        manifest["service_acquisition"] = json.loads((output / "service-acquisition.json").read_text())
        for name in ("src/resource_worker_service_acquire.c", "src/resource_worker_service_acquire.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
        manifest["method"] = manifest["method"].replace("setup, name length and acquisition modeled", "acquisition and name length recovered; setup/TLS/SVC/locks/diagnostics modeled")
    if args.recover_setup:
        manifest["service_setup"] = json.loads((output / "service-setup.json").read_text())
        for name in ("src/resource_worker_service_setup.c", "src/resource_worker_service_setup.h", "src/resource_wait.c", "src/resource_wait.h", "src/resource_sync.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
        manifest["method"] = manifest["method"].replace("setup/TLS/SVC/locks/diagnostics modeled", "setup/connect/register recovered; delay reused; TLS/kernel/sleep/locks/diagnostics modeled")
    if args.recover_diagnostic:
        manifest["diagnostic"] = json.loads((output / "diagnostic.json").read_text())
        for name in ("src/resource_worker_diagnostic.c", "src/resource_worker_diagnostic.h",
                     "src/resource_aligned_copy.c", "src/resource_aligned_copy.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
        manifest["method"] = manifest["method"].replace("TLS/kernel/sleep/locks/diagnostics modeled", "diagnostic record/delivery/process/request/copy recovered; TLS/kernel/sleep/locks/lower diagnostic waits modeled")
        manifest["comparison"]["services_svc_locks_diagnostics_modeled"] = False
        manifest["comparison"]["tls_kernel_locks_lower_waits_modeled"] = True
        (output / "comparison.json").write_text(json.dumps(manifest["comparison"], indent=2) + "\n")
    if args.recover_diagnostic_wait:
        manifest["diagnostic_wait"] = json.loads((output / "diagnostic-wait.json").read_text())
        for name in ("src/resource_diagnostic_wait.c", "src/resource_pool_initialize.c", "src/resource_pool_initialize.h", "src/unsigned_quotient.c", "src/unsigned_quotient.h", "src/resource_arbitration.c", "src/resource_signal.h"):
            manifest["files_sha256"][name] = digest(ROOT / name)
        manifest["method"] = manifest["method"].replace("lower diagnostic waits modeled", "diagnostic wait/init recovered; base initialization/arbitration source reused; exclusive outcomes/kernel arbitration modeled")
        for section, filename in (("diagnostic", "diagnostic.json"), ("descriptor_factory", "descriptor-factory.json"), ("service_initialize", "service-initialize.json"), ("service_startup", "service-startup.json"), ("service_acquisition", "service-acquisition.json"), ("service_setup", "service-setup.json")):
            manifest[section] = {(k.replace("lower_diagnostic_waits_", "").replace("lower_waits_", "") if k.endswith("_modeled") else "recovered_waits_both" if k == "lower_waits_both" else k): v for k, v in manifest[section].items()}
            (output / filename).write_text(json.dumps(manifest[section], indent=2) + "\n")
        manifest["comparison"].pop("tls_kernel_locks_lower_waits_modeled", None)
        manifest["comparison"]["tls_kernel_locks_exclusive_outcomes_modeled"] = True
        (output / "comparison.json").write_text(json.dumps(manifest["comparison"], indent=2) + "\n")
    check_hash(code, CODE_HASH)
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"binary_bytes": manifest["binary_bytes"], "comparison": comparison}))


if __name__ == "__main__":
    main()
