"""Build/compare read-service chain and pre-read delay through the lower read loop."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

TARGETS = (
    ("smt4_worker_file_read_service", 0x2a4e54, 0x2a4eb0),
    ("smt4_worker_file_read_method", 0x3564a8, 0x3564e8),
    ("smt4_worker_file_service_read", 0x356d04, 0x356d58),
    ("smt4_worker_file_pre_read_delay", 0x2adc48, 0x2adcd0),
    ("smt4_worker_file_handle", 0x239cd0, 0x239cf4),
    ("smt4_worker_file_read_lower", 0x2bb864, 0x2bb8ec),
    ("smt4_worker_file_read", 0x354f9c, 0x354fa4),
    ("smt4_unsigned_quotient", 0x2c6c64, 0x2c6c94),
    ("smt4_file_delay", 0x2bb4f0, 0x2bb518),
)
MUTANTS = {
    "null": ("handle == 0 || buffer == 0", "handle == 0 && buffer == 0"),
    "slot": ("vtable[0]", "vtable[1]"),
    "descriptor": ("(bytes << 4) | 12u", "(bytes << 4) | 10u"),
    "kernel": ("if (result >> 31)", "if (result != 0)"),
    "publish": ("    *received = command[2];", "    if (!(command[1] >> 31)) *received = command[2];"),
    "truncate": ("(base + extra) & UINT32_C(0xffff)", "(base & UINT32_C(0xffff)) + extra"),
    "numerator": ("mode != 0 ? 100u : 380u", "mode != 0 ? 380u : 100u"),
}



def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True)
    p.add_argument("--mutant", choices=MUTANTS)
    args = p.parse_args()
    out = local_path(args.output)
    if out.exists():
        raise FileExistsError("Choose fresh local output")
    code = ROOT / "local/reference-eu/base/0000/exefs/code.bin"
    check_hash(code, CODE_HASH)
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    td = ROOT / pins["directory"] / "bin"
    for name, h in pins["executables"].items():
        check_hash(td / name, h)
    java = java_command()
    out.mkdir(parents=True)
    sources = [ROOT / "src" / name for name in (
        "resource_worker_file_read_service.c", "resource_worker_file_owner.c",
        "resource_worker_file_read.c", "resource_worker_file_methods.c", "resource_wait.c", "unsigned_quotient.c")]
    if args.mutant:
        old, new = MUTANTS[args.mutant]
        content = sources[0].read_text()
        assert content.count(old) == 1
        sources[0] = out / "mutant.c"
        sources[0].write_text(content.replace(old, new))
    elf, binary = out / "read-service.elf", out / "read-service.bin"
    run([str(td / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-fno-inline", "-march=armv6k", "-marm",
         "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-Wall", "-Wextra", "-Werror",
         "-nostdlib", *map(str, sources), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_worker_file_read_service", "-Wl,--gc-sections", "-Wl,--build-id=none",
         *[f"-Wl,--undefined={name}" for name, _, _ in TARGETS],
         "-Wl,--defsym,smt4_worker_backend_diagnostic=0x2bbd70",
         "-Wl,--defsym,smt4_worker_file_diagnostic=0x2bbd70",
         "-Wl,--defsym,smt4_worker_file_delay_state=0x44e650",
         "-Wl,--defsym,smt4_file_sleep=0x1382e4", "-Wl,--defsym,smt4_file_spin=0x1382bc", "-o", str(elf)], out, "build")
    run([str(td / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", str(elf), str(binary)], out, "objcopy")
    run([str(td / "arm-none-eabi-objdump.exe"), "-d", str(elf)], out, "disassembly")
    symbols = run([str(td / "arm-none-eabi-nm.exe"), "-n", "-S", str(elf)], out, "symbols")
    assert " U " not in symbols
    entries = {row.split()[3]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 4 and row.split()[2] == "T"}
    (out / "entries.txt").write_text("".join(f"{entries[name]}\n" for name, _, _ in TARGETS))
    for name, start, end in TARGETS[:4]:
        run([str(td / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}", str(code)], out, name)
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(ROOT / "local/ghidra/smt4-eu"),
               "SMT4-EU", "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceWorkerFileReadService.java", str(out), "-log", str(out / "ghidra.log")], out, "comparison")
    if args.mutant:
        if "SMT4_READ_SERVICE_COMPARE_OK" in log or "Read service case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by a case assertion")
        result = {"mutant": args.mutant, "rejected": True, "binary_sha256": digest(binary),
                  "source_sha256": digest(sources[0]),
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (out / "NEGATIVE.json").write_text(json.dumps(result, indent=2) + "\n")
    else:
        if "SMT4_READ_SERVICE_COMPARE_OK" not in log:
            raise RuntimeError("Comparison failed; inspect comparison.log")
        comparison = json.loads((out / "comparison.json").read_text())
        assert comparison["new_instruction_sites"] == 94 and comparison["persistent_sequences"] > 0
        files = ["src/" + name for name in (
            "resource_worker_file_read_service.c", "resource_worker_file_owner.c", "resource_worker_file_owner.h",
            "resource_worker_file_methods.c", "resource_worker_file_methods.h", "resource_worker_file_read.c",
            "resource_wait.c", "resource_wait.h", "unsigned_quotient.c", "unsigned_quotient.h")]
        files += ["tools/check_resource_worker_read_service.py", "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                  "config/recovery-tools.json", "config/analysis-tools.json"]
        files += ["tools/ghidra/" + name + ".java" for name in (
            "CompareResourceWorkerFileReadService", "CompareResourceWorkerFileRead", "CompareResourceWorkerFilePosition",
            "CompareResourceWorkerFileMethods", "CompareResourceWorkerAllocation", "CompareResourceWorkerIo",
            "CompareResourceSync", "CompareResourceLifecycle")]
        result = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "comparison": comparison, "new_recovered_contracts": 4, "aggregate_read_service_model_removed": True,
                  "tls_svc_sleep_diagnostics_modeled": True, "binary_matching": False, "live_verified": False,
                  "original_binary_helpers_required": False,
                  "files_sha256": {name: digest(ROOT / name) for name in files}}
        check_hash(code, CODE_HASH)
        (out / "COMPLETE.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "files_sha256"}))


if __name__ == "__main__":
    main()
