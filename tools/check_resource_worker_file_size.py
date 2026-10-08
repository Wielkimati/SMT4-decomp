"""Build/compare file-size dispatch, concrete method and IPC through cache/seek."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

TARGETS = (
    ("smt4_worker_file_size_service", 0x2a8914, 0x2a893c),
    ("smt4_worker_file_size_method", 0x3dfca8, 0x3dfcc8),
    ("smt4_worker_file_service_size", 0x356de8, 0x356e1c),
    ("smt4_worker_file_handle", 0x239cd0, 0x239cf4),
    ("smt4_worker_file_size_lower", 0x2bb8ec, 0x2bb944),
    ("smt4_worker_file_seek_lower", 0x2aca78, 0x2acb24),
    ("smt4_worker_file_position", 0x146458, 0x1464f4),
    ("smt4_worker_file_size", 0x3dfc54, 0x3dfc80),
    ("smt4_worker_file_seek", 0x354f70, 0x354f9c),
)
MUTANTS = {
    "null": ("size == 0 || handle == 0", "size == 0 && handle == 0"),
    "slot": ("vtable[2]", "vtable[3]"),
    "high": ("uint32_t high = command[3];", "uint32_t high = command[2];"),
    "kernel": ("if (result >> 31)", "if (result != 0)"),
    "publish": ("    *(volatile uint64_t *)size =", "    if (!(command[1] >> 31)) *(volatile uint64_t *)size ="),
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
        "resource_worker_file_size_service.c", "resource_worker_file_owner.c",
        "resource_worker_file_position.c", "resource_worker_file_methods.c")]
    if args.mutant:
        old, new = MUTANTS[args.mutant]
        content = sources[0].read_text()
        assert content.count(old) == 1
        sources[0] = out / "mutant.c"
        sources[0].write_text(content.replace(old, new))
    elf, binary = out / "size.elf", out / "size.bin"
    run([str(td / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k", "-marm",
         "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-Wall", "-Wextra", "-Werror",
         "-nostdlib", *map(str, sources), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_worker_file_size_service", "-Wl,--gc-sections", "-Wl,--build-id=none",
         *[f"-Wl,--undefined={name}" for name, _, _ in TARGETS],
         "-Wl,--defsym,smt4_worker_backend_diagnostic=0x2bbd70",
         "-Wl,--defsym,smt4_worker_file_diagnostic=0x2bbd70", "-o", str(elf)], out, "build")
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
               "-postScript", "CompareResourceWorkerFileSize.java", str(out), "-log", str(out / "ghidra.log")], out, "comparison")
    if args.mutant:
        if "SMT4_FILE_SIZE_COMPARE_OK" in log or "File size case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by a case assertion")
        result = {"mutant": args.mutant, "rejected": True, "binary_sha256": digest(binary),
                  "source_sha256": digest(sources[0]),
                  "assertions": [line.strip() for line in log.splitlines() if "IllegalStateException:" in line]}
        (out / "NEGATIVE.json").write_text(json.dumps(result, indent=2) + "\n")
    else:
        if "SMT4_FILE_SIZE_COMPARE_OK" not in log:
            raise RuntimeError("Comparison failed; inspect comparison.log")
        comparison = json.loads((out / "comparison.json").read_text())
        assert comparison["new_instruction_sites"] == 31 and comparison["persistent_sequences"] > 0
        files = ["src/" + name for name in (
            "resource_worker_file_size_service.c", "resource_worker_file_owner.c", "resource_worker_file_owner.h",
            "resource_worker_file_methods.c", "resource_worker_file_methods.h", "resource_worker_file_position.c")]
        files += ["tools/check_resource_worker_file_size.py", "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                  "config/recovery-tools.json", "config/analysis-tools.json"]
        files += ["tools/ghidra/" + name + ".java" for name in (
            "CompareResourceWorkerFileSize", "CompareResourceWorkerFilePosition", "CompareResourceWorkerFileMethods",
            "CompareResourceWorkerAllocation", "CompareResourceWorkerIo", "CompareResourceSync", "CompareResourceLifecycle")]
        result = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary), "binary_bytes": binary.stat().st_size,
                  "comparison": comparison, "new_recovered_contracts": 3, "size_service_call_model_removed": True,
                  "tls_svc_diagnostics_modeled": True, "binary_matching": False, "live_verified": False,
                  "original_binary_helpers_required": False,
                  "files_sha256": {name: digest(ROOT / name) for name in files}}
        check_hash(code, CODE_HASH)
        (out / "COMPLETE.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "files_sha256"}))


if __name__ == "__main__":
    main()
