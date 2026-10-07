"""Build/compare synchronous loading including signal/locks; OS boundaries remain modeled."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

NAMES = ["smt4_resource_load_sync", "smt4_resource_load", "smt4_file_mark_cleanup",
         "smt4_file_set_flags", "smt4_file_set_parameter", "smt4_file_failed",
         "smt4_file_create", "smt4_file_wait", "smt4_file_delay",
         "smt4_file_signal", "smt4_signal_lock_acquire", "smt4_signal_lock_release"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--recover-arbitration", action="store_true",
                        help="Execute arbitration marshalling; intercept only SVC 0x22")
    args = parser.parse_args()
    output, project = local_path(args.output), local_path(args.project_dir)
    if output.exists():
        raise FileExistsError("Choose new output under local/")
    if not (project / "SMT4-EU.gpr").is_file():
        raise FileNotFoundError("Saved EU project required")
    check_hash(ROOT / "local/reference-eu/base/0000/exefs/code.bin", CODE_HASH)
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    tool_dir = ROOT / pins["directory"] / "bin"
    for name, expected in pins["executables"].items():
        check_hash(tool_dir / name, expected)
    java = java_command()
    output.mkdir(parents=True)
    elf, binary = output / "resource-chain-signal.elf", output / "resource-chain-signal.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(ROOT / "src/resource_sync.c"), str(ROOT / "src/resource_descriptor.c"),
         str(ROOT / "src/resource_create.c"), str(ROOT / "src/resource_wait.c"),
         str(ROOT / "src/resource_signal.c"), str(ROOT / "src/resource_lock.c"),
         *([str(ROOT / "src/resource_arbitration.c")] if args.recover_arbitration else []),
         "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_resource_load_sync", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_resource_path_mode=0x465040",
         "-Wl,--defsym,smt4_resource_path_format=0x409740",
         "-Wl,--defsym,smt4_resource_clear=0x2c3b98",
         "-Wl,--defsym,smt4_resource_path_has_prefix=0x2b0674",
         "-Wl,--defsym,smt4_resource_format=0x2be850",
         "-Wl,--defsym,smt4_file_sync_handle=0x465010",
         "-Wl,--defsym,smt4_file_list_head=0x46500c",
         "-Wl,--defsym,smt4_file_path_format=0x2b066c",
         "-Wl,--defsym,smt4_file_acquire=0x2c4350",
         "-Wl,--defsym,smt4_file_release=0x2c54a4",
         "-Wl,--defsym,smt4_file_check_result=0x2c54bc",
         "-Wl,--defsym,smt4_file_allocate=0x2c4bd8",
         "-Wl,--defsym,smt4_file_clear=0x2c4b84",
         "-Wl,--defsym,smt4_file_path_length=0x2c32e4",
         "-Wl,--defsym,smt4_file_path_copy=0x2bf8c0",
         "-Wl,--defsym,smt4_file_wait_signal=0x465024",
         "-Wl,--defsym,smt4_arbitration_handle=0x471b58",
         *([] if args.recover_arbitration else ["-Wl,--defsym,smt4_signal_arbitrate=0x2a88fc"]),
         "-Wl,--defsym,smt4_file_sleep=0x1382e4",
         "-Wl,--defsym,smt4_file_spin=0x1382bc",
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    # Independent disassembler evidence for every recovered original entry.
    for start, stop in ((0x2c5e90, 0x2c5fa4), (0x2c3344, 0x2c334c),
                        (0x2b0468, 0x2b0494), (0x14e634, 0x14e648),
                        (0x14e744, 0x14e760), (0x2b0494, 0x2b0630),
                        (0x1181b0, 0x1181f4), (0x2bb4f0, 0x2bb520),
                        (0x2c4298, 0x2c4350), (0x1464f8, 0x1465d8),
                        (0x138fc0, 0x139010), (0x2a88fc, 0x2a8914)):
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start}", f"--stop-address={stop}",
             str(ROOT / "local/reference-eu/base/0000/exefs/code.bin")],
            output, f"original-{start:08x}-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    names = NAMES + (["smt4_signal_arbitrate"] if args.recover_arbitration else [])
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in names))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceChainSignal.java",
               str(output), *(["svc"] if args.recover_arbitration else []),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if "SMT4_CHAIN_SIGNAL_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["chain_cases"] != 3924 or comparison["pending_prefix_cases"] != 265
            or comparison["signal_pending_prefix_cases"] != 36
            or comparison["original_instruction_addresses"] != (341 if args.recover_arbitration else 335)
            or comparison["arbitration_intercepted"] == args.recover_arbitration
            or comparison["svc_intercepted"] != args.recover_arbitration
            or comparison["arbitration_calls_both_paths"] != 43270
            or comparison["wrapper_returns_both_paths"] != (43270 if args.recover_arbitration else 0)):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "synchronous_orchestration_implemented": True, "signal_locks_implemented": True, "file_io_allocation_implemented": False,
                "arbitration_marshalling_implemented": args.recover_arbitration,
                "method": "Original/rebuilt ARM synchronous chain including signal/locks; exclusives scheduled; allocation/OS/strings/timing modeled; " +
                          ("arbitration wrapper executes through SVC" if args.recover_arbitration else "arbitration wrapper modeled"),
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_sync.c", "src/resource_sync.h", "src/resource_descriptor.c",
                    "src/resource_create.c", "src/resource_create.h", "src/resource_wait.c", "src/resource_wait.h",
                    "src/resource_signal.c", "src/resource_lock.c", "src/resource_signal.h",
                    "tools/check_resource_chain_signal.py", "tools/ghidra/CompareResourceChainSignal.java",
                    "tools/ghidra/CompareResourceChain.java", "tools/ghidra/CompareResourceSignalLock.java",
                    "tools/ghidra/CompareResourceSync.java", "tools/ghidra/CompareResourceCreate.java",
                    "tools/ghidra/CompareResourceLifecycle.java",
                    "config/recovery-tools.json", "config/analysis-tools.json",
                    *(["src/resource_arbitration.c"] if args.recover_arbitration else []))}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
