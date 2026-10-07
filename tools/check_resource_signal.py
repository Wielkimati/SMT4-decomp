"""Build/compare signal with scheduled exclusive outcomes and modeled lock/arbitration boundaries."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

NAMES = ["smt4_file_signal"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
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
    elf, binary = output / "resource-signal.elf", output / "resource-signal.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(ROOT / "src/resource_signal.c"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_file_signal", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_arbitration_handle=0x471b58",
         "-Wl,--defsym,smt4_signal_lock_acquire=0x1464f8",
         "-Wl,--defsym,smt4_signal_lock_release=0x138fc0",
         "-Wl,--defsym,smt4_signal_arbitrate=0x2a88fc",
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    # Independent disassembler evidence for every recovered original entry.
    for start, stop in ((0x2c4298, 0x2c4350), (0x1464f8, 0x1465d8),
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
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in NAMES))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceSignal.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if "SMT4_SIGNAL_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if (comparison["signal_cases"] != 3352 or comparison["pending_prefix_cases"] != 24
            or comparison["original_instruction_addresses"] != 45):
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "signal_implemented": True,
                "file_io_allocation_implemented": False,
                "method": "Original/rebuilt ARM execution; exclusive outcomes scheduled; lock/arbitration modeled",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_signal.c", "src/resource_signal.h",
                    "tools/check_resource_signal.py", "tools/ghidra/CompareResourceSignal.java",
                    "tools/ghidra/CompareResourceLifecycle.java",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()

