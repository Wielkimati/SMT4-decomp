"""Build and compare the EU worker's adapted state-zero I/O region."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    parser.add_argument("--mutant", choices=("open-early-return", "flags-bit-test", "short-read-size", "cached-close-handle", "advance-failed-conversion"))
    args = parser.parse_args()
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
    source = ROOT / "src/resource_worker_io.c"
    if args.mutant:
        edits = {
            "open-early-return": ("if (result >> 31)\n        d[0] = 5;\n    o = object(d);\n    d[6]", "if (result >> 31) { d[0] = 5; return; }\n    o = object(d);\n    d[6]"),
            "flags-bit-test": ("(flags == 1 || flags == 17)", "(flags & 1)"),
            "short-read-size": ("smt4_worker_io_busy = 0;", "d[6] = bytes_read;\n    smt4_worker_io_busy = 0;"),
            "cached-close-handle": ("if (o[1] & 1)\n            smt4_worker_file_preclose(o[1]);\n        smt4_worker_file_close(o[1] & ~UINT32_C(1));", "uint32_t saved = o[1];\n        if (saved & 1)\n            smt4_worker_file_preclose(saved);\n        smt4_worker_file_close(saved & ~UINT32_C(1));"),
            "advance-failed-conversion": ("break;\n        ++out;", "{ ++out; break; }\n        ++out;"),
        }
        old, new = edits[args.mutant]
        text = source.read_text()
        if text.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        source = output / "mutant.c"
        source.write_text(text.replace(old, new))
    elf, binary = output / "resource-worker-io.elf", output / "resource-worker-io.bin"
    definitions = {
        "smt4_worker_file_construction": 0x420870,
        "smt4_worker_io_lock_handle": 0x465124,
        "smt4_worker_io_busy": 0x465004,
        "smt4_worker_object_allocate": 0x2c244c,
        # Synthetic ARM call boundaries for the original Thumb helpers.
        "smt4_worker_path_reset": 0x710000,
        "smt4_worker_path_measure": 0x710004,
        "smt4_worker_path_convert": 0x710008,
        "smt4_worker_file_open": 0x2bb944,
        "smt4_worker_data_allocate": 0x2bf7ec,
        "smt4_worker_io_acquire": 0x2c3afc,
        "smt4_worker_io_release": 0x2c3a78,
        "smt4_worker_file_preclose": 0x2bce9c,
        "smt4_worker_file_close": 0x2b9450,
    }
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_worker_state0_io", "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}={address:#x}" for name, address in definitions.items()],
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
         "--adjust-vma=0x100000", "--start-address=0x113e80", "--stop-address=0x114134",
         str(code)], output, "original-disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    (output / "entries.txt").write_text(f"{entries['smt4_worker_state0_io']}\n")
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceWorkerIo.java",
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_WORKER_IO_COMPARE_OK" in log:
            raise RuntimeError("Mutant survived")
        if "Worker I/O case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Failure was not an asserted corpus rejection")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(source)}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_WORKER_IO_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    if comparison["io_cases"] != 3456 or comparison["original_instruction_addresses"] != 163:
        raise RuntimeError("Incomplete comparison corpus")
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "method": "Adapted state-zero region; lower file/path/allocation/locking modeled; successful object allocation",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/resource_worker_io.c", "src/resource_worker_io.h",
                    "tools/check_resource_worker_io.py", "tools/ghidra/CompareResourceWorkerIo.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra/CompareResourceSync.java",
                    "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
                    "config/recovery-tools.json", "config/analysis-tools.json")}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
