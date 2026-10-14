"""Build/compare table reload; optionally recover its concrete copy dependency."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

NAMES = ["smt4_table_resource_reload", "smt4_table_reload_state_set",
         "smt4_table_reload_state_get", "smt4_table_reload_gate", "smt4_table_resource_initialize"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--recover-copy", action="store_true")
    parser.add_argument("--mutant", choices=["restore", "signed-state", "publish-size",
                                           "copy-prefix", "copy-group", "copy-half"])
    parser.add_argument("--project-dir", default="local/ghidra/smt4-eu")
    args = parser.parse_args()
    if args.mutant and args.mutant.startswith("copy-") and not args.recover_copy:
        parser.error("Copy faults require --recover-copy")
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
    source = ROOT / "src/table_resource_reload.c"
    copy_source = ROOT / "src/table_resource_copy.c"
    aligned_source = ROOT / "src/resource_aligned_copy.c"
    if args.mutant and not args.mutant.startswith("copy-"):
        old, new = {"restore": ("if (!was_enabled)", "if (was_enabled)"),
                    "signed-state": ("(int32_t)value - 256", "(int32_t)value"),
                    "publish-size": ("entry[2] = size;", "entry[2] = 0;")}[args.mutant]
        content = source.read_text()
        assert content.count(old) == 1
        source = output / source.name
        source.write_text(content.replace(old, new))
    if args.mutant and args.mutant.startswith("copy-"):
        mutation_source = copy_source if args.mutant == "copy-prefix" else aligned_source
        content = mutation_source.read_text()
        old, new = {
            "copy-prefix": ("n -= 4 - residue;", "n -= 3 - residue;"),
            "copy-group": (
                "for (unsigned i = 0; i < 8; ++i) batch[i] = in[i];\n        for (unsigned i = 0; i < 8; ++i) out[i] = batch[i];",
                "for (unsigned i = 0; i < 8; ++i) { batch[i] = in[i]; out[i] = batch[i]; }"),
            "copy-half": ("half = *(const volatile uint16_t *)tail_in;", "half = *tail_in;")}[args.mutant]
        assert content.count(old) == 1
        mutation_source = output / mutation_source.name
        mutation_source.write_text(content.replace(old, new))
        if args.mutant == "copy-prefix":
            copy_source = mutation_source
        else:
            aligned_source = mutation_source
    copy_build = ([str(copy_source), str(aligned_source)] if args.recover_copy else
                  ["-Wl,--defsym,smt4_table_reload_copy=0x2c6048"])
    elf, binary = output / "resource-lifecycle.elf", output / "resource-lifecycle.bin"
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), str(ROOT / "src/table_resource_initialize.c"), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_table_resource_reload", "-Wl,--build-id=none",
         "-Wl,--defsym,smt4_table_resource_registry=0x49382c",
         "-Wl,--defsym,smt4_resource_load=0x2c3344",
         *copy_build,
         "-Wl,--defsym,smt4_resource_release=0x2c43b4", "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {row.split()[2]: int(row.split()[0], 16) for row in symbols.splitlines()
               if len(row.split()) == 3 and row.split()[1] == "T"}
    names = NAMES + (["smt4_table_reload_copy", "smt4_diagnostic_copy"] if args.recover_copy else [])
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in names))
    script = "CompareTableResourceCopy.java" if args.recover_copy else "CompareTableResourceReload.java"
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", script,
               str(output), "-log", str(output / "ghidra.log")], output, "comparison")
    if "SMT4_TABLE_RELOAD_COMPARE_OK" not in log or not (output / "comparison.json").is_file():
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "comparison": comparison,
                "binary_matching": False, "backend_implemented": False,
                "copy_recovered": args.recover_copy,
                "method": "Original/rebuilt ARM execution with identical explicit backend models",
                "files_sha256": {name: digest(ROOT / name) for name in (
                    "src/table_resource_reload.c", "src/table_resource_reload.h", "src/table_resource_copy.h", "src/resource_aligned_copy.h",
                    "src/table_resource_initialize.c", "src/table_resource_initialize.h", "src/resource_lifecycle.h",
                    "tools/check_table_resource_reload.py", "tools/ghidra/CompareTableResourceReload.java",
                    "tools/ghidra/CompareResourceLifecycle.java", "tools/ghidra_reference.py",
                    "tools/check_nkm_lookup.py", "config/recovery-tools.json", "config/analysis-tools.json")}}
    if args.recover_copy:
        for name in ("src/table_resource_copy.c", "src/resource_aligned_copy.c", "tools/ghidra/CompareTableResourceCopy.java"):
            manifest["files_sha256"][name] = digest(ROOT / name)
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
