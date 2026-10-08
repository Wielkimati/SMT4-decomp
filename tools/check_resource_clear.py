"""Build and compare original clearing entries and exact destination writes."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

TARGETS = (("smt4_worker_backend_clear", 0x139f54, 0x139f84),
           ("smt4_resource_allocate_zero", 0x2c3b9c, 0x2c3bdc),
           ("smt4_resource_fill_words", 0x2c4b88, 0x2c4bd8))
MUTATIONS = {
    "ordered-end": ("address != end", "address < end"),
    "byte-width": ("*(volatile uint16_t *)(uintptr_t)address = 0;", "*(volatile uint8_t *)(uintptr_t)address = 0;\n            *(volatile uint8_t *)(uintptr_t)(address + 1u) = 0;"),
    "tail": ("if ((count & 1u) != 0)", "if ((count & 1u) == 0)"),
}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True)
    p.add_argument("--mutant", choices=MUTATIONS)
    a = p.parse_args()
    out = local_path(a.output)
    if out.exists():
        raise FileExistsError("Choose new output under local/")
    code = ROOT / "local/reference-eu/base/0000/exefs/code.bin"
    check_hash(code, CODE_HASH)
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    tool = ROOT / pins["directory"] / "bin"
    for name, expected in pins["executables"].items():
        check_hash(tool / name, expected)
    java = java_command()
    out.mkdir(parents=True)
    source = ROOT / "src/resource_clear.c"
    if a.mutant:
        old, new = MUTATIONS[a.mutant]
        content = source.read_text()
        assert content.count(old) == 1
        source = out / source.name
        source.write_text(content.replace(old, new))
    elf, binary = out / "resource-clear.elf", out / "resource-clear.bin"
    run([str(tool / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k", "-marm",
         "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_worker_backend_clear", "-Wl,--build-id=none", "-o", str(elf)], out, "build")
    run([str(tool / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", str(elf), str(binary)], out, "objcopy")
    run([str(tool / "arm-none-eabi-objdump.exe"), "-d", str(elf)], out, "disassembly")
    for name, start, end in TARGETS:
        run([str(tool / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}", str(code)], out, f"original-{name}")
    symbols = run([str(tool / "arm-none-eabi-nm.exe"), "-n", str(elf)], out, "symbols")
    assert " U " not in symbols
    entries = {r.split()[2]: int(r.split()[0], 16) for r in symbols.splitlines() if len(r.split()) == 3 and r.split()[1] == "T"}
    (out / "entries.txt").write_text("".join(f"{entries[n]}\n" for n, _, _ in TARGETS))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(ROOT / "local/ghidra/smt4-eu"), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceClear.java", str(out), "-log", str(out / "ghidra.log")], out, "comparison")
    if a.mutant:
        if "SMT4_CLEAR_COMPARE_OK" in log or "Clear case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by behavioral assertion")
        m = {"mutant": a.mutant, "rejected": True, "binary_sha256": digest(binary),
             "assertions": [s.strip() for s in log.splitlines() if "IllegalStateException:" in s]}
        (out / "NEGATIVE.json").write_text(json.dumps(m, indent=2) + "\n")
    else:
        if "SMT4_CLEAR_COMPARE_OK" not in log:
            raise RuntimeError("Comparison failed; inspect comparison.log")
        m = {"reference_sha256": CODE_HASH, "binary_bytes": binary.stat().st_size, "binary_sha256": digest(binary),
             "comparison": json.loads((out / "comparison.json").read_text()), "binary_matching": False,
             "original_binary_helpers_required": False, "files_sha256": {n: digest(ROOT / n) for n in (
                 "src/resource_clear.c", "src/resource_clear.h", "tools/check_resource_clear.py",
                 "tools/ghidra/CompareResourceClear.java", "tools/ghidra/CompareResourceSync.java",
                 "tools/ghidra/CompareResourceLifecycle.java", "config/recovery-tools.json", "config/analysis-tools.json")}}
        check_hash(code, CODE_HASH)
        (out / "COMPLETE.json").write_text(json.dumps(m, indent=2) + "\n")
    print(json.dumps(m if a.mutant else {"binary_bytes": m["binary_bytes"], "comparison": m["comparison"]}))

if __name__ == "__main__":
    main()
