"""Build and compare recursive wrappers with executed base locks and scheduled exclusives."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run

TARGETS = (("smt4_worker_backend_acquire", 0x2c3afc, 0x2c3b34),
           ("smt4_worker_backend_release", 0x2c3a78, 0x2c3a98))
MUTATIONS = {
    "acquire-fast-r2": ("return (uint32_t)(uintptr_t)lock;", "return 0;"),
    "acquire-slow-r2": ("return 0;", "return 1;"),
    "tls-cache": ("mov r4, r0", "mov r4, r0\\nmrc p15, 0, r2, c13, c0, 3"),
    "owner-order": ("str r1, [r0, #4]", "push {r4, lr}\\nmov r4, r0\\nbl smt4_signal_lock_release\\nmov r1, #0\\nstr r1, [r4, #4]\\npop {r4, pc}"),
    "count-wrap": ("add r0, r0, #1", "adds r0, r0, #1\\nsubcs r0, r0, #1"),
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
    source = ROOT / "src/resource_recursive_lock.c"
    base_source = ROOT / "src/resource_lock.c"
    if a.mutant and a.mutant.startswith("acquire-"):
        old, new = MUTATIONS[a.mutant]
        content = base_source.read_text()
        assert content.count(old) == (2 if a.mutant == "acquire-slow-r2" else 1)
        base_source = out / base_source.name
        base_source.write_text(content.replace(old, new))
    elif a.mutant:
        old, new = MUTATIONS[a.mutant]
        content = source.read_text()
        assert content.count(old) == 1
        source = out / source.name
        content = content.replace(old, new)
        if a.mutant == "owner-order":
            content = content.replace("b smt4_signal_lock_release", "nop")
        if a.mutant == "tls-cache":
            # Cache the initial TLS in a stack slot across the base call, then
            # use it instead of the required second read. Keep public alignment.
            content = content.replace("push {r4, lr}", "push {r4, lr}\\nsub sp, sp, #8")
            content = content.replace("mrc p15, 0, r2, c13, c0, 3", "mrc p15, 0, r2, c13, c0, 3\\nstr r2, [sp]")
            content = content.replace("mrc p15, 0, r0, c13, c0, 3\\n\"\n    \"str r0, [r4, #4]", "ldr r0, [sp]\\n\"\n    \"str r0, [r4, #4]")
            content = content.replace("pop {r4, pc}", "add sp, sp, #8\\npop {r4, pc}")
        source.write_text(content)
    elf, binary = out / "resource-recursive-lock.elf", out / "resource-recursive-lock.bin"
    run([str(tool / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k", "-marm",
         "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-Wall", "-Wextra", "-Werror", "-nostdlib",
         str(source), str(base_source), "-I", str(ROOT / "src"), "-Wl,-Ttext=0x600000",
         "-Wl,--entry=smt4_worker_backend_acquire", "-Wl,--build-id=none", "-Wl,--defsym,smt4_arbitration_handle=0x471b58",
         "-Wl,--defsym,smt4_signal_arbitrate=0x2a88fc", "-o", str(elf)], out, "build")
    run([str(tool / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", str(elf), str(binary)], out, "objcopy")
    run([str(tool / "arm-none-eabi-objdump.exe"), "-d", str(elf)], out, "disassembly")
    for name, start, end in TARGETS:
        run([str(tool / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start:#x}", f"--stop-address={end:#x}", str(code)], out, f"original-{name}")
    symbols = run([str(tool / "arm-none-eabi-nm.exe"), "-n", str(elf)], out, "symbols")
    assert " U " not in symbols
    entries = {r.split()[2]: int(r.split()[0], 16) for r in symbols.splitlines() if len(r.split()) == 3 and r.split()[1] == "T"}
    (out / "entries.txt").write_text("".join(f"{entries[n]}\n" for n in [t[0] for t in TARGETS] + ["smt4_signal_lock_acquire", "smt4_signal_lock_release"]))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(ROOT / "local/ghidra/smt4-eu"), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath", str(ROOT / "tools/ghidra"),
               "-postScript", "CompareResourceRecursiveLock.java", str(out), "-log", str(out / "ghidra.log")], out, "comparison")
    if a.mutant:
        if "SMT4_RECURSIVE_LOCK_COMPARE_OK" in log or "Recursive case " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by behavioral assertion")
        m = {"mutant": a.mutant, "rejected": True, "binary_sha256": digest(binary),
             "assertions": [s.strip() for s in log.splitlines() if "IllegalStateException:" in s]}
        (out / "NEGATIVE.json").write_text(json.dumps(m, indent=2) + "\n")
    else:
        if "SMT4_RECURSIVE_LOCK_COMPARE_OK" not in log:
            raise RuntimeError("Comparison failed; inspect comparison.log")
        comparison = json.loads((out / "comparison.json").read_text())
        if any(comparison[k] != v for k, v in {"cases": 164, "pending_prefixes": 4,
                "persistent_sequences": 2, "new_instruction_sites": 22}.items()):
            raise RuntimeError("Incomplete recursive lock corpus")
        m = {"reference_sha256": CODE_HASH, "binary_bytes": binary.stat().st_size, "binary_sha256": digest(binary),
             "comparison": comparison, "binary_matching": False,
             "original_binary_helpers_required": False, "files_sha256": {n: digest(ROOT / n) for n in (
                 "src/resource_recursive_lock.c", "src/resource_recursive_lock.h", "tools/check_resource_recursive_lock.py",
                 "tools/ghidra/CompareResourceRecursiveLock.java", "tools/ghidra/CompareResourceLock.java", "src/resource_lock.c", "src/resource_signal.h",
                 "tools/ghidra/CompareResourceLifecycle.java", "config/recovery-tools.json", "config/analysis-tools.json")}}
        check_hash(code, CODE_HASH)
        (out / "COMPLETE.json").write_text(json.dumps(m, indent=2) + "\n")
    print(json.dumps(m if a.mutant else {"binary_bytes": m["binary_bytes"], "comparison": m["comparison"]}))

if __name__ == "__main__":
    main()
