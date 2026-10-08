"""Compare registry submission through the continuous worker, I/O and release."""
import argparse
import json
from ghidra_reference import ROOT, CODE_HASH, check_hash, java_command, local_path
from check_nkm_lookup import digest, run
from check_resource_worker_completion import MUTANTS, RANGES
from check_resource_release_convert import MUTATIONS as CONVERSION_MUTATIONS
from check_resource_heap_index import MUTATIONS as SELECTOR_MUTATIONS
from check_resource_allocate_register import MUTATIONS as REGISTRATION_MUTATIONS
from check_resource_allocate_raw import MUTATIONS as RAW_MUTATIONS
from check_resource_heap_allocate import MUTATIONS as HEAP_MUTATIONS

NAMES = ["resource_request_if_dynamic", "resource_load_complete",
         "smt4_resource_request_complete", "smt4_file_create", "smt4_resource_release",
         "smt4_file_worker", "smt4_file_worker_step", "smt4_worker_state0_io"]
SOURCES = ["resource_lifecycle", "resource_request", "resource_create", "resource_descriptor",
           "resource_release", "resource_worker", "resource_worker_loop", "resource_worker_io"]
MUTATIONS = {key: MUTANTS[key] for key in
             ("restart-head", "skip-reset", "retain-success-data", "clear-cleanup", "skip-io")}
MUTATIONS["wrong-packet"] = ("resource_request.c",
    "descriptor[0x134 / 4] = (uint32_t)(uintptr_t)context;",
    "descriptor[0x134 / 4] = (uint32_t)(uintptr_t)context + 0x100;")
MUTATIONS["missing-backlink"] = ("resource_create.c",
    "descriptor[0x140 / 4] = (uint32_t)(uintptr_t)node;",
    "descriptor[0x140 / 4] = 0;")
MUTATIONS["skip-reused-clear"] = ("resource_create.c",
    "smt4_file_clear(descriptor, 0x144);",
    "if (descriptor[0] != 4) smt4_file_clear(descriptor, 0x144);")
MUTATIONS["missing-next-backlink"] = ("resource_worker.c",
    "next[0x140 / 4] = (uint32_t)(uintptr_t)previous;",
    "next[0x140 / 4] = next[0x140 / 4];")
ALLOCATION_MUTATIONS = {
    "skip-outer-zero": ("resource_allocate.c", "smt4_resource_allocate_zero(result, size);", "(void)size;"),
    "skip-inner-zero": ("resource_allocate_lower.c", "smt4_resource_allocate_zero(result, size);", "(void)size;"),
    "wrong-raw-backlink": ("resource_allocate_lower.c",
        "*(uint32_t *)(uintptr_t)(user - 4u) = address;",
        "*(uint32_t *)(uintptr_t)(user - 4u) = user;"),
    "wrong-rounded-size": ("resource_allocate_lower.c", "size + 0x13bu", "size + 0x1bbu"),
    "damage-header": ("resource_create.c", "smt4_file_clear(descriptor, 0x144);",
        "smt4_file_clear(descriptor, 0x144); descriptor[-1] = 0;"),
}
# Cache only for the deliberate faulty local variant.
ALLOCATION_MUTATIONS["cached-outer-lock"] = ("resource_allocate.c",
    "    smt4_resource_heap_acquire(smt4_resource_allocator_state[1]);\n"
    "    void *result = smt4_resource_allocate_lower(first, second, third, size, fifth);\n"
    "    if (result != 0)\n        smt4_resource_allocate_zero(result, size);\n"
    "    /* Lower allocation/zeroing may change the synchronization handle. */\n"
    "    smt4_resource_heap_release(smt4_resource_allocator_state[1]);",
    "    uint32_t saved = smt4_resource_allocator_state[1];\n"
    "    smt4_resource_heap_acquire(saved);\n"
    "    void *result = smt4_resource_allocate_lower(first, second, third, size, fifth);\n"
    "    if (result != 0) smt4_resource_allocate_zero(result, size);\n"
    "    smt4_resource_heap_release(saved);")
MUTATIONS.update(ALLOCATION_MUTATIONS)
MUTATIONS.update({"conversion-" + key: ("resource_release_convert.c", *value)
                  for key, value in CONVERSION_MUTATIONS.items()})
MUTATIONS.update({"selector-" + key: ("resource_heap_index.c", *value)
                  for key, value in SELECTOR_MUTATIONS.items()})
MUTATIONS.update({"registration-" + key: ("resource_allocate_register.c", *value)
                  for key, value in REGISTRATION_MUTATIONS.items()})
MUTATIONS.update({"raw-" + key: ("resource_allocate_raw.c", *RAW_MUTATIONS[key])
                  for key in ("sixth-word", "reload-lock")})
MUTATIONS["raw-heap-route"] = ("resource_allocate_raw.c", "0x1cu : 0x88u", "0x20u : 0x88u")
MUTATIONS["raw-alignment"] = ("resource_allocate_raw.c", "case 0x100: alignment = 4;", "case 0x100: alignment = 8;")
MUTATIONS.update({"heap-" + key: ("resource_heap_allocate.c", *HEAP_MUTATIONS[key])
                  for key in ("subobject", "call-order", "size-alignment", "null-count",
                              "counter-offset", "increment", "return")})
MUTATIONS["heap-early-count"] = ("resource_heap_allocate.c",
    "    void *result =", "    uint32_t saved = *(volatile uint32_t *)(uintptr_t)(heap + 0x54u);\n    void *result =")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--mutant", choices=MUTATIONS)
    parser.add_argument("--recover-allocation", action="store_true",
                        help="Execute both allocation layers for request packets and descriptors")
    parser.add_argument("--recover-conversion", action="store_true",
                        help="Execute metadata release conversion (requires --recover-allocation)")
    parser.add_argument("--recover-selector", action="store_true",
                        help="Execute heap selection (requires --recover-conversion)")
    parser.add_argument("--recover-registration", action="store_true",
                        help="Execute allocation registration (requires --recover-selector)")
    parser.add_argument("--recover-raw-allocation", action="store_true",
                        help="Execute raw allocation routing (requires --recover-registration)")
    parser.add_argument("--recover-heap-allocation", action="store_true",
                        help="Execute heap wrapper (requires --recover-raw-allocation)")
    parser.add_argument("--resubmit", action="store_true",
                        help="Run two retained batches with freed address reuse and interleaved pending nodes")
    args = parser.parse_args()
    if args.recover_heap_allocation and not args.recover_raw_allocation:
        parser.error("--recover-heap-allocation requires --recover-raw-allocation")
    if args.mutant and args.mutant.startswith("heap-") and not args.recover_heap_allocation:
        parser.error("Heap allocation mutants require --recover-heap-allocation")
    if args.mutant in ALLOCATION_MUTATIONS and not args.recover_allocation:
        parser.error("Allocation mutants require --recover-allocation")
    if args.recover_conversion and not args.recover_allocation:
        parser.error("--recover-conversion requires --recover-allocation")
    if args.recover_selector and not args.recover_conversion:
        parser.error("--recover-selector requires --recover-conversion")
    if args.mutant and args.mutant.startswith("selector-") and not args.recover_selector:
        parser.error("Selector mutants require --recover-selector")
    if args.mutant and args.mutant.startswith("conversion-") and not args.recover_conversion:
        parser.error("Conversion mutants require --recover-conversion")
    if args.recover_registration and not args.recover_selector:
        parser.error("--recover-registration requires --recover-selector")
    if args.mutant and args.mutant.startswith("registration-") and not args.recover_registration:
        parser.error("Registration mutants require --recover-registration")
    if args.recover_raw_allocation and not args.recover_registration:
        parser.error("--recover-raw-allocation requires --recover-registration")
    if args.mutant and args.mutant.startswith("raw-") and not args.recover_raw_allocation:
        parser.error("Raw allocation mutants require --recover-raw-allocation")
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
    sources = SOURCES + (["resource_allocate", "resource_allocate_lower"] if args.recover_allocation else [])
    names = NAMES + (["smt4_file_allocate"] if args.recover_allocation else [])
    if args.recover_conversion:
        sources += ["resource_release_convert"]
        names += ["smt4_resource_release_convert"]
    if args.recover_selector:
        sources += ["resource_heap_index"]
        names += ["smt4_resource_heap_index"]
    if args.recover_registration:
        sources += ["resource_allocate_register"]
        names += ["smt4_resource_allocate_register"]
    if args.recover_raw_allocation:
        sources += ["resource_allocate_raw"]
        names += ["smt4_resource_allocate_raw"]
    if args.recover_heap_allocation:
        sources += ["resource_heap_allocate"]
        names += ["smt4_resource_heap_allocate"]
    paths = [ROOT / "src" / (name + ".c") for name in sources]
    if args.mutant:
        filename, old, new = MUTATIONS[args.mutant]
        original = ROOT / "src" / filename
        content = original.read_text()
        if content.count(old) != 1:
            raise RuntimeError("Mutation anchor")
        mutant = output / filename
        content = content.replace(old, new)
        if args.mutant == "heap-early-count":
            content = content.replace("*count = *count + 1u;", "*count = saved + 1u;")
        mutant.write_text(content)
        paths[paths.index(original)] = mutant
    definitions = {
        "smt4_table_resource_registry": 0x49382c,
        "smt4_resource_path_mode": 0x465040, "smt4_resource_path_format": 0x409740,
        "smt4_file_clear": 0x2c4b84, "smt4_file_allocate": 0x2c4bd8,
        "smt4_resource_path_has_prefix": 0x2b0674, "smt4_resource_format": 0x2be850,
        "smt4_file_sync_handle": 0x465010, "smt4_file_list_head": 0x46500c,
        "smt4_file_acquire": 0x2c4350, "smt4_file_release": 0x2c54a4,
        "smt4_worker_unlock": 0x2c54a4, "smt4_file_check_result": 0x2c54bc,
        "smt4_file_path_length": 0x2c32e4, "smt4_file_path_copy": 0x2bf8c0,
        "smt4_file_path_format": 0x2b066c, "smt4_resource_allocator_state": 0x465120,
        "smt4_resource_heap_acquire": 0x2c3afc, "smt4_resource_heap_release": 0x2c3a78,
        "smt4_resource_release_convert": 0x1245f0, "smt4_resource_heap_free": 0x1244e8,
        "smt4_worker_file_construction": 0x420870,
        "smt4_worker_io_lock_handle": 0x465124, "smt4_worker_io_busy": 0x465004,
        "smt4_worker_object_allocate": 0x2c244c,
        "smt4_worker_path_is_initial": 0x710000, "smt4_worker_path_measure": 0x710004,
        "smt4_worker_path_convert": 0x710008, "smt4_worker_file_open": 0x2bb944,
        "smt4_worker_data_allocate": 0x2bf7ec, "smt4_worker_io_acquire": 0x2c3afc,
        "smt4_worker_io_release": 0x2c3a78, "smt4_worker_file_preclose": 0x2bce9c,
        "smt4_worker_file_close": 0x2b9450,
        "smt4_worker_stop": 0x465000, "smt4_worker_event": 0x465024,
        "smt4_worker_event_wait": 0x2c367c, "smt4_worker_event_reset": 0x138f5c,
        "smt4_file_delay": 0x2bb4f0,
    }
    elf, binary = output / "registry-worker.elf", output / "registry-worker.bin"
    if args.recover_allocation:
        del definitions["smt4_file_allocate"]
        definitions.update({"smt4_resource_allocate_raw": 0x2b26f0,
                            "smt4_resource_allocate_register": 0x2b260c,
                            "smt4_resource_allocate_zero": 0x2c3b9c})
    if args.recover_conversion:
        del definitions["smt4_resource_release_convert"]
        definitions["smt4_resource_heap_index"] = 0x2b3340
    if args.recover_selector:
        del definitions["smt4_resource_heap_index"]
    if args.recover_registration:
        del definitions["smt4_resource_allocate_register"]
    if args.recover_raw_allocation:
        del definitions["smt4_resource_allocate_raw"]
        definitions.update({"smt4_resource_raw_state": 0x465170,
                            "smt4_resource_heap_allocate": 0x2c3a98,
                            "smt4_resource_fixed_allocate": 0x144978})
    if args.recover_heap_allocation:
        del definitions["smt4_resource_heap_allocate"]
        definitions.update({"smt4_resource_heap_configure_fourth": 0x146ce0,
                            "smt4_resource_heap_configure_fifth": 0x146cf0,
                            "smt4_resource_heap_configure_sixth": 0x146d10,
                            "smt4_resource_heap_allocate_inner": 0x146ad8})
    run([str(tool_dir / "arm-none-eabi-gcc.exe"), "-std=c11", "-O2", "-march=armv6k",
         "-marm", "-mfloat-abi=soft", "-ffreestanding", "-fno-builtin", "-fno-unwind-tables",
         "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-fdata-sections",
         "-Wall", "-Wextra", "-Werror", "-nostdlib", *map(str, paths), "-I", str(ROOT / "src"),
         "-Wl,-Ttext=0x600000", "-Wl,--entry=resource_request_if_dynamic", "-Wl,--gc-sections",
         "-Wl,--undefined=smt4_file_worker", "-Wl,--undefined=smt4_worker_state0_io", "-Wl,--build-id=none",
         *[f"-Wl,--defsym,{name}=0x{value:x}" for name, value in definitions.items()],
         "-o", str(elf)], output, "build")
    run([str(tool_dir / "arm-none-eabi-objcopy.exe"), "-O", "binary", "--only-section=.text", "--only-section=.rodata",
         str(elf), str(binary)], output, "objcopy")
    sections = run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-h", str(elf)], output, "sections")
    text_bytes = next(int(row.split()[2], 16) for row in sections.splitlines()
                      if len(row.split()) >= 3 and row.split()[1] == ".text")
    (output / "text-size.txt").write_text(f"{text_bytes}\n")
    run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-d", str(elf)], output, "disassembly")
    ranges = RANGES + [(0x113d58, 0x113de8), (0x113e80, 0x114070),
        (0x114098, 0x114134), (0x114340, 0x114370), (0x33c844, 0x33c898),
        (0x2ae72c, 0x2ae878), (0x2b6820, 0x2b6840), (0x155bbc, 0x155bd8),
        (0x2b0478, 0x2b0630), (0x14e744, 0x14e760)]
    if args.recover_allocation:
        ranges += [(0x2c4bd8, 0x2c4c40), (0x2c5544, 0x2c5634)]
    if args.recover_conversion:
        ranges += [(0x1245f0, 0x1246f0)]
    if args.recover_selector:
        ranges += [(0x2b3340, 0x2b33d0)]
    if args.recover_registration:
        ranges += [(0x2b260c, 0x2b26f0)]
    if args.recover_raw_allocation:
        ranges += [(0x2b26f0, 0x2b2868)]
    if args.recover_heap_allocation:
        ranges += [(0x2c3a98, 0x2c3afc)]
    for start, stop in ranges:
        run([str(tool_dir / "arm-none-eabi-objdump.exe"), "-D", "-b", "binary", "-m", "arm",
             "--adjust-vma=0x100000", f"--start-address={start}", f"--stop-address={stop}",
             str(code)], output, f"original-{start:08x}")
    symbols = run([str(tool_dir / "arm-none-eabi-nm.exe"), "-n", str(elf)], output, "symbols")
    if " U " in symbols:
        raise RuntimeError("Unresolved symbols")
    entries = {r.split()[2]: int(r.split()[0], 16) for r in symbols.splitlines()
               if len(r.split()) == 3 and r.split()[1] == "T"}
    (output / "entries.txt").write_text("".join(f"{entries[name]}\n" for name in names))
    log = run([*java, "ghidra.app.util.headless.AnalyzeHeadless", str(project), "SMT4-EU",
               "-process", "code.bin", "-readOnly", "-noanalysis", "-scriptPath",
               str(ROOT / "tools/ghidra"), "-postScript", "CompareResourceRegistryWorker.java",
               str(output), *(["resubmit"] if args.resubmit else []),
               *(["allocation"] if args.recover_allocation else []),
               *(["conversion"] if args.recover_conversion else []),
               *(["selector"] if args.recover_selector else []),
               *(["registration"] if args.recover_registration else []),
               *(["raw-allocation"] if args.recover_raw_allocation else []),
               *(["heap-allocation"] if args.recover_heap_allocation else []),
               "-log", str(output / "ghidra.log")], output, "comparison")
    if args.mutant:
        if "SMT4_REGISTRY_WORKER_OK" in log or "Registry worker scenario " not in log or "IllegalStateException" not in log:
            raise RuntimeError("Mutant not rejected by corpus assertion")
        marker = {"mutant": args.mutant, "rejected": True, "source_sha256": digest(mutant),
                  "binary_sha256": digest(binary),
                  "assertion": next((line.strip() for line in log.splitlines()
                                     if "Caused by: java.lang.IllegalStateException:" in line), "")}
        (output / "NEGATIVE.json").write_text(json.dumps(marker, indent=2) + "\n")
        print(json.dumps(marker))
        return
    if "SMT4_REGISTRY_WORKER_OK" not in log:
        raise RuntimeError("Comparison failed; inspect comparison.log")
    comparison = json.loads((output / "comparison.json").read_text())
    expected_counts = {"scenarios": 324, "submissions_both_paths": 1296,
        "completions_both_paths": 1296, "skipped_calls_both_paths": 1944,
        "traversals_both_paths": 1944, "node_visits_both_paths": 4536,
        "io_executions_both_paths": 1296, "release_executions_both_paths": 2592,
        "lower_io_calls_both_paths": 132984, "original_instruction_addresses": 578}
    if args.resubmit:
        expected_counts = {"scenarios": 324, "submissions_both_paths": 2592,
            "completions_both_paths": 2592, "traversals_both_paths": 3888,
            "node_visits_both_paths": 9072, "io_executions_both_paths": 2592,
            "release_executions_both_paths": 5184, "reused_allocations_both_paths": 2592,
            "interleaved_lists_both_paths": 288, "skipped_calls_both_paths": 2628,
            "null_resubmissions_both_paths": 414, "loaded_skips_both_paths": 684,
            "lower_io_calls_both_paths": 285768, "original_instruction_addresses": 578}
    if args.recover_allocation:
        expected_counts["original_instruction_addresses"] = 649
        allocation = json.loads((output / "allocation.json").read_text())
        allocations = expected_counts["submissions_both_paths"] * 2
        if allocation != {"allocation_executions_both_paths": allocations,
                          "zero_calls_both_paths": allocations * 2,
                          "metadata_conversions_both_paths": allocations, "raw_residues": 32}:
            raise RuntimeError("Incomplete allocation corpus")
        comparison.update(allocation)
    if args.recover_conversion:
        expected_counts["original_instruction_addresses"] = 713
        conversion = json.loads((output / "conversion.json").read_text())
        if (conversion["conversion_executions_both_paths"] != allocations
                or conversion["list_topologies"] != (3 if args.recover_registration else 4)
                or conversion["selector_calls_both_paths"] != (6912 if args.resubmit else 3456)):
            raise RuntimeError("Incomplete conversion corpus")
        comparison.update(conversion)
    if args.recover_registration:
        registration = json.loads((output / "registration.json").read_text())
        if registration != {"registration_executions_both_paths": allocations,
                            "registration_selector_calls_both_paths": conversion["selector_calls_both_paths"],
                            "registration_modeled": False}:
            raise RuntimeError("Incomplete registration corpus")
        comparison.update(registration)
    if args.recover_selector:
        # Selector adds 25 addresses; empty high-base direct-release ranges omit
        # ten release-routing addresses exercised by the prior fixture.
        expected_counts["original_instruction_addresses"] = 784 if args.recover_registration else 728
        selector = json.loads((output / "selector.json").read_text())
        if selector != {"selector_executions_both_paths": conversion["selector_calls_both_paths"] * (2 if args.recover_registration else 1),
                        "selector_results": [0, 1], "selector_modeled": False}:
            raise RuntimeError("Incomplete selector corpus")
        comparison.update(selector)
    if args.recover_raw_allocation:
        expected_counts["original_instruction_addresses"] = 828
        raw = json.loads((output / "raw-allocation.json").read_text())
        if raw != {"raw_allocation_executions_both_paths": allocations,
                   "raw_lower_calls_both_paths": allocations,
                   "raw_lock_calls_both_paths": allocations * 2,
                   "raw_original_instruction_addresses": 44,
                   "raw_allocation_modeled": False, "raw_lower_dependencies_modeled": not args.recover_heap_allocation}:
            raise RuntimeError("Incomplete raw allocation corpus")
        comparison.update(raw)
    if args.recover_heap_allocation:
        expected_counts["original_instruction_addresses"] = 853
        heap = json.loads((output / "heap-allocation.json").read_text())
        if (heap["heap_allocation_executions_both_paths"] != allocations
                or heap["heap_inner_calls_both_paths"] != allocations * 4
                or heap["heap_counter_reads_both_paths"] != allocations
                or heap["heap_counter_writes_both_paths"] != allocations
                or heap["heap_counter_wraps_both_paths"] <= 0
                or heap["heap_wrapping_addresses_both_paths"] <= 0
                or heap["heap_original_instruction_addresses"] != 25
                or heap["heap_allocation_modeled"] is not False
                or heap["heap_inner_dependencies_modeled"] is not True):
            raise RuntimeError("Incomplete heap allocation corpus")
        comparison.update(heap)
    if any(comparison[key] != value for key, value in expected_counts.items()):
        raise RuntimeError("Incomplete comparison corpus")
    files = ["src/" + name + ".c" for name in sources]
    files += ["src/" + name + ".h" for name in sources if (ROOT / "src" / (name + ".h")).exists()]
    files += ["src/resource_sync.h", "src/resource_wait.h", "src/resource_worker_path.h", "tools/check_resource_registry_worker.py",
              "tools/check_resource_worker_completion.py", "tools/check_nkm_lookup.py", "tools/ghidra_reference.py",
              "tools/check_resource_release_convert.py",
              "tools/check_resource_heap_index.py", "tools/check_resource_allocate_register.py",
              "tools/check_resource_allocate_raw.py",
              "tools/check_resource_heap_allocate.py",
              "config/recovery-tools.json", "config/analysis-tools.json"]
    files += ["tools/ghidra/CompareResource" + name + ".java"
              for name in ("RegistryWorker", "RegistryRequest", "Create", "Sync", "Lifecycle")]
    manifest = {"reference_sha256": CODE_HASH, "binary_sha256": digest(binary),
                "binary_bytes": binary.stat().st_size, "text_bytes": text_bytes, "comparison": comparison,
                "binary_matching": False, "original_binary_helpers_required": False,
                "resubmission": args.resubmit,
                "recovered_allocation_layers": args.recover_allocation,
                "recovered_release_conversion": args.recover_conversion,
                "recovered_heap_selector": args.recover_selector,
                "recovered_registration": args.recover_registration,
                "recovered_raw_allocation": args.recover_raw_allocation,
                "recovered_heap_allocation": args.recover_heap_allocation,
                "method": "Retained registry submission/construction and continuous worker/I/O/completion/release; lower calls modeled",
                "files_sha256": {name: digest(ROOT / name) for name in files}}
    (output / "COMPLETE.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
