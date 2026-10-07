"""Build/exercise the A08 host research adapter with synthetic data only.

Requires 64-bit Python and installed Visual C++ x64 build tools. This does not
run ARM code, load game assets, or implement a native resource service.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from ghidra_reference import ROOT, local_path
from check_nkm_lookup import synthetic_table, write_cases
from nkm_pair_cases import pair_table, write_pair_cases
from tbcr_access_cases import ORIGINALS, TABLE, write_helper_cases

REGISTRY = 0x49382C
SENTINEL = 0xA55A1234
OK, BAD_MAP, UNMAPPED, ALIGNMENT, WRAP, BUDGET, BAD_OPERATION = range(7)
SELECT, PAYLOAD, COUNT, RESOURCE, LOOKUP, PAIRS = range(6)
SOURCES = ["src/nkm_sort_index.c", "src/nkm_section3.c", "src/tbcr_access.c",
           "src/unsigned_quotient.c", "src/nkm_sort_index.h", "src/tbcr_access.h",
           "src/unsigned_quotient.h", "src/resource_lifecycle.h"]
ADAPTER = ["tools/host/nkm_address_space.c", "tools/host/nkm_address_space.h"]
VALIDATION = ["tools/check_nkm_host_boundary.py", "tools/check_nkm_lookup.py",
              "tools/nkm_pair_cases.py", "tools/tbcr_access_cases.py",
              "tools/ghidra/CompareNkmLookup.java"]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def record(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class Region(C.Structure):
    _fields_ = [("address", C.c_uint32), ("size", C.c_uint32),
                ("bytes", C.POINTER(C.c_uint8))]


class Space(C.Structure):
    _fields_ = [("regions", C.POINTER(Region)), ("region_count", C.c_size_t),
                ("registry_address", C.c_uint32), ("read_budget", C.c_uint32)]


class Memory:
    def __init__(self, regions, registry=REGISTRY, budget=100000):
        self.buffers = [(C.c_uint8 * len(raw)).from_buffer_copy(raw)
                        for address, raw in regions]
        self.regions = (Region * len(regions))(*(Region(address, len(raw), buffer)
                         for (address, raw), buffer in zip(regions, self.buffers)))
        self.space = Space(self.regions, len(regions), registry, budget)
        self.before = [bytes(b) for b in self.buffers]

    def unchanged(self):
        if self.before != [bytes(b) for b in self.buffers]:
            raise AssertionError("Host adapter modified input bytes")


def registry_bytes(address=TABLE):
    raw = bytearray(b"\xA5" * (67 * 16))
    struct.pack_into("<I", raw, 20, address)
    return bytes(raw)


def build(output, vcvarsall, adapter_source=None):
    if C.sizeof(C.c_void_p) != 8:
        raise RuntimeError("64-bit Python is required for this boundary check")
    if vcvarsall is None:
        vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
        installation = subprocess.check_output([str(vswhere), "-latest", "-products", "*",
            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property", "installationPath"], text=True).strip()
        if not installation:
            raise RuntimeError("Visual C++ x64 build tools not found; use --vcvarsall")
        vcvarsall = Path(installation) / "VC/Auxiliary/Build/vcvarsall.bat"
    vcvarsall = vcvarsall.resolve(strict=True)
    # The batch contains a quoted installed path only, never user source text.
    if any(c in str(vcvarsall) for c in '%!^&|<>"\r\n'):
        raise ValueError("Unsupported shell metacharacter in vcvarsall path")
    setup = output / "environment.cmd"
    setup.write_text(f'@echo off\ncall "{vcvarsall}" x64 >nul\nif errorlevel 1 exit /b 1\nset\n')
    # Windows env names are case insensitive; normalize before passing to tools.
    environment = {k.upper(): v for k, v in os.environ.items()}
    result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(setup)],
                            env=environment, text=True, capture_output=True, timeout=60, check=True)
    for line in result.stdout.splitlines():
        if "=" in line and not line.startswith("="):
            key, value = line.split("=", 1)
            environment[key.upper()] = value
    compiler = shutil.which("cl.exe", path=environment.get("PATH"))
    linker = shutil.which("link.exe", path=environment.get("PATH"))
    if not compiler or not linker:
        raise RuntimeError("vcvarsall did not provide compiler/linker")
    dll = output / "nkm-host.dll"
    command = [compiler, "/nologo", "/std:c11", "/W4", "/WX", "/O2", "/LD",
               "/I" + str(ROOT / "src"), "/I" + str(ROOT / "tools/host"),
               str(adapter_source or ROOT / ADAPTER[0]),
               str(ROOT / "src/unsigned_quotient.c"), "/Fe:" + str(dll),
               "/link", "/INCREMENTAL:NO"]
    record(output / "build-command.json", command)
    result = subprocess.run(command, cwd=output, env=environment, text=True,
                            capture_output=True, timeout=120)
    (output / "build.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError("Host build failed; see build.log")
    version = subprocess.run([compiler], cwd=output, env=environment, text=True,
                             capture_output=True, timeout=30)
    return dll, {"compiler": compiler, "compiler_sha256": digest(compiler),
                 "linker": linker, "linker_sha256": digest(linker),
                 "vcvarsall": str(vcvarsall), "vcvarsall_sha256": digest(vcvarsall),
                 "version": (version.stdout + version.stderr).strip(),
                 "python": sys.version, "host_pointer_bits": 64,
                 "note": "Installed research compiler; not original compiler or port toolchain selection"}


def exercise(dll, output):
    library = C.CDLL(str(dll))
    evaluate = library.smt4_host_eval
    evaluate.argtypes = [C.POINTER(Space), C.c_uint32, C.c_uint32, C.c_uint32,
                         C.POINTER(C.c_uint32), C.POINTER(C.c_uint32)]
    evaluate.restype = C.c_int
    results = []

    def check(name, memory, op, a=0, b=0, expected=0, status=OK, reads=None):
        value, loads = C.c_uint32(SENTINEL), C.c_uint32(0)
        actual = evaluate(C.byref(memory.space), op, a, b, C.byref(value), C.byref(loads))
        wanted = expected if status == OK else SENTINEL
        if actual != status or value.value != wanted or (reads is not None and loads.value != reads):
            raise AssertionError(f"{name}: got {(actual, value.value, loads.value)}, expected {(status, wanted, reads)}")
        memory.unchanged()
        results.append({"name": name, "operation": op, "arg0": a, "arg1": b,
                        "status": actual, "value": value.value, "reads": loads.value})

    fixtures = output / "fixtures"
    fixtures.mkdir()
    # Reuse the existing oracles without supplying any original asset. Their
    # reference-shape fixture is explicitly a synthetic 1201-record stand-in.
    sort_reference = fixtures / "synthetic-sort-input.bin"
    sort_reference.write_bytes(synthetic_table([0xBEEF0000 + i for i in range(1201)]))
    pair_reference = fixtures / "synthetic-pair-input.bin"
    pair_reference.write_bytes(pair_table([(i, (i * 37) & 65535) for i in range(1201)]))
    write_cases(fixtures, sort_reference)
    write_pair_cases(fixtures, pair_reference)
    write_helper_cases(fixtures)
    corpus_totals = {}
    for filename, group in (("helpers.tsv", "helper"), ("cases.tsv", "lookup"), ("pairs.tsv", "pairs")):
        rows = (fixtures / filename).read_text().splitlines()[1:]
        for number, row in enumerate(rows):
            cols = row.split("\t")
            name = cols[0]
            raw = (fixtures / (name + ".bin")).read_bytes()
            registry_path = fixtures / (name + ".registry.bin")
            reg = registry_path.read_bytes() if registry_path.exists() else registry_bytes()
            memory = Memory([(TABLE, raw), (REGISTRY, reg)])
            if group == "helper":
                op = list(ORIGINALS).index(cols[1])
                a, b, expected = map(int, cols[2:])
            else:
                op, a, b, expected = LOOKUP if group == "lookup" else PAIRS, int(cols[1]), 0, int(cols[2])
            check(f"{group}/{number}/{name}", memory, op, a, b, expected)
        corpus_totals[group] = len(rows)

    # Extra risks introduced by the host boundary, distinct from original returns.
    empty = Memory([])
    check("invalid-id-needs-no-registry", empty, RESOURCE, 67, 0, reads=0)
    check("high-id-needs-no-registry", empty, RESOURCE, 0xFFFFFFFF, 0, reads=0)
    check("missing-registry", empty, RESOURCE, 1, status=UNMAPPED)
    check("bad-operation", empty, 6, status=BAD_OPERATION)
    null = Memory([(REGISTRY, bytes(67 * 16))])
    check("null-pairs-safe", null, PAIRS, 7, expected=50, reads=1)
    check("null-lookup-not-game-zero", null, LOOKUP, status=UNMAPPED, reads=1)
    check("payload-no-backing-needed", Memory([(TABLE, b"TBL1")]), PAYLOAD, TABLE, expected=TABLE + 16, reads=1)
    check("payload-address-wrap", Memory([(0xFFFFFFF0, b"TBL1")]), PAYLOAD, 0xFFFFFFF0, expected=0, reads=1)
    check("header-truncated", Memory([(TABLE, b"TBCR")]), SELECT, TABLE, status=UNMAPPED, reads=1)
    check("word-misaligned", Memory([(TABLE + 1, b"TBCR" + bytes(12))]), SELECT, TABLE + 1, status=ALIGNMENT)
    check("split-word-rejected", Memory([(TABLE, b"TB"), (TABLE + 2, b"CR")]), SELECT, TABLE, status=UNMAPPED)
    check("header-address-overflow", Memory([(0xFFFFFFFC, b"TBCR")]), SELECT, 0xFFFFFFFC, status=WRAP, reads=1)
    check("map-wrap", Memory([(0xFFFFFFFC, bytes(8))]), SELECT, status=BAD_MAP)
    check("map-overlap", Memory([(TABLE, bytes(8)), (TABLE + 4, bytes(8))]), SELECT, status=BAD_MAP)
    check("map-empty-span", Memory([(TABLE, b"")]), SELECT, status=BAD_MAP)
    check("too-many-regions", Memory([(4 * i, bytes(4)) for i in range(65)]), SELECT, status=BAD_MAP)
    missing_pointer = Memory([(TABLE, bytes(4))])
    missing_pointer.regions[0].bytes = C.POINTER(C.c_uint8)()
    check("null-host-backing", missing_pointer, SELECT, status=BAD_MAP)

    # Rebase complete data far above 2 GiB, keeping serialized addresses u32.
    table = pair_table([(7, 0), (7, 65535), (32768, 65535)])
    for address in (0x80000000, 0xFFFFF000):
        memory = Memory([(address, table), (REGISTRY, registry_bytes(address))])
        check(f"high-address-zero-first/{address}", memory, PAIRS, 7, expected=50, reads=12)
        check(f"high-address-width/{address}", memory, PAIRS, 32768, expected=65535, reads=20)
        check(f"full-width-key/{address}", memory, PAIRS, 0x10007, expected=50, reads=22)
    # Count is called again after the final mismatch: 7 setup + 3*4 + 3 loads.
    memory = Memory([(TABLE, table), (REGISTRY, registry_bytes())], budget=21)
    check("repeated-count-budget", memory, PAIRS, 0x10007, status=BUDGET, reads=21)
    raw = synthetic_table([0xABCD8123], declared_size=0)
    check("zero-count-still-reads", Memory([(TABLE, raw), (REGISTRY, registry_bytes())]), LOOKUP,
          0xFFFFFFFF, expected=0x8123, reads=11)
    raw = synthetic_table([], declared_size=0)
    check("empty-lookup-fault", Memory([(TABLE, raw), (REGISTRY, registry_bytes())]), LOOKUP, status=UNMAPPED)
    raw = synthetic_table([0x11112222, 0x33334444])
    check("truncated-selected-halfword", Memory([(TABLE, raw[:-3]), (REGISTRY, registry_bytes())]), LOOKUP, 1, status=UNMAPPED)
    # Adjacent regions must not let a consumer walk out of its backing object.
    split = len(raw) - 4
    check("consumer-cross-object", Memory([(TABLE, raw[:split]), (TABLE + split, raw[split:]),
          (REGISTRY, registry_bytes())]), LOOKUP, 1, status=UNMAPPED)
    check("zero-budget", Memory([(TABLE, b"TBL1")], budget=0), PAYLOAD, TABLE, status=BUDGET, reads=0)
    record(output / "results.json", results)
    return {"corpus": corpus_totals, "boundary_cases": len(results) - sum(corpus_totals.values()),
            "total": len(results), "all_input_bytes_unchanged": True,
            "all_faults_preserve_result_sentinel": True,
            "results_sha256": digest(output / "results.json")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--vcvarsall", type=Path)
    args = parser.parse_args()
    output = local_path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    dll, toolchain = build(output, args.vcvarsall)
    record(output / "toolchain.json", toolchain)
    validation = exercise(dll, output)
    # Compile faulty adapters in isolated local directories; source stays intact.
    # These expose layout, input-width, call-order and map-validation mistakes.
    mutations = {
        "registry-field": ("+ id * 16 + 4, 4)", "+ id * 16 + 8, 4)"),
        "narrow-pair-key": ("candidate == key", "candidate == (key & UINT32_C(65535))"),
        "cache-pair-count": (
            "uint32_t index;\n    for (index = 0; !e->status && index < count(e, section); ++index)",
            "uint32_t index;\n    uint32_t cached = count(e, section);\n    for (index = 0; !e->status && index < cached; ++index)"),
        "accept-overlap": (
            "if ((uint64_t)r->address < (uint64_t)other->address + other->size &&",
            "if (other->size == 0 && (uint64_t)r->address < (uint64_t)other->address + other->size &&"),
    }
    negatives = []
    original = (ROOT / ADAPTER[0]).read_text()
    for name, (old, new) in mutations.items():
        if original.count(old) != 1:
            raise RuntimeError(f"Mutation anchor changed: {name}")
        negative = output / ("negative-" + name)
        negative.mkdir()
        source = negative / "mutant.c"
        source.write_text(original.replace(old, new), encoding="utf-8")
        mutant_dll, _ = build(negative, Path(toolchain["vcvarsall"]), source)
        try:
            exercise(mutant_dll, negative)
        except AssertionError as failure:
            item = {"mutant": name, "rejected": True, "failure": str(failure),
                    "source_sha256": digest(source), "dll_sha256": digest(mutant_dll)}
            record(negative / "NEGATIVE.json", item)
            negatives.append(item)
        else:
            raise AssertionError(f"Surviving native adapter mutant: {name}")
    record(output / "negatives.json", negatives)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_diff = subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", *SOURCES],
                                 cwd=ROOT, capture_output=True)
    if source_diff.returncode not in (0, 1):
        raise RuntimeError("Cannot determine recovered source revision state")
    manifest = {"status": "validated", "scope": "A08 host address/registry research; synthetic only",
        "base_revision": revision, "recovered_files_sha256": {p: digest(ROOT / p) for p in SOURCES},
        "adapter_files_sha256": {p: digest(ROOT / p) for p in ADAPTER},
        "validation_files_sha256": {p: digest(ROOT / p) for p in VALIDATION},
        "toolchain_sha256": digest(output / "toolchain.json"), "dll_sha256": digest(dll),
        "validation": validation, "compiled_mutants_rejected": len(negatives),
        "negatives_sha256": digest(output / "negatives.json"),
        "game_data_used": False, "arm_emulation_used": False,
        "recovered_source_differs_from_base_revision": source_diff.returncode == 1, "source_transfer": False,
        "live_gameplay_validation": False, "g1_passed": False, "g2_passed": False, "g3_passed": False}
    record(output / "COMPLETE.json", manifest)
    print(json.dumps({"output": str(output.relative_to(ROOT)), **validation}))


if __name__ == "__main__":
    main()
