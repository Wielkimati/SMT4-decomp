"""Opt-in private file-to-memory evidence bridge, not a native resource loader.

Reuses completed original/GCC observations; runs no ARM instructions. All private
bytes and generated observations stay under local/. Default host checks remain
synthetic-only in check_nkm_host_boundary.py.
"""
from __future__ import annotations

import argparse
import csv
import ctypes as C
import hashlib
import json
from pathlib import Path
import struct

import check_nkm_host_boundary as host
from check_nkm_lookup import write_cases
from ghidra_reference import ROOT, CODE_HASH, check_hash, local_path
from nkm_pair_cases import write_pair_cases
from tbcr import parse

TABLE = "local/reference-eu/base/0000/romfs/battle/NKMSortIndex.tbb"
CODE = "local/reference-eu/base/0000/exefs/code.bin"
CONTRACT = "config/nkm-host-contract.json"
VALIDATION = ["tools/check_nkm_lookup.py", "tools/ghidra/CompareNkmLookup.java",
              "tools/tbcr_access_cases.py", "tools/unsigned_quotient_cases.py",
              "tools/nkm_pair_cases.py", "config/recovery-tools.json",
              "config/analysis-tools.json"]


def admit_snapshot(raw: bytes, identity: dict):
    """Research admission policy, deliberately stricter than original helpers.

    Identity is supplied by the pinned contract in the private command; synthetic
    tests supply their own identity to reach structural checks without game data.
    """
    if len(raw) != identity["resource_bytes"]:
        raise ValueError("Table size mismatch")
    if hashlib.sha256(raw).hexdigest() != identity["resource_sha256"]:
        raise ValueError("Table SHA-256 mismatch")
    container = parse(raw)
    if len(container.sections) < 4:
        raise ValueError("Missing consumed sections")
    if container.section_base % 4 or any(s.offset % 4 for s in container.sections):
        raise ValueError("Unaligned section header")
    for section in container.sections[2:4]:
        if section.entry_size != 4 or section.entry_count != 1201 or section.remainder_size:
            raise ValueError("Unexpected consumed section layout")
    return container


def observation_rows(cases: Path, observations: Path):
    """Require complete, ordered original/rebuilt evidence for exact TSV inputs."""
    with cases.open(newline="", encoding="ascii") as stream:
        expected = csv.DictReader(stream, delimiter="\t")
        fields, rows = expected.fieldnames, list(expected)
    with observations.open(newline="", encoding="ascii") as stream:
        actual = csv.DictReader(stream, delimiter="\t")
        if actual.fieldnames != fields + ["original", "rebuilt"]:
            raise ValueError("Observation columns differ")
        results = list(actual)
    if len(rows) != len(results) or not rows:
        raise ValueError("Incomplete observations")
    seen = set()
    for row, result in zip(rows, results):
        if {key: result[key] for key in fields} != row:
            raise ValueError("Observation inputs differ")
        key = tuple(row.values())
        if key in seen:
            raise ValueError("Duplicate observation")
        seen.add(key)
        if result["original"] != row["expected"] or result["rebuilt"] != row["expected"]:
            raise ValueError("Original/rebuilt result differs")
    return results


def verify_unit(unit: Path, fixtures: Path, contract: dict):
    previous = json.loads((unit / "COMPLETE.json").read_text())
    reference, artifact = contract["reference"], contract["arm_unit"]
    if previous["reference_sha256"] != CODE_HASH or previous["table_sha256"] != reference["resource_sha256"]:
        raise ValueError("Unit reference identity differs")
    if (previous["binary_sha256"] != artifact["binary_sha256"] or
            previous["binary_bytes"] != artifact["bytes"] or
            (unit / "nkm-sort-index.bin").stat().st_size != artifact["bytes"]):
        raise ValueError("Unit binary identity differs")
    check_hash(unit / "nkm-sort-index.bin", artifact["binary_sha256"])
    sources = {item["path"]: item["working_file_sha256"] for item in contract["recovered_files"]}
    recorded = {name.replace("\\", "/"): value for name, value in previous["source_files_sha256"].items()}
    if recorded != sources or set(sources) != set(host.SOURCES):
        raise ValueError("Unit source inventory differs")
    if set(previous["validation_files_sha256"]) != set(VALIDATION):
        raise ValueError("Unit validation inventory differs")
    for name, sha256 in {**sources, **previous["validation_files_sha256"]}.items():
        check_hash(ROOT / name, sha256)
    comparison = json.loads((unit / "comparison.json").read_text())
    if comparison != previous["comparison"]:
        raise ValueError("Unit comparison differs from manifest")
    if (not comparison["recovered_table_helpers"] or not comparison["recovered_quotient"] or
            previous["rebuilt_path_original_code_required"] or
            "SMT4_NKM_COMPARE_OK" not in (unit / "comparison.log").read_text()):
        raise ValueError("Expected completed recovered pair-mode comparison")
    identities = {}
    for path in sorted(fixtures.iterdir()):
        # Names come only from the unchanged deterministic fixture generators.
        expected = host.digest(path)
        check_hash(unit / "fixtures" / path.name, expected)
        identities[path.name] = expected
    groups = {}
    for name, cases, results, counter, manifest_counts in (
            ("lookup", "cases.tsv", "results.tsv", "lookup_cases", "fixtures"),
            ("pairs", "pairs.tsv", "pairs-results.tsv", "pair_cases", "pair_cases")):
        rows = observation_rows(fixtures / cases, unit / results)
        counts = {}
        for row in rows:
            counts[row["fixture"]] = counts.get(row["fixture"], 0) + 1
        if comparison[counter] != len(rows) or previous[manifest_counts] != counts:
            raise ValueError("Unit observation coverage differs")
        groups[name] = rows
    return groups, {"path": unit.relative_to(ROOT).as_posix(),
        "files_sha256": {name: host.digest(unit / name) for name in (
            "COMPLETE.json", "nkm-sort-index.bin", "comparison.json", "comparison.log",
            "results.tsv", "pairs-results.tsv")},
        "regenerated_fixtures_sha256": identities,
        "source_and_validation_identities_checked": True,
        "observations_checked": {name: len(rows) for name, rows in groups.items()},
        "arm_execution": "reused completed original/GCC observations; not rerun"}


def synthetic_snapshot():
    sections = []
    for records in ([struct.pack("<I", 123)], [struct.pack("<I", 456)],
                    [struct.pack("<I", i) for i in range(1201)],
                    [struct.pack("<HH", i, i % 37) for i in range(1201)]):
        payload = b"".join(records)
        sections.append(struct.pack("<4sIII", b"TBL1", len(payload), 4, 0) + payload)
    offsets, size = [], 0
    for section in sections:
        offsets.append(size)
        size += len(section)
    return struct.pack("<4sII4I", b"TBCR", 28, 4, *offsets) + b"".join(sections)


def synthetic_identity(raw):
    return {"resource_bytes": len(raw), "resource_sha256": hashlib.sha256(raw).hexdigest()}


def admission_negatives():
    raw = synthetic_snapshot()
    container = admit_snapshot(raw, synthetic_identity(raw))
    cases = [("size", raw[:-1], synthetic_identity(raw)),
             ("identity", b"NOPE" + raw[4:], synthetic_identity(raw))]
    mutations = [("magic", 0, b"NOPE"), ("directory", 8, struct.pack("<I", 0xFFFFFFFF)),
                 ("section-outside", 24, struct.pack("<I", 0xFFFFFFFC)),
                 ("payload-extent", container.sections[3].offset + 4, struct.pack("<I", 0xFFFFFFFF)),
                 ("zero-stride", container.sections[2].offset + 8, bytes(4)),
                 ("count", container.sections[2].offset + 4, struct.pack("<I", 4800))]
    for name, offset, replacement in mutations:
        changed = raw[:offset] + replacement + raw[offset + len(replacement):]
        cases.append((name, changed, synthetic_identity(changed)))
    # Valid parser structure, unsupported aligned-load boundary.
    unaligned = bytearray(raw[:28] + b"!" + raw[28:])
    struct.pack_into("<I", unaligned, 4, 29)
    cases.append(("alignment", bytes(unaligned), synthetic_identity(unaligned)))
    results = []
    for name, changed, identity in cases:
        try:
            admit_snapshot(changed, identity)
        except ValueError as error:
            results.append({"case": name, "rejected": True, "reason": str(error),
                            "synthetic_only": True})
        else:
            raise AssertionError(f"Admission failure accepted: {name}")
    return results


def exercise(dll: Path, raw: bytes, groups: dict, fixtures: Path):
    library = C.CDLL(str(dll))
    evaluate = library.smt4_host_eval
    evaluate.argtypes = [C.POINTER(host.Space), C.c_uint32, C.c_uint32, C.c_uint32,
                         C.POINTER(C.c_uint32), C.POINTER(C.c_uint32)]
    evaluate.restype = C.c_int
    results = []
    # Second placement exercises the full private file above 2 GiB near u32 end.
    for address in (host.TABLE, 0xFFFF0000):
        for group, rows in groups.items():
            selected = {"reference"} if group == "lookup" else {
                "pair_reference", "pair_duplicate", "pair_zero_first"}
            for row in rows:
                if row["fixture"] not in selected:
                    continue
                private = row["fixture"] in ("reference", "pair_reference")
                backing = raw if private else (fixtures / (row["fixture"] + ".bin")).read_bytes()
                memory = host.Memory([(address, backing), (host.REGISTRY, host.registry_bytes(address))])
                value, reads = C.c_uint32(host.SENTINEL), C.c_uint32(0)
                argument = int(row["index" if group == "lookup" else "key"])
                status = evaluate(C.byref(memory.space), host.LOOKUP if group == "lookup" else host.PAIRS,
                                  argument, 0, C.byref(value), C.byref(reads))
                if status != host.OK or value.value != int(row["original"]) or value.value != int(row["rebuilt"]):
                    raise AssertionError(f"Host/ARM mismatch: {group}/{row['fixture']}/{argument}")
                memory.unchanged()
                results.append({"group": group, "fixture": row["fixture"], "argument": argument,
                                "table_address": address, "private_reference": private,
                                "original": int(row["original"]), "rebuilt": int(row["rebuilt"]),
                                "host": value.value, "status": status, "reads": reads.value})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--unit", required=True, help="Completed --recover-pairs output under local/")
    parser.add_argument("--table", default=TABLE, help="Pinned table input under local/ (identity unchanged)")
    parser.add_argument("--vcvarsall", type=Path)
    args = parser.parse_args()
    output, unit = local_path(args.output), local_path(args.unit)
    table = local_path(args.table)
    if output.exists():
        raise FileExistsError("Choose a fresh output directory")
    contract = json.loads((ROOT / CONTRACT).read_text())
    pins = json.loads((ROOT / "config/recovery-tools.json").read_text())
    reference = contract["reference"]
    if (reference["expanded_code_sha256"] != CODE_HASH or reference["resource_bytes"] != 50400 or
            reference["resource_sha256"] != pins["nkm_sort_index_sha256"]):
        raise ValueError("Contract/reference pins disagree")
    check_hash(ROOT / CODE, CODE_HASH)
    with table.open("rb") as stream:
        raw = stream.read(reference["resource_bytes"] + 1)
    container = admit_snapshot(raw, reference)
    output.mkdir(parents=True)
    fixtures = output / "fixtures"
    fixtures.mkdir()
    write_cases(fixtures, table)
    write_pair_cases(fixtures, table)
    groups, reuse = verify_unit(unit, fixtures, contract)
    host.record(output / "reused-unit.json", reuse)
    host.record(output / "table-summary.json", container.summary())
    negatives = admission_negatives()
    host.record(output / "admission-negatives.json", negatives)
    dll, toolchain = host.build(output, args.vcvarsall)
    host.record(output / "toolchain.json", toolchain)
    results = exercise(dll, raw, groups, fixtures)
    host.record(output / "host-results.json", results)
    check_hash(table, reference["resource_sha256"])
    check_hash(ROOT / CODE, CODE_HASH)
    # Capture every artifact consumed in reuse and every generated observation.
    evidence = [output / name for name in ("reused-unit.json", "table-summary.json",
        "admission-negatives.json", "toolchain.json", "host-results.json", "nkm-host.dll",
        "build-command.json", "build.log")]
    tools = ["tools/check_nkm_host_reference.py", "tools/tbcr.py", CONTRACT,
             *host.ADAPTER, *host.VALIDATION, *host.SOURCES]
    summary = {"total": len(results), "private_reference": sum(r["private_reference"] for r in results),
               "synthetic_first_match": sum(not r["private_reference"] for r in results),
               "admission_failures_rejected": len(negatives), "all_mapped_bytes_unchanged": True}
    host.record(output / "COMPLETE.json", {"status": "validated",
        "scope": "A08 private file-to-memory host evidence bridge; stable synthetic registry",
        "reference_sha256": CODE_HASH, "table_sha256": reference["resource_sha256"],
        "table_input": table.relative_to(ROOT).as_posix(),
        "validation": summary, "unit": reuse["path"],
        "files_sha256": {p.relative_to(ROOT).as_posix(): host.digest(p)
                         for p in [*evidence, *(ROOT / name for name in tools)]},
        "inputs_unchanged": True, "arm_observations_reused": True, "arm_execution_this_run": False,
        "new_recovered_entry_points": 0, "source_transfer": False, "runtime_services": False,
        "live_validation": False, "g1_passed": False, "g2_passed": False, "g3_passed": False})
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
