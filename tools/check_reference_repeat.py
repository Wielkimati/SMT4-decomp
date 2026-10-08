"""Verify two complete private preparations; this does not validate a decoder independently."""

import argparse
import json
from pathlib import Path, PurePosixPath
import sys

from prepare_reference import REPO, check_log, inventory, sha256, write_json


# Accepted G0 identities: docs/reference-eu.md and docs/recovery/nkm-host-boundary.md.
SELECTED = {
    "exefs-original/code.bin": (2141552, "c9fafbf3a4e46e5f8b984e5b060d7cb90d12f4a0244bbe7440b2cfd97be4f2d9"),
    "exefs/code.bin": (3633152, "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),
    "exheader.bin": (2048, "27305333aae9ce837964861a589ee3e44bb7ae234041d31bf97a20bba79cf29e"),
    "romfs/battle/NKMSortIndex.tbb": (50400, "194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4"),
}


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def confined(root, relative):
    """Manifest paths must be canonical relative POSIX paths, even on Windows."""
    value = PurePosixPath(relative)
    if (not relative or "\\" in relative or ":" in relative or value.is_absolute()
            or ".." in value.parts or value.as_posix() != relative):
        raise ValueError("Unsafe manifest path")
    target = (root / relative).resolve()
    if target == root or not target.is_relative_to(root):
        raise ValueError("Manifest path escaped its root")
    return target


def index_rows(rows):
    result = {}
    for row in rows:
        name = row["path"]
        if name in result:
            raise ValueError("Duplicate inventory path")
        result[name] = row
    return result


def load_preparation(root, config):
    """Rehash inventory bytes and logs; a COMPLETE marker alone is insufficient."""
    root = root.resolve(strict=True)
    complete = read_json(root / "COMPLETE.json")
    documents = {}
    for name in ("inputs", "files", "manifest"):
        path = root / (name + ".json")
        if sha256(path) != complete[name + "_sha256"]:
            raise ValueError(f"{name} manifest hash mismatch")
        documents[name] = read_json(path)
    manifest = documents["manifest"]
    if manifest["reference_name"] != config["reference_name"] or manifest["tool"] != config["ctrtool"]:
        raise ValueError("Reference/tool identity mismatch")
    expected = index_rows(documents["files"])
    for name in expected:
        confined(root, name)
    actual = []
    for package in config["packages"]:
        role = package["role"]
        for row in inventory(confined(root, role)):
            row["path"] = role + "/" + row["path"]
            actual.append(row)
        matches = [r for r in documents["inputs"]["files"] if r["sha256"] == package["sha256"]]
        if len(matches) != 1:
            raise ValueError("Input package identity mismatch")
        contents = [r for r in manifest["contents"] if r["role"] == role]
        if len(contents) != package["content_count"]:
            raise ValueError("Content count mismatch")
    if index_rows(actual) != expected or manifest["file_count"] != len(expected):
        raise ValueError("Extracted file inventory mismatch")
    for content in manifest["contents"]:
        if expected[content["file"]]["sha256"] != content["sha256"]:
            raise ValueError("Content identity mismatch")
    executable = [r for r in manifest["contents"] if r["role"] == "base"
                  and r["form_type"] == "Executable" and r["content_type"] == "Application"]
    if len(executable) != 1 or executable[0] != manifest["main_executable"]:
        raise ValueError("Executable selection mismatch")
    logs = []
    for command in manifest["commands"]:
        path = confined(root, command["log"])
        log = path.read_text(encoding="utf-8", errors="replace")
        exceptions = check_log(log, command["returncode"])
        if "(GOOD)" not in log or exceptions != command["signature_exceptions"]:
            raise ValueError("Verification log mismatch")
        logs.append({"path": command["log"], "sha256": sha256(path),
                     "signature_exception_lines": len(exceptions)})
    if not logs:
        raise ValueError("Missing verification commands")
    documents["logs_checked"] = logs
    documents["complete_sha256"] = sha256(root / "COMPLETE.json")
    return documents


def compare_preparations(baseline, repeat, selected=SELECTED):
    if index_rows(baseline["inputs"]["files"]) != index_rows(repeat["inputs"]["files"]):
        raise ValueError("Input inventories differ")
    if index_rows(baseline["files"]) != index_rows(repeat["files"]):
        raise ValueError("Output inventories differ")
    for key in ("reference_name", "tool", "main_executable", "contents", "file_count", "extension_counts"):
        if baseline["manifest"][key] != repeat["manifest"][key]:
            raise ValueError(f"Preparation metadata differs: {key}")
    main = repeat["manifest"]["main_executable"]
    prefix = main["role"] + "/" + main["index"] + "/"
    rows = index_rows(repeat["files"])
    matches = []
    for suffix, (size, digest) in selected.items():
        row = rows[prefix + suffix]
        if (row["size"], row["sha256"]) != (size, digest):
            raise ValueError(f"Accepted reference identity mismatch: {suffix}")
        matches.append(row)
    return {"status": "validated", "input_files": len(repeat["inputs"]["files"]),
            "extracted_files": len(rows), "contents": len(repeat["manifest"]["contents"]),
            "selected": matches, "independent_decoder_validation": False,
            "scope": "Same pinned CTRTool, complete repeat extraction; no decoder independence or authenticity claim."}


def check_paths(baseline, repeat, output):
    roots = [p.resolve() for p in (baseline, repeat, output)]
    local = (REPO / "local").resolve()
    if roots[2] == local or not roots[2].is_relative_to(local):
        raise ValueError("Output must be a new subdirectory inside repo/local/")
    for i, left in enumerate(roots):
        for right in roots[i + 1:]:
            if left.is_relative_to(right) or right.is_relative_to(left):
                raise ValueError("Preparation and evidence roots must be distinct and non-overlapping")
    if roots[2].exists():
        raise ValueError("Output already exists; no overwrite")
    return roots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=REPO / "local/reference-eu")
    parser.add_argument("--repeat", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    baseline, repeat, output = check_paths(args.baseline, args.repeat, args.output)
    config = read_json(REPO / "config/reference-eu.json")
    print("Rehashing both preparations and checking recorded verification logs...", flush=True)
    old = load_preparation(baseline, config)
    new = load_preparation(repeat, config)
    result = compare_preparations(old, new)
    output.mkdir(parents=True)
    write_json(output / "comparison.json", result)
    write_json(output / "preparations.json", {
        "baseline": {"root": str(baseline), "complete_sha256": old["complete_sha256"], "logs": old["logs_checked"]},
        "repeat": {"root": str(repeat), "complete_sha256": new["complete_sha256"], "logs": new["logs_checked"]}})
    write_json(output / "COMPLETE.json", {
        "status": "validated", "independent_decoder_validation": False,
        "comparison_sha256": sha256(output / "comparison.json"),
        "preparations_sha256": sha256(output / "preparations.json"),
        "checker_sha256": sha256(Path(__file__)),
        "prepare_script_sha256": sha256(REPO / "tools/prepare_reference.py"),
        "config_sha256": sha256(REPO / "config/reference-eu.json")})
    print(f"Matched {result['extracted_files']} files and {result['contents']} contents; decoder independence remains open.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Repeat check failed: {error}", file=sys.stderr)
        sys.exit(1)
