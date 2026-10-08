"""Independently read the pinned table from preserved NCCH; no CIA/IVFC verification."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys

from ncch_romfs import Limits, read_file
from prepare_reference import sha256, write_json
from check_reference_repeat import confined, index_rows
from check_code_decoder import check_paths


REPO = Path(__file__).resolve().parents[1]
CONTENT = "base/content.0000.00000000"
TABLE = "base/0000/romfs/battle/NKMSortIndex.tbb"
ROMFS_PATH = "battle/NKMSortIndex.tbb"
PINS = {
    CONTENT: (1875677184, "92d6feba05dbcacda8efb7d51dab6c2da35c079e4e2130848e9a56b1b96c824a"),
    TABLE: (50400, "194158b3cd8c31a24a65ecb1c66407a1444126ec07ab60661c9b1f8afc99c7a4"),
}


def admission(reference, config, pins=PINS):
    """Verify the accepted inventory and selected actual files, not a fresh intake."""
    reference = reference.resolve(strict=True)
    documents, hashes = {}, {}
    complete_path = reference / "COMPLETE.json"
    complete = json.loads(complete_path.read_text(encoding="utf-8"))
    hashes["COMPLETE.json"] = sha256(complete_path)
    for name in ("inputs", "files", "manifest"):
        path = reference / (name + ".json")
        digest = sha256(path)
        if digest != complete[name + "_sha256"]:
            raise ValueError(f"Stale reference {name} manifest")
        documents[name] = json.loads(path.read_text(encoding="utf-8"))
        hashes[path.name] = digest
    manifest = documents["manifest"]
    if manifest["reference_name"] != config["reference_name"] or manifest["tool"] != config["ctrtool"]:
        raise ValueError("Reference preparation identity mismatch")
    selected = [r for r in manifest["contents"] if r["role"] == "base"
                and r["form_type"] == "Executable" and r["content_type"] == "Application"]
    if len(selected) != 1 or selected[0] != manifest["main_executable"]:
        raise ValueError("Ambiguous main executable metadata")
    main = selected[0]
    if (main["file"] != CONTENT or main["title_id"] != "0004000000141c00" or
            main["product_code"] != "CTR-N-AMXP" or main["crypto"] != "None" or
            main["sha256"] != pins[CONTENT][1]):
        raise ValueError("Unexpected selected executable metadata")
    inventory = index_rows(documents["files"])
    selected_rows = {}
    for name, (size, digest) in pins.items():
        path = confined(reference, name)
        row = inventory.get(name)
        if not row or (row["size"], row["sha256"]) != (size, digest):
            raise ValueError(f"Pinned inventory identity mismatch: {name}")
        if path.stat().st_size != size or sha256(path) != digest:
            raise ValueError(f"Pinned actual file identity mismatch: {name}")
        hashes[name] = digest
        selected_rows[name] = row
    return {"metadata_sha256": {k: v for k, v in hashes.items() if k.endswith(".json")},
            "selected_inventory": selected_rows, "main_executable": main,
            "input_sha256": hashes}


def compare_metadata(details):
    header = details["ncch"]
    if (header["program_id"] != "0004000000141c00" or
            header["partition_id"] != "0004000000141c00" or
            header["product_code"] != "CTR-N-AMXP"):
        raise ValueError("Independent NCCH identity differs from accepted metadata")


def run(reference, output):
    reference, output = check_paths(reference, output, REPO / "local")
    config = json.loads((REPO / "config/reference-eu.json").read_text(encoding="utf-8"))
    admitted = admission(reference, config)
    content = confined(reference, CONTENT)
    expected = confined(reference, TABLE).read_bytes()
    with content.open("rb") as stream:
        data, details = read_file(stream, content.stat().st_size, ROMFS_PATH,
                                  Limits(file_bytes=PINS[TABLE][0]))
    compare_metadata(details)
    if data != expected or hashlib.sha256(data).hexdigest() != PINS[TABLE][1]:
        raise ValueError("Independent table bytes differ from accepted extraction")
    output.mkdir(parents=True)
    target = output / "NKMSortIndex.tbb"  # Never construct a host path from untrusted names.
    with target.open("xb") as stream:
        stream.write(data)
    if target.read_bytes() != expected:
        raise ValueError("Written table bytes differ")
    # Whole selected NCCH/table hashes and reference records checked before/after.
    for name, digest in admitted["input_sha256"].items():
        if sha256(confined(reference, name)) != digest:
            raise ValueError(f"Input changed during validation: {name}")
    details.update(status="validated", comparison="byte-for-byte", table_bytes=len(data),
                   table_sha256=hashlib.sha256(data).hexdigest(), reference_root=str(reference))
    write_json(output / "admission.json", admitted)
    write_json(output / "comparison.json", details)
    files = [output / n for n in ("admission.json", "comparison.json", "NKMSortIndex.tbb")]
    sources = ["tools/ncch_romfs.py", "tools/check_ncch_romfs.py", "tools/prepare_reference.py",
               "tools/check_reference_repeat.py", "tools/check_code_decoder.py", "config/reference-eu.json"]
    write_json(output / "COMPLETE.json", {
        "status": "validated", "scope": "Bounded independent NCCH/RomFS table path extraction",
        "content_sha256": PINS[CONTENT][1], "table_sha256": PINS[TABLE][1],
        "table_bytes": len(data), "all_table_bytes_equal": True, "inputs_unchanged": True,
        "python": sys.version, "platform": platform.platform(),
        "files_sha256": {p.relative_to(REPO).as_posix(): sha256(p) for p in files},
        "implementation_sha256": {n: sha256(REPO / n) for n in sources},
        "cia_decoding": False, "ivfc_hash_verification": False,
        "full_filesystem_validation": False, "new_recovered_entry_points": 0,
        "runtime_services": False, "g3_passed": False})
    return details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=REPO / "local/reference-eu")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.reference, args.output)
    print(f"Independent NCCH/RomFS read matches all {result['table_bytes']:,} table bytes; "
          f"offset 0x{result['romfs']['file_ncch_offset']:X}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as error:
        print(f"NCCH/RomFS check failed: {error}", file=sys.stderr)
        sys.exit(1)
