"""Inventory local resource prefixes and bounded TBCR summaries, without exporting assets."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

import tbcr
from ghidra_reference import ROOT, local_path


def inventory(root: Path) -> dict:
    signatures = Counter()
    tables = []
    rejected = []
    file_count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # Never follow a link to input outside the selected resource tree.
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"Resource path escapes input root: {path}")
        with path.open("rb") as stream:
            prefix = stream.read(4)
        file_count += 1
        signatures[(path.suffix.lower(), prefix.hex())] += 1
        if prefix != b"TBCR" and path.suffix.lower() != ".tbb":
            continue
        relative = path.relative_to(root).as_posix()
        try:
            tables.append({"path": relative, **tbcr.read(path).summary()})
        except tbcr.FormatError as error:
            rejected.append({"path": relative, "error": str(error)})
    return {
        "schema": 1, "file_count": file_count,
        "signatures": [{"extension": ext, "prefix_hex": prefix, "count": count}
                       for (ext, prefix), count in sorted(signatures.items())],
        "tables": tables, "rejected": rejected,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--romfs", type=Path,
                        default=ROOT / "local/reference-eu/base/0000/romfs")
    parser.add_argument("--output", required=True, help="New directory under repository local/")
    args = parser.parse_args()
    output = local_path(args.output)
    root = args.romfs.resolve()
    if not root.is_dir():
        parser.error("--romfs must be an existing directory")
    if output.is_relative_to(root):
        parser.error("Output must be outside the input resource tree")
    output.mkdir(parents=True, exist_ok=False)
    report = inventory(root)
    (output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    result = {"file_count": report["file_count"], "accepted_tables": len(report["tables"]),
              "rejected_tables": len(report["rejected"]),
              "input_root": str(root), "report": "inventory.json"}
    (output / "COMPLETE.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if report["rejected"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
