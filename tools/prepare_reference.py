"""Prepare this project's identified EU dumps using pinned CTRTool 1.3.0.

Inputs are read-only. Outputs and full tool logs must stay under repo/local/.
CTRTool's --contents option is a filename prefix, despite its help saying dir.
NCCH extraction automatically decompresses .code using ExHeader metadata.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


REPO = Path(__file__).resolve().parents[1]
SIGNATURE_ERRORS = (
    "[ctrtool::CiaProcess ERROR] Signature for Ticket was invalid.",
    "[ctrtool::CiaProcess ERROR] Signature for TitleMetaData was invalid.",
    "[ctrtool::NcchProcess ERROR] Signature for NcchHeader was invalid.",
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, data):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def check_log(text, returncode):
    """CTRTool can return zero despite failed verification: inspect diagnostics."""
    if returncode:
        raise ValueError(f"CTRTool exited with {returncode}; see local log")
    exceptions = []
    for line in text.splitlines():
        if "ERROR]" in line or "WARN" in line or "(FAIL)" in line:
            # stderr may interrupt a tree-prefix line when streams are combined.
            if any(line.strip().endswith(message) for message in SIGNATURE_ERRORS):
                exceptions.append(line.strip())
            elif re.match(r"^\s*(?:\|-\s*)?(?:DigitalSignature|Signature):\s*\(FAIL\)", line):
                exceptions.append(line.strip())
            else:
                raise ValueError("Unexpected CTRTool verification diagnostic; see local log")
    return exceptions


def run_tool(tool, output, name, arguments, commands, verify=False):
    args = [str(tool), *map(str, arguments)]
    log = output / "logs" / f"{name}.txt"
    with log.open("xb") as stream:
        result = subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT, check=False)
    text = log.read_text(encoding="utf-8", errors="replace")
    exceptions = check_log(text, result.returncode)
    if verify and "(GOOD)" not in text:
        raise ValueError(f"No successful verification checks in {name}")
    commands.append({"argv": args, "returncode": result.returncode,
                     "log": log.relative_to(output).as_posix(),
                     "signature_exceptions": exceptions})
    write_json(output / "logs" / f"{name}.command.json", commands[-1])
    return text


def field(text, label):
    match = re.search(r"^" + re.escape(label) + r"\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else None


def inventory(root):
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Inventory encountered a file outside its root")
        with path.open("rb") as stream:
            prefix = stream.read(16)
        rows.append({"path": path.relative_to(root).as_posix(),
                     "size": path.stat().st_size, "sha256": sha256(path),
                     "first_16_bytes": prefix.hex()})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-dir", type=Path, default=REPO.parent / "Game")
    parser.add_argument("--ctrtool", type=Path,
                        default=REPO / "local/tools/ctrtool-v1.3.0/bin/ctrtool.exe")
    parser.add_argument("--output", type=Path, default=REPO / "local/reference-eu")
    args = parser.parse_args()
    game = args.game_dir.resolve(strict=True)
    tool = args.ctrtool.resolve(strict=True)
    output = args.output.resolve()
    local = (REPO / "local").resolve()
    if output == local or not output.is_relative_to(local):
        raise ValueError("Output must be a new subdirectory inside repo/local/")
    if output.is_relative_to(game) or game.is_relative_to(output):
        raise ValueError("Input and output directories must not overlap")
    if output.exists():
        raise ValueError("Output already exists; choose a new directory (no overwrite/resume)")

    config = json.loads((REPO / "config/reference-eu.json").read_text(encoding="utf-8"))
    if sha256(tool) != config["ctrtool"]["executable_sha256"]:
        raise ValueError("CTRTool executable hash does not match pinned Windows x64 release")

    print("Hashing input files...", flush=True)
    inputs = inventory(game)
    selected = {}
    for package in config["packages"]:
        matches = [row for row in inputs if row["sha256"] == package["sha256"]]
        if len(matches) != 1:
            raise ValueError(f"Expected one identified {package['role']} package; found {len(matches)}")
        selected[package["role"]] = game / matches[0]["path"]
    known_cias = {path.resolve() for path in selected.values()}
    if any((game / row["path"]).suffix.lower() == ".cia"
           and (game / row["path"]).resolve() not in known_cias for row in inputs):
        raise ValueError("Unidentified CIA found; inspect it before extending the reference config")

    output.mkdir(parents=True)
    (output / "logs").mkdir()
    write_json(output / "inputs.json", {"root": str(game), "files": inputs})
    commands = []
    contents = []
    for package in config["packages"]:
        role = package["role"]
        print(f"Verifying and extracting {role} package...", flush=True)
        folder = output / role
        folder.mkdir()
        text = run_tool(tool, output, f"{role}-cia", ["--verify", "--raw",
                        f"--contents={folder / 'content'}", selected[role]], commands, verify=True)
        tmd = text.split("TitleMetaData:", 1)[1].split("NCCH:", 1)[0]
        ids = re.findall(r"TitleId:\s*([0-9a-fA-F]{16})", tmd)
        versions = re.findall(r"TitleVersion:.*\((\d+)\)", tmd)
        if ids != [package["title_id"]] or versions != [str(package["title_version"])]:
            raise ValueError(f"{role}: unexpected title identity/version")
        if len(re.findall(r"Hash: \(GOOD\)", tmd)) != package["content_count"]:
            raise ValueError(f"{role}: incorrect count of verified content hashes")
        if "Encrypted:   YES" in tmd:
            raise ValueError("This reference pipeline expects decrypted CIA content")
        paths = sorted(folder.glob("content.*"))
        if len(paths) != package["content_count"]:
            raise ValueError(f"{role}: unexpected number of extracted contents")

        for content in paths:
            index = content.name.split(".")[1]
            target = folder / index
            target.mkdir()
            print(f"  {role} content {index}: verifying and unpacking...", flush=True)
            text = run_tool(tool, output, f"{role}-{index}", ["--verify",
                            f"--exheader={target / 'exheader.bin'}",
                            f"--exefs={target / 'exefs.bin'}",
                            f"--exefsdir={target / 'exefs'}",
                            f"--romfsdir={target / 'romfs'}", content], commands, verify=True)
            contents.append({"role": role, "index": index,
                             "file": content.relative_to(output).as_posix(),
                             "sha256": sha256(content),
                             "title_id": field(text, "Title id:"),
                             "product_code": field(text, "Product code:"),
                             "form_type": field(text, " > FormType:"),
                             "content_type": field(text, " > ContentType:"),
                             "crypto": field(text, " > Crypto Key")})
            exefs = target / "exefs.bin"
            if exefs.is_file():
                # Keep on-disk compressed bytes separately from the automatic expansion.
                run_tool(tool, output, f"{role}-{index}-exefs-original",
                         ["--verify", "--raw", "--intype=exefs",
                          f"--exefsdir={target / 'exefs-original'}", exefs], commands, verify=True)

    executable = [row for row in contents if row["role"] == "base"
                  and row["form_type"] == "Executable" and row["content_type"] == "Application"]
    if len(executable) != 1:
        raise ValueError("Expected one main executable application, selected by NCCH metadata")
    print("Hashing extracted files...", flush=True)
    files = []
    for role in selected:
        for row in inventory(output / role):
            row["path"] = f"{role}/{row['path']}"
            files.append(row)
    write_json(output / "files.json", files)
    manifest = {"reference_name": config["reference_name"], "tool": config["ctrtool"],
                "main_executable": executable[0], "contents": contents,
                "commands": commands, "file_count": len(files),
                "extension_counts": dict(Counter(Path(row["path"]).suffix.lower() or "<none>"
                                                 for row in files)),
                "verification_note": "Content checks passed; listed signature exceptions are retained. "
                                     "This verifies internal integrity, not retail authenticity."}
    write_json(output / "manifest.json", manifest)
    # Detect input changes during preparation without modifying the input files.
    if inventory(game) != inputs:
        raise ValueError("Input files changed during preparation; output is not a stable reference")
    write_json(output / "COMPLETE.json", {"manifest_sha256": sha256(output / "manifest.json"),
                                         "files_sha256": sha256(output / "files.json"),
                                         "inputs_sha256": sha256(output / "inputs.json")})
    print(f"Prepared {len(contents)} contents; {len(files)} extracted files. Output: {output}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, IndexError) as error:
        print(f"Preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
