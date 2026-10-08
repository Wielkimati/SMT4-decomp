"""Independently expand the pinned compressed EU code; compare all output bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import sys

from code_lz import decode


REPO = Path(__file__).resolve().parents[1]
# Accepted G0 identities, not supplied by the candidate decoder.
IDENTITIES = {
    "exefs-original/code.bin": (2141552, "c9fafbf3a4e46e5f8b984e5b060d7cb90d12f4a0244bbe7440b2cfd97be4f2d9"),
    "exefs/code.bin": (3633152, "834938d18d2b7c688311c46c27bed813d0d7a9f8e3cbb61da8a6a3f23d360ebd"),
    "exheader.bin": (2048, "27305333aae9ce837964861a589ee3e44bb7ae234041d31bf97a20bba79cf29e"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_paths(reference, output, local):
    reference, output, local = (p.resolve() for p in (reference, output, local))
    if output == local or not output.is_relative_to(local):
        raise ValueError("Output must be a fresh subdirectory inside repo/local/")
    if output.is_relative_to(reference) or reference.is_relative_to(output):
        raise ValueError("Reference and output roots must not overlap")
    if output.exists():
        raise ValueError("Output already exists; no overwrite")
    return reference, output


def compare(blobs, identities=IDENTITIES):
    for name, (size, sha) in identities.items():
        if (len(blobs[name]), digest(blobs[name])) != (size, sha):
            raise ValueError(f"Pinned identity mismatch: {name}")
    exheader = blobs["exheader.bin"]
    if len(exheader) < 0x40 or not exheader[0xD] & 1:
        raise ValueError("ExHeader does not select compressed code")
    allocated = sum(int.from_bytes(exheader[o:o + 4], "little") * 4096
                    for o in (0x14, 0x24, 0x34))
    expected = blobs["exefs/code.bin"]
    if allocated != len(expected):
        raise ValueError("ExHeader segment allocation differs from expanded size")
    # Never pass the already expanded image into the decoder.
    decoded, details = decode(blobs["exefs-original/code.bin"], max_output=len(expected))
    if decoded != expected:
        raise ValueError("Independent output differs from accepted expanded bytes")
    return decoded, {"status": "validated", "comparison": "byte-for-byte",
                     "decoded_size": len(decoded), "decoded_sha256": digest(decoded),
                     "exheader_flags": exheader[0xD], "segment_allocation": allocated,
                     **details}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=REPO / "local/reference-eu/base/0000")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reference, output = check_paths(args.reference, args.output, REPO / "local")
    blobs = {name: (reference / name).read_bytes() for name in IDENTITIES}
    decoded, result = compare(blobs)
    output.mkdir(parents=True)
    (output / "code.bin").write_bytes(decoded)
    if (output / "code.bin").read_bytes() != blobs["exefs/code.bin"]:
        raise ValueError("Written output differs from accepted expanded bytes")
    # Rehash private inputs after the check; none are opened for writing.
    for name, blob in blobs.items():
        if (reference / name).read_bytes() != blob:
            raise ValueError(f"Input changed during validation: {name}")
    result["reference_root"] = str(reference)
    result["input_identities"] = {n: {"size": len(b), "sha256": digest(b)} for n, b in blobs.items()}
    write_json(output / "comparison.json", result)
    write_json(output / "COMPLETE.json", {
        "status": "validated", "scope": "Independent compressed ExeFS code expansion only",
        "independent_decoder_validation": True, "inputs_unchanged": True,
        "python": sys.version, "platform": platform.platform(),
        "comparison_sha256": digest((output / "comparison.json").read_bytes()),
        "decoded_sha256": digest(decoded),
        "implementation_sha256": {name: digest((REPO / name).read_bytes()) for name in
                                  ("tools/code_lz.py", "tools/check_code_decoder.py")},
        "container_filesystem_independence": False,
        "new_recovered_entry_points": 0})
    print(f"Independent expansion matches all {len(decoded):,} bytes; {digest(decoded)}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"Decoder check failed: {error}", file=sys.stderr)
        sys.exit(1)
