"""Bounded, read-only TBCR/TBL1 inspection; no record semantics are assumed."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 65536


class FormatError(ValueError):
    """Input is outside the supported TBCR/TBL1 structural profile."""


@dataclass(frozen=True)
class Section:
    index: int
    offset: int
    end: int
    payload_size: int
    entry_size: int
    unknown_0c: int
    raw: bytes

    @property
    def payload(self) -> memoryview:
        return memoryview(self.raw)[self.offset + 16:self.offset + 16 + self.payload_size]

    @property
    def trailing_bytes(self) -> memoryview:
        return memoryview(self.raw)[self.offset + 16 + self.payload_size:self.end]

    @property
    def entry_count(self) -> int | None:
        return self.payload_size // self.entry_size if self.entry_size else None

    @property
    def remainder_size(self) -> int | None:
        return self.payload_size % self.entry_size if self.entry_size else None

    def entry(self, index: int) -> memoryview:
        # Require an exact fixed-size layout before offering record slicing.
        if not self.entry_size or self.remainder_size:
            raise FormatError("Section does not have an exact nonzero entry-size layout")
        if not 0 <= index < self.entry_count:
            raise IndexError("Section entry index out of range")
        start = index * self.entry_size
        return self.payload[start:start + self.entry_size]


@dataclass(frozen=True)
class Container:
    raw: bytes
    section_base: int
    relative_offsets: tuple[int, ...]
    sections: tuple[Section, ...]

    @property
    def header_extra(self) -> memoryview:
        return memoryview(self.raw)[12 + 4 * len(self.sections):self.section_base]

    @property
    def leading_bytes(self) -> memoryview:
        end = self.sections[0].offset if self.sections else len(self.raw)
        return memoryview(self.raw)[self.section_base:end]

    def summary(self) -> dict:
        return {
            "size": len(self.raw),
            "sha256": hashlib.sha256(self.raw).hexdigest(),
            "section_base": self.section_base,
            "section_count": len(self.sections),
            "relative_offsets": list(self.relative_offsets),
            "header_extra_size": len(self.header_extra),
            "leading_size": len(self.leading_bytes),
            "sections": [{
                "index": s.index, "offset": s.offset, "end": s.end,
                "payload_size": s.payload_size, "entry_size": s.entry_size,
                "unknown_0c": s.unknown_0c, "entry_count_quotient": s.entry_count,
                "remainder_size": s.remainder_size,
                "trailing_size": len(s.trailing_bytes),
                "payload_sha256": hashlib.sha256(s.payload).hexdigest(),
            } for s in self.sections],
        }


def parse(raw: bytes) -> Container:
    """Validate extents, retaining unknown words, payloads, gaps and trailing bytes.

    This tool deliberately checks more bounds than the original pointer helpers.
    It is not a reconstruction of their behavior on malformed input.
    """
    if not isinstance(raw, bytes):
        raise TypeError("parse requires immutable bytes")
    size = len(raw)
    if size < 12 or size > 0xffffffff:
        raise FormatError("Container size is outside the 32-bit TBCR profile")
    magic, base, count = struct.unpack_from("<4sII", raw)
    if magic != b"TBCR":
        raise FormatError("Expected TBCR signature")
    # Check before allocating/iterating based on a file-controlled count.
    if base < 12 or base > size or count > (base - 12) // 4:
        raise FormatError("Section offset directory does not fit before section base")
    if count > MAX_SECTIONS or count > (size - base) // 16:
        raise FormatError("Section count exceeds the file capacity or analysis limit")
    offsets = tuple(struct.unpack_from("<I", raw, 12 + i * 4)[0] for i in range(count))
    starts = tuple(base + offset for offset in offsets)
    for i, start in enumerate(starts):
        if start > size - 16:
            raise FormatError(f"Section {i} header is outside the file")
        if i and start <= starts[i - 1]:
            raise FormatError("Section offsets must be strictly increasing")
    sections = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < count else size
        if end - start < 16:
            raise FormatError(f"Section {i} overlaps the next header")
        signature, payload_size, entry_size, unknown = struct.unpack_from("<4sIII", raw, start)
        if signature != b"TBL1":
            raise FormatError(f"Section {i}: expected TBL1 signature")
        if payload_size > end - start - 16:
            raise FormatError(f"Section {i} payload exceeds its extent")
        sections.append(Section(i, start, end, payload_size, entry_size, unknown, raw))
    return Container(raw, base, offsets, tuple(sections))


def read(path: Path) -> Container:
    # Bounded read also handles files growing between stat and read.
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise FormatError(f"File exceeds analysis limit of {MAX_FILE_BYTES} bytes")
    return parse(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(read(args.file).summary(), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
