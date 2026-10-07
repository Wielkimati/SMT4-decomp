"""Synthetic structural/bounds tests; no game assets are required."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import tbcr
from inventory_resources import inventory


def fixture() -> bytes:
    # Nonzero opaque bytes ensure no zero-padding assumptions slip in.
    first = struct.pack("<4sIII", b"TBL1", 6, 2, 0x89abcdef) + b"abcdef" + b"!?"
    second = struct.pack("<4sIII", b"TBL1", 0, 0, 16) + b"tail"
    return struct.pack("<4sIIII", b"TBCR", 24, 2, 4, 4 + len(first)) + b"head" + b"lead" + first + second


def word(raw: bytes, offset: int, value: int) -> bytes:
    result = bytearray(raw)
    struct.pack_into("<I", result, offset, value)
    return bytes(result)


class TbcrTests(unittest.TestCase):
    def test_sections_and_unknown_bytes_are_preserved(self):
        raw = fixture()
        table = tbcr.parse(raw)
        self.assertEqual(table.relative_offsets, (4, 28))
        self.assertEqual(table.header_extra, b"head")
        self.assertEqual(table.leading_bytes, b"lead")
        first, second = table.sections
        self.assertEqual(first.offset, 28)
        self.assertEqual(first.unknown_0c, 0x89abcdef)
        self.assertEqual(first.entry_count, 3)
        self.assertEqual(first.entry(0), b"ab")
        self.assertEqual(first.entry(2), b"ef")
        self.assertEqual(first.trailing_bytes, b"!?")
        self.assertEqual(second.payload, b"")
        self.assertIsNone(second.entry_count)
        # Reassemble through all exposed extents, including unknown bytes.
        parts = [raw[:20], table.header_extra, table.leading_bytes]
        for section in table.sections:
            parts.extend([raw[section.offset:section.offset + 16], section.payload, section.trailing_bytes])
        self.assertEqual(b"".join(parts), raw)

    def test_all_truncations_before_last_payload_end_are_rejected(self):
        raw = fixture()
        # Last section has no payload: its header ends at 68; trailing data is optional.
        for length in range(68):
            with self.subTest(length=length), self.assertRaises(tbcr.FormatError):
                tbcr.parse(raw[:length])
        self.assertEqual(len(tbcr.parse(raw[:68]).sections), 2)

    def test_bad_magic_is_rejected(self):
        for offset in (0, 28, 52):
            with self.subTest(offset=offset), self.assertRaises(tbcr.FormatError):
                tbcr.parse(word(fixture(), offset, 0))

    def test_bad_directory_extents_and_counts_are_rejected(self):
        for offset, value in [(4, 0), (4, 16), (4, 0xffffffff), (8, 0xffffffff),
                              (12, 0xffffffff), (16, 4), (16, 3), (16, 8),
                              (32, 0xffffffff), (32, 9), (56, 5)]:
            with self.subTest(offset=offset, value=value), self.assertRaises(tbcr.FormatError):
                tbcr.parse(word(fixture(), offset, value))

    def test_nondivisible_payload_is_retained_but_not_record_sliced(self):
        section = tbcr.parse(word(fixture(), 36, 4)).sections[0]
        self.assertEqual(section.payload, b"abcdef")
        self.assertEqual(section.entry_count, 1)
        self.assertEqual(section.remainder_size, 2)
        with self.assertRaises(tbcr.FormatError):
            section.entry(0)

    def test_zero_stride_is_retained_but_not_record_sliced(self):
        section = tbcr.parse(word(fixture(), 36, 0)).sections[0]
        self.assertEqual(section.payload, b"abcdef")
        self.assertIsNone(section.remainder_size)
        with self.assertRaises(tbcr.FormatError):
            section.entry(0)

    def test_entry_bounds(self):
        section = tbcr.parse(fixture()).sections[0]
        for index in (-1, 3, 0xffffffff):
            with self.subTest(index=index), self.assertRaises(IndexError):
                section.entry(index)

    def test_operational_limits_are_enforced(self):
        with patch.object(tbcr, "MAX_SECTIONS", 1), self.assertRaises(tbcr.FormatError):
            tbcr.parse(fixture())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.tbb"
            path.write_bytes(fixture())
            with patch.object(tbcr, "MAX_FILE_BYTES", 12), self.assertRaises(tbcr.FormatError):
                tbcr.read(path)

    def test_empty_directory_and_mutable_input(self):
        table = tbcr.parse(struct.pack("<4sII", b"TBCR", 12, 0) + b"opaque")
        self.assertEqual(table.leading_bytes, b"opaque")
        with self.assertRaises(TypeError):
            tbcr.parse(bytearray(fixture()))

    def test_inventory_includes_non_tbb_and_reports_invalid_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "valid.bin").write_bytes(fixture())
            (root / "bad.tbb").write_bytes(b"oops")
            (root / "empty.bin").write_bytes(b"")
            result = inventory(root)
            self.assertEqual(result["file_count"], 3)
            self.assertEqual([t["path"] for t in result["tables"]], ["valid.bin"])
            self.assertEqual([t["path"] for t in result["rejected"]], ["bad.tbb"])


if __name__ == "__main__":
    unittest.main()
