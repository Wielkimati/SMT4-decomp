"""Validate the comparison corpus using synthetic data only; not game execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_nkm_lookup import synthetic_table, write_cases
from tbcr import parse


class NkmCorpusTests(unittest.TestCase):
    def test_decoy_sections_and_opaque_word(self):
        table = parse(synthetic_table([0xBEEF8001, 0xCAFEFFFF]))
        self.assertEqual(len(table.sections), 3)
        self.assertEqual(table.sections[2].unknown_0c, 0xA5A51234)
        self.assertEqual(bytes(table.sections[2].payload), b"\x01\x80\xef\xbe\xff\xff\xfe\xca")
        self.assertNotEqual(table.sections[0].payload[:2], table.sections[2].payload[:2])
        self.assertNotEqual(table.sections[1].payload[:2], table.sections[2].payload[:2])

    def test_oracle_covers_width_stride_and_unsigned_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reference = root / "synthetic-reference.bin"
            reference.write_bytes(synthetic_table([0xBEEF0000 + i for i in range(1201)]))
            out = root / "cases"
            out.mkdir()
            counts = write_cases(out, reference)
            rows = [line.split("\t") for line in (out / "cases.tsv").read_text().splitlines()[1:]]
            cases = {(name, int(index)): int(expected) for name, index, expected in rows}
            self.assertEqual(len(cases), sum(counts.values()))
            self.assertEqual(cases["reference", 1200], 1200)
            for index in [1201, 0x80000000, 0xFFFFFFFF]:
                self.assertEqual(cases["reference", index], 0)
            self.assertEqual([cases["halfwords", i] for i in range(4)], [65535, 32768, 0, 258])
            self.assertEqual(cases["fixed_stride", 1], 0x55AA)
            self.assertEqual(cases["floor_count", 1], 0x1234)
            self.assertEqual(cases["zero_count_readable", 0], 0xABCD)
            self.assertEqual(cases["zero_divisor_readable", 0], 0x4321)

    def test_fixture_size_and_count_are_independent_of_readable_backing(self):
        section = parse(synthetic_table([0xCAFE1234, 0xBEEF5678], declared_size=7)).sections[2]
        self.assertEqual(section.entry_count, 1)
        self.assertEqual(section.remainder_size, 3)
        self.assertEqual(len(section.trailing_bytes), 1)


if __name__ == "__main__":
    unittest.main()
