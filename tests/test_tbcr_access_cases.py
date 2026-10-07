"""Check helper corpus coverage/guard fixtures without private game data."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from tbcr_access_cases import TABLE, write_helper_cases


class TbcrAccessCorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)
        self.counts = write_helper_cases(self.output)
        self.rows = [row.split("\t") for row in
                     (self.output / "helpers.tsv").read_text().splitlines()[1:]]
        self.cases = {(fixture, helper, int(r0), int(r1)): int(expected)
                      for fixture, helper, r0, r1, expected in self.rows}

    def test_coverage_and_minimal_guard_backing(self):
        self.assertEqual(len(self.cases), len(self.rows))
        self.assertEqual(len(self.rows), sum(self.counts.values()))
        for fixture, helper, r0, r1, expected in self.rows:
            self.assertTrue((self.output / f"{fixture}.bin").is_file())
        self.assertEqual((self.output / "magic_42414421.bin").read_bytes(), b"BAD!")
        self.assertEqual((self.output / "empty_container.bin").stat().st_size, 12)
        # Returning a payload pointer requires neither a full header nor a payload read.
        self.assertEqual(self.cases["magic_54424c31", "tbl1_payload", TABLE, 0], TABLE + 16)

    def test_modular_address_cases(self):
        self.assertEqual(self.cases["null_selected_pointer", "tbcr_select_section", TABLE, 0], 0)
        self.assertEqual(self.cases["wrapping_offset_sum", "tbcr_select_section", TABLE, 0], TABLE + 16)
        for index in (0x40000000, 0x80000000, 0xC0000000):
            self.assertEqual(self.cases["wrapping_index_shift", "tbcr_select_section", TABLE, index], TABLE + 16)
        self.assertEqual(self.cases["wrapping_index_shift", "tbcr_select_section", TABLE, 0xFFFFFFFF], 0)

    def test_registry_boundaries_and_decoy_fields(self):
        registry = (self.output / "registry_boundaries.registry.bin").read_bytes()
        self.assertEqual(len(registry), 67 * 16)
        for slot, section_offset in ((0, 16), (1, 0x110), (66, 0x210)):
            self.assertEqual(self.cases["registry_boundaries", "resource_select_tbcr_section", slot, 0],
                             TABLE + section_offset)
            fields = struct.unpack_from("<4I", registry, slot * 16)
            self.assertEqual(fields[0], fields[2])
            self.assertEqual(fields[2], fields[3])
            self.assertNotEqual(fields[1], fields[0])
        for slot in (2, 65, 67, 0x80000000, 0xFFFFFFFF):
            self.assertEqual(self.cases["registry_boundaries", "resource_select_tbcr_section", slot, 0], 0)

    def test_unsigned_count_edges_without_payload_allocations(self):
        found = set()
        for fixture, helper, r0, r1, expected in self.rows:
            if not fixture.startswith("count_") or helper != "tbl1_entry_count":
                continue
            raw = (self.output / f"{fixture}.bin").read_bytes()
            self.assertEqual(len(raw), 16)
            _, size, stride, _ = struct.unpack("<4sIII", raw)
            found.add((size, stride, int(expected)))
        for case in ((0xFFFFFFFF, 1, 0xFFFFFFFF), (0x80000000, 0xFFFFFFFF, 0),
                     (0xFFFFFFFF, 0x80000000, 1), (7, 4, 1), (0xFFFFFFFF, 0, 0)):
            self.assertIn(case, found)


if __name__ == "__main__":
    unittest.main()
