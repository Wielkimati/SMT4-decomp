"""Public synthetic admission/evidence checks; no game files or native compiler."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_nkm_host_reference import (admit_snapshot, admission_negatives,
                                     observation_rows, synthetic_identity,
                                     synthetic_snapshot)


class AdmissionTests(unittest.TestCase):
    def test_exact_synthetic_profile(self):
        raw = synthetic_snapshot()
        result = admit_snapshot(raw, synthetic_identity(raw))
        self.assertEqual([s.entry_count for s in result.sections[2:4]], [1201, 1201])
        self.assertEqual(result.raw, raw)

    def test_identity_structure_and_alignment_failures(self):
        results = admission_negatives()
        self.assertEqual({item["case"] for item in results}, {
            "size", "identity", "magic", "directory", "section-outside",
            "payload-extent", "zero-stride", "count", "alignment"})
        self.assertTrue(all(item["rejected"] and item["synthetic_only"] for item in results))

    def test_missing_consumed_section(self):
        raw = bytearray(synthetic_snapshot())
        struct.pack_into("<I", raw, 8, 3)
        raw = bytes(raw)
        with self.assertRaisesRegex(ValueError, "Missing consumed"):
            admit_snapshot(raw, synthetic_identity(raw))

    def test_partial_record_rejected(self):
        raw = bytearray(synthetic_snapshot())
        container = admit_snapshot(bytes(raw), synthetic_identity(raw))
        struct.pack_into("<I", raw, container.sections[3].offset + 4, 4803)
        raw = bytes(raw)
        with self.assertRaisesRegex(ValueError, "section layout"):
            admit_snapshot(raw, synthetic_identity(raw))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cases = Path(self.temp.name) / "cases.tsv"
        self.results = Path(self.temp.name) / "results.tsv"
        self.header = "fixture\tkey\texpected\tcount"
        self.rows = ["pair_synthetic\t7\t50\t3", "pair_synthetic\t8\t123\t3"]
        self.observations = [self.rows[0] + "\t50\t50", self.rows[1] + "\t123\t123"]

    def check(self):
        self.cases.write_text(self.header + "\n" + "\n".join(self.rows) + "\n")
        self.results.write_text(self.header + "\toriginal\trebuilt\n" + "\n".join(self.observations) + "\n")
        return observation_rows(self.cases, self.results)

    def test_complete(self):
        self.assertEqual(len(self.check()), 2)

    def test_missing(self):
        self.observations.pop()
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.check()

    def test_reordered_or_wrong_input(self):
        self.observations.reverse()
        with self.assertRaisesRegex(ValueError, "inputs differ"):
            self.check()

    def test_duplicate(self):
        self.rows[1] = self.rows[0]
        self.observations[1] = self.observations[0]
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.check()

    def test_false_original_or_rebuilt(self):
        for suffix in ("\t51\t50", "\t50\t51"):
            with self.subTest(suffix=suffix):
                self.observations[0] = self.rows[0] + suffix
                with self.assertRaisesRegex(ValueError, "result differs"):
                    self.check()


if __name__ == "__main__":
    unittest.main()
