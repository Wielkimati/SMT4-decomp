"""Synthetic checks of ABI evidence completeness and observation validation."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from check_table_abi import fingerprint, validate_results


class AbiEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "observations.tsv"
        self.rows = ["kind\tprofile\theader\tdividend\tdivisor\tr0\tr1\tstack_depth"]
        for kind in range(4):
            for profile in range(2):
                self.rows.append(f"{kind}\t{profile}\t0\t17\t5\t3\t{5 if kind % 2 else 2}\t{8 if kind % 2 else 0}")
        for kind in (2, 3):
            for profile in range(2):
                for header in range(3):
                    self.rows.append(f"{kind}\t{profile}\t{header}\t17\t{0 if header == 0 else 5}\t0\t0\t0")

    def check(self):
        self.path.write_text("\n".join(self.rows) + "\n", encoding="ascii")
        return validate_results(self.path, {"calls": 20}, [(17, 5, 3)])

    def test_complete_observations(self):
        self.assertEqual(self.check(), {"independently_checked_rows": 20,
                                      "direct_original_rebuilt_r1_differences": 2})

    def test_missing_observation(self):
        self.rows.pop()
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            self.check()

    def test_duplicate_observation(self):
        self.rows[-1] = self.rows[-2]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.check()

    def test_remainder_corruption(self):
        self.rows[1] = self.rows[1].replace("\t3\t2\t0", "\t3\t0\t0")
        with self.assertRaisesRegex(ValueError, "remainder"):
            self.check()

    def test_stack_depth_drift(self):
        self.rows[3] = self.rows[3][:-1] + "0"
        with self.assertRaisesRegex(ValueError, "stack-depth"):
            self.check()

    def test_marker_scan_does_not_identify_compiler(self):
        result = fingerprint(b"\0GCC: synthetic\0NW4C_test\0__aeabi_uidiv\0")
        self.assertEqual(result["compiler_identity"], "unresolved")
        self.assertEqual(result["hits"]["compiler"][0]["virtual_address"], 0x100001)
        self.assertEqual([len(result["hits"][key]) for key in result["hits"]], [1, 1, 1])


if __name__ == "__main__":
    unittest.main()
