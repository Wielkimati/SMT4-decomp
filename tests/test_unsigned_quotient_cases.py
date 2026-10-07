"""Check the independent division corpus, without private reference data."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from unsigned_quotient_cases import MAX, division_cases


class DivisionCorpusTests(unittest.TestCase):
    def test_oracle_and_domain(self):
        cases = division_cases()
        self.assertEqual(cases, division_cases())
        self.assertEqual(len(cases), len({(a, b) for a, b, _ in cases}))
        for a, b, q in cases:
            self.assertTrue(0 <= a <= MAX and 1 <= b <= MAX)
            self.assertTrue(q * b <= a < (q + 1) * b)

    def test_dispatch_edges_and_full_width(self):
        cases = {(a, b): q for a, b, q in division_cases()}
        for shift in [2, 5, 8, 12, 16, 24]:
            for delta in [-1, 0, 1]:
                self.assertIn(((3 << shift) + delta, 3), cases)
        for bit in range(32):
            b = 1 << bit
            self.assertEqual(cases[b - 1, b], 0)
            self.assertEqual(cases[b, b], 1)
        self.assertEqual(cases[MAX, 1], MAX)
        self.assertEqual(cases[MAX, 0x80000000], 1)
        self.assertEqual(cases[0, MAX], 0)


if __name__ == "__main__":
    unittest.main()
