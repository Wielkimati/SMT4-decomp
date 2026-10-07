import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from resource_order_cases import remainder_cases, index_cases


class ResourceOrderCasesTest(unittest.TestCase):
    def test_remainder_domain_and_boundary_coverage(self):
        rows = remainder_cases()
        pairs = {(a, b) for a, b, _ in rows}
        self.assertEqual(len(rows), len(pairs))
        for width in range(34, 67):
            for dividend in [0, 1, width-1, width, width+1, 65535]:
                self.assertIn((dividend, width), pairs)
        for a, b, r in rows:
            self.assertTrue(0 <= a <= 65535 and 34 <= b <= 66)
            self.assertTrue(0 <= r < b)
            self.assertEqual((a-r) % b, 0)

    def test_inverse_seeds_reach_each_target(self):
        reached = set()
        for seed, lower, upper, state, result in index_cases():
            self.assertTrue(0 <= seed <= 0xffffffff)
            self.assertEqual((seed * 0x41c64e6d + 0x3039) & 0xffffffff, state)
            self.assertEqual(upper, 66)
            self.assertTrue(1 <= lower <= 33 and lower <= result <= upper)
            reached.add((state >> 16, 67-lower, state & 65535))
        self.assertEqual(reached, {(a, b, lo) for a, b, _ in remainder_cases() for lo in [0, 65535]})


if __name__ == "__main__":
    unittest.main()
