"""Check that synthetic comparison cases distinguish the consumer's edge rules."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from nkm_pair_cases import pair_table, write_pair_cases
from tbcr import parse


class PairCorpusTests(unittest.TestCase):
    def test_first_match_full_key_fallback_and_fixed_stride(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            table = root / "reference.bin"
            table.write_bytes(pair_table([(i, i + 100) for i in range(1201)]))
            counts = write_pair_cases(root, table)
            rows = [line.split("\t") for line in (root / "pairs.tsv").read_text().splitlines()[1:]]
            cases = {(name, int(key)): int(value) for name, key, value, count in rows}
            self.assertEqual(len(cases), sum(counts.values()))
            for name, key, value in [
                ("one", 7, 65432), ("one", 65543, 50),
                ("duplicate", 7, 321), ("zero_first", 7, 50),
                ("width", 0, 65535), ("width", 7, 32768),
                ("width", 65535, 65000), ("floor", 8, 50),
                ("stride_eight", 8, 456), ("stride_eight", 9, 50),
                ("stride_two", 10, 321), ("reference", 1200, 1300),
            ]:
                self.assertEqual(cases["pair_" + name, key], value)
            for name in ("empty", "zero_count", "zero_stride", "missing", "bad_container", "bad_section"):
                self.assertEqual(cases["pair_" + name, 7], 50)
            empty = parse((root / "pair_empty.bin").read_bytes()).sections[3]
            self.assertEqual(len(empty.payload), 0)
            self.assertEqual(empty.entry_count, 0)


if __name__ == "__main__":
    unittest.main()
