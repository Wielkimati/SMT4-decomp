"""Data-free checks for the import wrapper's input/output safeguards."""
import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "ghidra_reference", Path(__file__).resolve().parents[1] / "tools/ghidra_reference.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ImportSafeguardTests(unittest.TestCase):
    def test_output_cannot_escape_local(self):
        for name in ("../outside", "local/../../outside", "local", "docs/import"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE.local_path(name)
        self.assertEqual(MODULE.local_path("local/ghidra/synthetic"),
                         MODULE.ROOT / "local/ghidra/synthetic")

    def test_tampered_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.dat"
            path.write_bytes(b"synthetic reference")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            MODULE.check_hash(path, expected)
            path.write_bytes(b"changed reference")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                MODULE.check_hash(path, expected)


if __name__ == "__main__":
    unittest.main()
