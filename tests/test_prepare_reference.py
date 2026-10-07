"""Check the preparation pipeline's failure handling without game data."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "tools/prepare_reference.py"
spec = importlib.util.spec_from_file_location("prepare_reference", SCRIPT)
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class VerificationTests(unittest.TestCase):
    def test_content_failure_is_fatal_even_with_zero_exit_code(self):
        with self.assertRaises(ValueError):
            prepare.check_log("Section hash: (FAIL) 1234\n", 0)

    def test_known_signature_failures_are_recorded(self):
        log = (prepare.SIGNATURE_ERRORS[0] + "\n"
               "|- DigitalSignature: (FAIL)\n"
               "Section hash: (GOOD) 1234\n")
        self.assertEqual(len(prepare.check_log(log, 0)), 2)

    def test_other_errors_are_not_hidden_by_known_signature_error(self):
        log = prepare.SIGNATURE_ERRORS[0] + "\n[ctrtool ERROR] Cannot read input.\n"
        with self.assertRaises(ValueError):
            prepare.check_log(log, 0)

    def test_access_descriptor_failure_is_not_allowed(self):
        with self.assertRaises(ValueError):
            prepare.check_log("Program id: 0004000000141c00 (FAIL)\n", 0)

    def test_nonzero_exit_code_is_fatal_even_with_successful_hash(self):
        with self.assertRaises(ValueError):
            prepare.check_log("Section hash: (GOOD) 1234\n", 1)

    def test_json_output_never_overwrites_an_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text("preserve me", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                prepare.write_json(path, {"replacement": True})
            self.assertEqual(path.read_text(encoding="utf-8"), "preserve me")

    def test_cli_refuses_output_outside_ignored_local_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            game = root / "game"
            game.mkdir()
            tool = root / "dummy.exe"
            tool.write_bytes(b"not executed")
            output = root / "output"
            result = subprocess.run([sys.executable, str(SCRIPT), "--game-dir", str(game),
                                     "--ctrtool", str(tool), "--output", str(output)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("inside repo/local/", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
