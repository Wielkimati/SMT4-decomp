"""Synthetic repeat-preparation evidence and failure tests; no game data or tools."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location("check_reference_repeat", TOOLS / "check_reference_repeat.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class RepeatTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = {"reference_name": "synthetic", "ctrtool": {"version": "fake"},
                       "packages": [{"role": "base", "sha256": "synthetic-input", "content_count": 1}]}

    def write(self, path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def seal(self, root):
        self.write(root / "COMPLETE.json", {name + "_sha256": CHECK.sha256(root / (name + ".json"))
                                           for name in ("inputs", "files", "manifest")})

    def fixture(self, name):
        root = self.root / name
        (root / "base/0000").mkdir(parents=True)
        (root / "base/0000/payload").write_bytes(b"synthetic bytes")
        rows = CHECK.inventory(root / "base")
        for row in rows:
            row["path"] = "base/" + row["path"]
        main = {"role": "base", "index": "0000", "file": rows[0]["path"],
                "sha256": rows[0]["sha256"], "form_type": "Executable", "content_type": "Application"}
        log = "Region: (GOOD)\n"
        (root / "verify.txt").write_text(log, encoding="utf-8")
        self.write(root / "files.json", rows)
        self.write(root / "inputs.json", {"root": str(root / "fake-game"), "files": [
            {"path": "fake-input", "size": 42, "sha256": "synthetic-input", "first_16_bytes": ""}]})
        self.write(root / "manifest.json", {"reference_name": "synthetic", "tool": self.config["ctrtool"],
            "main_executable": main, "contents": [main], "file_count": 1, "extension_counts": {"<none>": 1},
            "commands": [{"log": "verify.txt", "returncode": 0, "signature_exceptions": []}]})
        self.seal(root)
        return root

    def test_complete_repeat_matches_with_different_absolute_input_roots(self):
        left = CHECK.load_preparation(self.fixture("left"), self.config)
        right = CHECK.load_preparation(self.fixture("right"), self.config)
        row = left["files"][0]
        result = CHECK.compare_preparations(left, right, {"payload": (row["size"], row["sha256"])})
        self.assertEqual(result["extracted_files"], 1)
        self.assertIs(result["independent_decoder_validation"], False)

    def test_missing_or_stale_complete_is_rejected(self):
        root = self.fixture("missing")
        (root / "COMPLETE.json").unlink()
        with self.assertRaises(FileNotFoundError):
            CHECK.load_preparation(root, self.config)
        root = self.fixture("stale")
        (root / "files.json").write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "manifest hash mismatch"):
            CHECK.load_preparation(root, self.config)

    def test_actual_missing_changed_and_extra_files_are_rejected(self):
        for change in ("missing", "changed", "extra"):
            with self.subTest(change=change):
                root = self.fixture(change)
                payload = root / "base/0000/payload"
                if change == "missing":
                    payload.unlink()
                elif change == "changed":
                    payload.write_bytes(b"wrong bytes")
                else:
                    (payload.parent / "extra").write_bytes(b"unrecorded")
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    CHECK.load_preparation(root, self.config)

    def test_failed_verification_cannot_hide_behind_complete(self):
        root = self.fixture("bad-log")
        (root / "verify.txt").write_text("Region: (GOOD)\nHash: (FAIL)\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "verification diagnostic"):
            CHECK.load_preparation(root, self.config)

    def test_wrong_tool_duplicate_paths_and_wrong_executable_are_rejected(self):
        for change in ("tool", "duplicate", "executable"):
            with self.subTest(change=change):
                root = self.fixture(change)
                if change == "duplicate":
                    rows = CHECK.read_json(root / "files.json")
                    self.write(root / "files.json", rows + rows)
                else:
                    manifest = CHECK.read_json(root / "manifest.json")
                    if change == "tool":
                        manifest["tool"] = {"version": "wrong"}
                    else:
                        manifest["main_executable"]["index"] = "ffff"
                    self.write(root / "manifest.json", manifest)
                self.seal(root)
                with self.assertRaises(ValueError):
                    CHECK.load_preparation(root, self.config)

    def test_input_drift_and_common_wrong_selected_identity_are_rejected(self):
        old = CHECK.load_preparation(self.fixture("baseline"), self.config)
        new = copy.deepcopy(old)
        new["inputs"]["files"][0]["sha256"] = "changed"
        with self.assertRaisesRegex(ValueError, "Input inventories differ"):
            CHECK.compare_preparations(old, new, {})
        with self.assertRaisesRegex(ValueError, "Accepted reference identity mismatch"):
            CHECK.compare_preparations(old, old, {"payload": (0, "wrong")})

    def test_manifest_paths_cannot_escape(self):
        for value in ("../outside", "/absolute", "C:/outside", "base\\payload", "base/../outside", "base//payload", "."):
            with self.subTest(value=value), self.assertRaises(ValueError):
                CHECK.confined(self.root, value)

    def test_evidence_roots_cannot_overlap_or_overwrite(self):
        local = CHECK.REPO / "local"
        for baseline, repeat, output in (
            (local / "a", local / "a", local / "z"),
            (local / "a", local / "b", local / "b/child"),
            (local / "a", local / "b", CHECK.REPO / "outside"),
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                CHECK.check_paths(baseline, repeat, output)
        with tempfile.TemporaryDirectory(dir=local if local.exists() else CHECK.REPO) as existing:
            with self.assertRaises(ValueError):
                CHECK.check_paths(local / "a", local / "b", Path(existing))


if __name__ == "__main__":
    unittest.main()
