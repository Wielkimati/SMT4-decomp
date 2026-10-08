"""Synthetic containers only: independent expected bytes, malformed extents/graphs."""

import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import ncch_romfs as RF
import check_ncch_romfs as CHECK

N = 0xFFFFFFFF
PAYLOAD = b"Independent RomFS byte oracle.\x00\xff\x80"


def directory(parent, sibling, child, file, name):
    raw = name.encode("utf-16-le")
    return struct.pack("<6I", parent, sibling, child, file, N, len(raw)) + raw + bytes(-len(raw) % 4)


def file_record(parent, sibling, off, size, name):
    raw = name.encode("utf-16-le")
    return struct.pack("<IIQQII", parent, sibling, off, size, N, len(raw)) + raw + bytes(-len(raw) % 4)


def fixture(master=32, filename="NKMSortIndex.tbb"):
    # Fixed directory offsets and explicit file ordering catch wrong coordinate bases.
    dirs = (directory(0, N, 24, 0, "") + directory(0, 60, 96, 48, "battle") +
            directory(0, N, N, N, "other") + directory(24, N, N, N, "inner"))
    assert len(dirs) == 132
    selected = file_record(24, N, 32, len(PAYLOAD), filename)
    zero_offset = 104 + len(selected)
    selected = file_record(24, zero_offset, 32, len(PAYLOAD), filename)
    files = (file_record(0, N, 0, 4, "root.bin") +
             file_record(24, 104, 16, 7, "ignored.bin") + selected +
             file_record(24, N, 0, 0, "zero"))
    assert files[104:108] == struct.pack("<I", 24)
    file_meta = 0xC4
    data_offset = (file_meta + len(files) + 15) // 16 * 16
    level3 = (0x60 + master + 4095) // 4096 * 4096
    romfs = 0xC00
    romfs_size = level3 + 0x3000
    raw = bytearray(romfs + romfs_size)
    raw[0x100:0x104] = b"NCCH"
    struct.pack_into("<I", raw, 0x104, len(raw) // 512)
    struct.pack_into("<Q", raw, 0x108, 0x0004000000141C00)
    struct.pack_into("<H", raw, 0x112, 2)
    struct.pack_into("<Q", raw, 0x118, 0x0004000000141C00)
    raw[0x150:0x15A] = b"CTR-N-AMXP"
    struct.pack_into("<I", raw, 0x180, 0x400)
    raw[0x188:0x190] = bytes([0, 0, 0, 0, 1, 3, 0, 4])
    struct.pack_into("<III", raw, 0x1A0, 5, 1, 1)
    struct.pack_into("<III", raw, 0x1B0, 6, romfs_size // 512, 1)
    raw[romfs:romfs + 4] = b"IVFC"
    struct.pack_into("<II", raw, romfs + 4, 0x10000, master)
    for field, logical, size in ((0xC, 0, 32), (0x24, 0x1000, 32), (0x3C, 0x2000, 0x400)):
        struct.pack_into("<QQII", raw, romfs + field, logical, size, 12, 0)
    struct.pack_into("<II", raw, romfs + 0x54, 0x5C, 0)
    base = romfs + level3
    struct.pack_into("<10I", raw, base, 40, 40, 12, 52, len(dirs),
                     184, 12, file_meta, len(files), data_offset)
    raw[base + 52:base + 52 + len(dirs)] = dirs
    raw[base + file_meta:base + file_meta + len(files)] = files
    raw[base + data_offset:base + data_offset + 4] = b"ROOT"
    raw[base + data_offset + 16:base + data_offset + 23] = b"ignored"
    raw[base + data_offset + 32:base + data_offset + 32 + len(PAYLOAD)] = PAYLOAD
    return raw, {"romfs": romfs, "l3": base, "dirs": base + 52,
                 "files": base + file_meta, "selected": base + file_meta + 104,
                 "zero": base + file_meta + zero_offset, "data": base + data_offset,
                 "data_relative": data_offset}


def read(raw, path=CHECK.ROMFS_PATH, **limits):
    return RF.read_file(io.BytesIO(raw), len(raw), path, RF.Limits(**limits))


class ReaderTests(unittest.TestCase):
    def test_independent_bytes_offsets_and_boundaries(self):
        raw, off = fixture()
        before = bytes(raw)
        value, detail = read(raw)
        self.assertEqual(value, PAYLOAD)
        self.assertEqual(detail["romfs"]["file_ncch_offset"], off["data"] + 32)
        self.assertEqual(detail["ivfc"]["level3_ncch_offset"], 0x1C00)
        self.assertEqual(detail["romfs"]["directory_records_indexed"], 4)
        self.assertEqual(detail["romfs"]["file_records_indexed"], 4)
        self.assertEqual(read(raw, "root.bin")[0], b"ROOT")
        self.assertEqual(read(raw, "battle/zero")[0], b"")
        self.assertEqual(raw, before)
        # Last byte and zero-size file exactly at the level boundary are valid.
        struct.pack_into("<QQ", raw, off["selected"] + 8, 0x400 - off["data_relative"] - 1, 1)
        raw[off["l3"] + 0x3FF] = 0xA7
        self.assertEqual(read(raw)[0], b"\xa7")
        struct.pack_into("<QQ", raw, off["zero"] + 8, 0x400 - off["data_relative"], 0)
        self.assertEqual(read(raw, "battle/zero")[0], b"")

    def test_master_hash_alignment_not_hardcoded(self):
        raw, off = fixture(master=4096)
        self.assertEqual(read(raw)[0], PAYLOAD)
        self.assertEqual(read(raw)[1]["ivfc"]["level3_ncch_offset"], 0x2C00)

    def test_utf16_case_sensitive_and_non_bmp(self):
        raw, off = fixture(filename="table_\u017c_\U0001f600.bin")
        self.assertEqual(read(raw, "battle/table_\u017c_\U0001f600.bin")[0], PAYLOAD)
        for name in ("battle/Table_\u017c_\U0001f600.bin", "Battle/table_\u017c_\U0001f600.bin"):
            with self.assertRaisesRegex(ValueError, "not found"):
                read(raw, name)

    def test_selected_file_offsets_never_wrap(self):
        for offset, size in ((RF.U64, 2), (1 << 63, 1), (0, RF.U64), (0x400, 0)):
            raw, off = fixture()
            struct.pack_into("<QQ", raw, off["selected"] + 8, offset, size)
            with self.subTest(offset=offset, size=size), self.assertRaisesRegex(ValueError, "file data"):
                read(raw)

    def test_ncch_admission_and_extents(self):
        mutations = [(0x100, b"CIA!"), (0x112, b"\x01\x00"), (0x18E, b"\xff"),
                     (0x18F, b"\0"), (0x18F, b"\x06"), (0x18D, b"\x09"),
                     (0x18C, b"\x02"), (0x180, struct.pack("<I", 0)),
                     (0x1B0, struct.pack("<I", N)), (0x1B4, struct.pack("<I", N)),
                     (0x1B0, struct.pack("<I", 5)), (0x1A0, bytes(4)),
                     (0x1A8, struct.pack("<I", 2)), (0x1B8, bytes(4)),
                     (0x194, struct.pack("<I", 1)), (0x104, struct.pack("<I", N))]
        for where, value in mutations:
            raw, off = fixture()
            raw[where:where + len(value)] = value
            with self.subTest(where=where, value=value.hex()), self.assertRaises(ValueError):
                read(raw)

    def test_ivfc_profile_logical_and_physical_bounds(self):
        changes = [(0, b"FAIL"), (4, bytes(4)), (8, bytes(4)), (8, struct.pack("<I", N)),
                   (0xC, struct.pack("<Q", 4096)), (0x24, struct.pack("<Q", RF.U64)),
                   (0x2C, struct.pack("<Q", RF.U64)), (0x3C, bytes(8)),
                   (0x44, struct.pack("<Q", RF.U64)), (0x44, struct.pack("<Q", 0x4000)),
                   (0x1C, struct.pack("<I", 32)), (0x34, struct.pack("<I", 0)),
                   (0x50, struct.pack("<I", 1)), (0x54, bytes(4)), (0x58, struct.pack("<I", 1))]
        for where, value in changes:
            raw, off = fixture()
            start = off["romfs"] + where
            raw[start:start + len(value)] = value
            with self.subTest(where=where, value=value.hex()), self.assertRaises(ValueError):
                read(raw)

    def test_table_header_bounds_and_overlaps(self):
        for index, value in ((0, 39), (1, 41), (2, N), (3, 40), (4, 4),
                             (5, 0), (6, 1), (7, N), (8, N - 3), (9, 0), (9, 0x401), (9, 0x410)):
            raw, off = fixture()
            struct.pack_into("<I", raw, off["l3"] + index * 4, value)
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                read(raw)

    def test_truncated_reads(self):
        raw, off = fixture()
        for length in (0, 0x1FF, off["romfs"] + 60, off["selected"] + 31, len(raw) - 1):
            with self.subTest(length=length), self.assertRaises(ValueError):
                RF.read_file(io.BytesIO(raw[:length]), len(raw), CHECK.ROMFS_PATH)
        with self.assertRaisesRegex(ValueError, "declared size"):
            read(raw[:-1])

    def test_root_parent_and_record_boundary_links(self):
        raw, off = fixture()
        changes = [(off["dirs"], 24), (off["dirs"] + 4, 24),
                   (off["dirs"] + 8, 25), (off["dirs"] + 8, 28),
                   (off["dirs"] + 8, N - 3), (off["dirs"] + 24, 60),
                   (off["dirs"] + 24 + 12, 108), (off["selected"], 60)]
        for where, value in changes:
            changed = bytearray(raw)
            struct.pack_into("<I", changed, where, value)
            with self.subTest(where=where, value=value), self.assertRaises(ValueError):
                read(changed)

    def test_cycles_even_after_matching_entry(self):
        raw, off = fixture()
        for where, value, path in ((off["dirs"] + 60 + 4, 24, CHECK.ROMFS_PATH),
                                    (off["dirs"] + 8, 0, CHECK.ROMFS_PATH),
                                    (off["dirs"] + 24 + 8, 24, "battle/inner/file"),
                                    (off["zero"] + 4, 48, CHECK.ROMFS_PATH)):
            changed = bytearray(raw)
            struct.pack_into("<I", changed, where, value)
            with self.subTest(where=where), self.assertRaisesRegex(ValueError, "cycle"):
                read(changed, path)

    def test_duplicate_names_rejected_after_match(self):
        raw, off = fixture()
        # Make a duplicate of battle in its sibling, keeping record extent.
        # "other" has two padding bytes, so its record can hold six characters.
        struct.pack_into("<I", raw, off["dirs"] + 60 + 20, 12)
        raw[off["dirs"] + 84:off["dirs"] + 96] = "battle".encode("utf-16-le")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            read(raw)

    def test_malformed_metadata_names(self):
        for length in (1, 1026, N - 1):
            raw, off = fixture()
            struct.pack_into("<I", raw, off["selected"] + 28, length)
            with self.subTest(length=length), self.assertRaises(ValueError):
                read(raw)
        for value in (b"\0\xd8", b"/\0", b"\\\0", b"\0\0", b":\0", b"\x1f\0"):
            raw, off = fixture()
            raw[off["selected"] + 32:off["selected"] + 34] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                read(raw)
        for name in (".", "..", ""):
            raw, off = fixture(filename=name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                read(raw)

    def test_path_policy_missing_and_depth(self):
        raw, off = fixture()
        for path in ("", "/battle/NKMSortIndex.tbb", "battle//NKMSortIndex.tbb", "../root.bin",
                     "battle/../root.bin", "battle\\NKMSortIndex.tbb", "C:/root.bin", "battle/",
                     "battle/no-such-file", "other/no-such-file", "missing/no-such-file", "battle/\ud800"):
            with self.subTest(path=repr(path)), self.assertRaises(ValueError):
                read(raw, path)
        with self.assertRaisesRegex(ValueError, "depth"):
            read(raw, depth=1)

    def test_explicit_work_and_allocation_limits(self):
        raw, off = fixture()
        self.assertEqual(read(raw, file_bytes=len(PAYLOAD), records=8, name_bytes=32)[0], PAYLOAD)
        details = read(raw)[1]
        self.assertEqual(read(raw, read_bytes=details["parser_bytes_read"])[0], PAYLOAD)
        for kwargs, message in (({"file_bytes": len(PAYLOAD)-1}, "output budget"),
                                ({"metadata_bytes": 100}, "metadata budget"),
                                ({"records": 3}, "record budget"), ({"records": 7}, "record budget"),
                                ({"name_bytes": 28}, "name length"),
                                ({"read_bytes": details["parser_bytes_read"] - 1}, "read budget")):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, message):
                read(raw, **kwargs)
        for value in (0, -1, RF.U64 + 1, 1.5):
            with self.assertRaises(ValueError):
                RF.Limits(records=value)

    def test_checked_arithmetic(self):
        self.assertEqual(RF.extent(RF.U64, 0, RF.U64, "test"), RF.U64)
        for args in ((RF.U64, 1, RF.U64), (-1, 1, 5), (0, -1, 5), (0, 1, RF.U64 + 1)):
            with self.assertRaises(ValueError):
                RF.extent(*args, "test")
        with self.assertRaises(ValueError):
            RF.align(RF.U64, 4096)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        raw, _ = fixture()
        self.pins = {}
        rows = []
        for name, data in ((CHECK.CONTENT, raw), (CHECK.TABLE, PAYLOAD)):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            self.pins[name] = (len(data), digest)
            rows.append({"path": name, "size": len(data), "sha256": digest})
        self.config = {"reference_name": "synthetic", "ctrtool": {"version": "synthetic-unused"}}
        main = {"role": "base", "file": CHECK.CONTENT, "sha256": self.pins[CHECK.CONTENT][1],
                "title_id": "0004000000141c00", "product_code": "CTR-N-AMXP", "crypto": "None",
                "form_type": "Executable", "content_type": "Application"}
        self.documents = {"inputs": {}, "files": rows, "manifest": {
            "reference_name": "synthetic", "tool": self.config["ctrtool"],
            "main_executable": main, "contents": [copy.deepcopy(main)]}}
        self.write_documents()

    def write_documents(self):
        complete = {}
        for name, doc in self.documents.items():
            path = self.root / (name + ".json")
            path.write_text(json.dumps(doc), encoding="utf-8")
            complete[name + "_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.root / "COMPLETE.json").write_text(json.dumps(complete))

    def check(self):
        return CHECK.admission(self.root, self.config, self.pins)

    def test_inventory_and_actual_identity(self):
        self.assertEqual(len(self.check()["selected_inventory"]), 2)
        for name in (CHECK.CONTENT, CHECK.TABLE):
            path = self.root / name
            before = path.read_bytes()
            path.write_bytes(b"X" + before[1:])
            with self.assertRaisesRegex(ValueError, "actual file"):
                self.check()
            path.write_bytes(before)

    def test_stale_missing_duplicate_or_wrong_inventory(self):
        (self.root / "files.json").write_text("[]")
        with self.assertRaisesRegex(ValueError, "Stale"):
            self.check()
        original = copy.deepcopy(self.documents["files"])
        for rows in ([], original + [original[0]], [{**original[0], "size": 1}, original[1]]):
            self.documents["files"] = rows
            self.write_documents()
            with self.assertRaises(ValueError):
                self.check()

    def test_metadata_selection(self):
        original = copy.deepcopy(self.documents["manifest"])
        for field, value in (("title_id", "bad"), ("crypto", "Encrypted"),
                             ("file", "../outside"), ("content_type", "Manual")):
            self.documents["manifest"] = copy.deepcopy(original)
            for row in (self.documents["manifest"]["main_executable"],
                        self.documents["manifest"]["contents"][0]):
                row[field] = value
            self.write_documents()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
        self.documents["manifest"] = copy.deepcopy(original)
        self.documents["manifest"]["contents"].append(copy.deepcopy(original["main_executable"]))
        self.write_documents()
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            self.check()

    def test_independent_header_identity(self):
        raw, _ = fixture()
        details = read(raw)[1]
        CHECK.compare_metadata(details)
        for key in ("program_id", "partition_id", "product_code"):
            bad = copy.deepcopy(details)
            bad["ncch"][key] = "bad"
            with self.assertRaises(ValueError):
                CHECK.compare_metadata(bad)

    def test_output_confinement_overlap_and_overwrite(self):
        local = self.root / "local"
        reference = local / "reference"
        reference.mkdir(parents=True)
        for output in (local, self.root / "outside", reference / "new", reference, local / "existing"):
            if output.name == "existing":
                output.mkdir()
            with self.subTest(output=output), self.assertRaises(ValueError):
                CHECK.check_paths(reference, output, local)
        self.assertEqual(CHECK.check_paths(reference, local / "fresh", local)[1], local / "fresh")

    def test_failed_admission_emits_no_success(self):
        output = self.root / "output"
        with patch.object(CHECK, "check_paths", return_value=(self.root, output)), \
                patch.object(CHECK, "admission", side_effect=ValueError("bad identity")):
            with self.assertRaisesRegex(ValueError, "bad identity"):
                CHECK.run(self.root, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
