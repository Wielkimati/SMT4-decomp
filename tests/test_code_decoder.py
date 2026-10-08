"""Synthetic reverse-LZ fixtures; no original bytes, private files or CTRTool."""

from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import code_lz as LZ
import check_code_decoder as CHECK


def frame(stream, output_size, prefix=b"", padding=b""):
    """Wrap bytes in decode order; expected output is supplied independently."""
    payload = stream[::-1]
    span = len(payload) + len(padding) + 8
    growth = output_size - len(prefix) - span
    assert 0 < growth <= 0xFFFFFFFF
    return prefix + payload + padding + struct.pack("<II", span | ((8 + len(padding)) << 24), growth)


def fixture(tokens, history, prefix=b"", padding=b""):
    stream = bytearray()
    for start in range(0, len(tokens), 8):
        group = tokens[start:start + 8]
        stream.append(sum((1 << (7 - i)) for i, item in enumerate(group) if isinstance(item, tuple)))
        for item in group:
            if isinstance(item, tuple):
                length, distance = item
                stream.extend((((length - 3) << 12) | (distance - 3)).to_bytes(2, "big"))
            else:
                stream.append(item)
    expected = prefix + history[::-1]
    return frame(bytes(stream), len(expected), prefix, padding), expected


class DecoderTests(unittest.TestCase):
    def test_hand_encoded_overlap_and_opaque_prefix(self):
        # Literal A, B, C; length 18, distance 3; unused flags zero.
        data = b"HDR\x00\xf0CBA\x10\x0e\x00\x00\x08\x07\x00\x00\x00"
        output, info = LZ.decode(data)
        self.assertEqual(output, b"HDR" + b"CBA" * 7)
        self.assertEqual(info["footer"]["prefix_size"], 3)
        self.assertEqual(info["tokens"]["overlapping_matches"], 1)
        self.assertEqual(data[:3], b"HDR")

    def test_footer_padding_and_partial_final_flags(self):
        for padding in (b"", b"\xff", b"\xff\xff", b"\xff\xff\xff", bytes(range(247))):
            for unused in (0, 15):
                # Larger repeat pays for even the maximum one-byte footer length.
                data, expected = fixture(list(b"ABC") + [(18, 3)] * 25, b"ABC" * 151,
                                         prefix=b"opaque", padding=padding)
                # The 28 tokens leave four unused bits in the final (lowest-address) group.
                mutable = bytearray(data)
                mutable[len(b"opaque") + 8] |= unused
                self.assertEqual(LZ.decode(bytes(mutable))[0], expected)

    def test_length_and_distance_boundaries(self):
        seed = bytes(i % 251 for i in range(4098))
        # Repetition pays the flag-byte overhead for a max-distance literal seed.
        base_tokens = list(seed) + [(18, 3)] * 40
        base_history = seed + seed[-3:] * 240
        for distance in (3, 4, 4097, 4098):
            for length in (3, 4, 17, 18):
                # Analytical repetition of the last `distance` bytes supports overlap.
                extension = (base_history[-distance:] * 6)[:length]
                data, expected = fixture(base_tokens + [(length, distance)], base_history + extension)
                self.assertEqual(LZ.decode(data)[0], expected)

    def test_flag_groups_and_exact_output_limit(self):
        tokens = list(b"ABCDEFGH") + [(18, 8)] * 8 + list(b"xyz")
        history = b"ABCDEFGH" * 19 + b"xyz"
        data, expected = fixture(tokens, history)
        self.assertEqual(LZ.decode(data, max_output=len(expected))[0], expected)
        with self.assertRaisesRegex(LZ.CodeLzError, "limit"):
            LZ.decode(data, max_output=len(expected) - 1)

    def test_truncated_footer(self):
        for size in range(8):
            with self.assertRaisesRegex(LZ.CodeLzError, "footer"):
                LZ.decode(bytes(size))

    def test_footer_arithmetic_and_zero_growth(self):
        for span, footer, growth in ((0, 8, 1), (9, 7, 1), (9, 10, 1),
                                     (11, 8, 1), (8, 8, 1), (9, 8, 0),
                                     (9, 8, 0xFFFFFFFF)):
            with self.assertRaises(LZ.CodeLzError):
                LZ.decode(b"xy" + struct.pack("<II", span | (footer << 24), growth))

    def test_truncated_token_and_empty_flag_group(self):
        for stream, message in ((b"\x80\xf0", "Truncated match"), (b"\x00", "no token")):
            with self.assertRaisesRegex(LZ.CodeLzError, message):
                LZ.decode(frame(stream, 50))

    def test_match_cannot_reference_unproduced_output(self):
        for stream in (b"\x80\xf0\x00", b"\x20AB\xf0\x00", b"\x10ABC\xff\xff"):
            with self.assertRaisesRegex(LZ.CodeLzError, "history"):
                LZ.decode(frame(stream, 50))

    def test_declared_output_overrun_and_underrun(self):
        for size, message in ((20, "exceeds"), (22, "ends before")):
            with self.assertRaisesRegex(LZ.CodeLzError, message):
                LZ.decode(frame(b"\x10ABC\xf0\x00", size))

    def test_extra_tokens_after_exact_output(self):
        with self.assertRaisesRegex(LZ.CodeLzError, "Excess token"):
            LZ.decode(frame(b"\x10ABC\xf0\x00Z", 21))

    def test_no_uncompressed_autodetection(self):
        with self.assertRaises(LZ.CodeLzError):
            LZ.decode(b"Already expanded" + bytes(8))


class CheckerTests(unittest.TestCase):
    def blobs(self):
        compressed, expected = fixture(list(b"ABC") + [(18, 3)] * 227 + list(b"1234567"),
                                       b"ABC" * 1363 + b"1234567")
        self.assertEqual(len(expected), 4096)
        exheader = bytearray(2048)
        exheader[13] = 1
        exheader[0x14] = 1
        return {"exefs-original/code.bin": compressed, "exefs/code.bin": expected,
                "exheader.bin": bytes(exheader)}

    def identities(self, blobs):
        return {n: (len(b), CHECK.digest(b)) for n, b in blobs.items()}

    def test_full_synthetic_artifact_comparison(self):
        blobs = self.blobs()
        decoded, details = CHECK.compare(blobs, self.identities(blobs))
        self.assertEqual(decoded, blobs["exefs/code.bin"])
        self.assertEqual(details["segment_allocation"], 4096)

    def test_identity_drift_and_expanded_input_swap(self):
        blobs = self.blobs()
        identities = self.identities(blobs)
        for name in blobs:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "identity"):
                CHECK.compare(blobs | {name: blobs[name] + b"x"}, identities)
        with self.assertRaisesRegex(ValueError, "identity"):
            CHECK.compare(blobs | {"exefs-original/code.bin": blobs["exefs/code.bin"]}, identities)

    def test_exheader_compression_and_allocation_required(self):
        for offset, value, message in ((13, 0, "compressed"), (0x14, 2, "allocation")):
            blobs = self.blobs()
            header = bytearray(blobs["exheader.bin"])
            header[offset] = value
            blobs["exheader.bin"] = bytes(header)
            with self.assertRaisesRegex(ValueError, message):
                CHECK.compare(blobs, self.identities(blobs))

    def test_output_mismatch_is_not_success(self):
        blobs = self.blobs()
        bad = bytearray(blobs["exefs/code.bin"])
        bad[2000] ^= 1
        blobs["exefs/code.bin"] = bytes(bad)
        with self.assertRaisesRegex(ValueError, "differs"):
            CHECK.compare(blobs, self.identities(blobs))

    def test_fresh_confined_nonoverlapping_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            local = root / "local"
            reference = local / "reference"
            reference.mkdir(parents=True)
            valid = local / "new"
            self.assertEqual(CHECK.check_paths(reference, valid, local), (reference, valid))
            for output in (local, root / "outside", reference / "child", reference,
                           local / "new/../../escape"):
                with self.assertRaises(ValueError):
                    CHECK.check_paths(reference, output, local)
            valid.mkdir()
            with self.assertRaisesRegex(ValueError, "already exists"):
                CHECK.check_paths(reference, valid, local)

    def test_failed_cli_creates_no_success_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reference = root / "local/reference"
            reference.mkdir(parents=True)
            output = root / "local/output"
            with patch.object(CHECK, "REPO", root), patch.object(sys, "argv", [
                    "check_code_decoder", "--reference", str(reference), "--output", str(output)]):
                with self.assertRaises(FileNotFoundError):
                    CHECK.main()
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
