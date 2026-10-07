"""Deterministic section-3 fixtures; original assets stay in local output only."""
from pathlib import Path
import random
import struct

from tbcr import read


def pair_table(pairs, *, entry_size=4, declared_size=None):
    payload = b"".join(struct.pack("<HH", *pair) for pair in pairs)
    size = len(payload) if declared_size is None else declared_size
    # Earlier sections contain matching keys but distinct values as decoys.
    sections = [struct.pack("<4sIIIHH", b"TBL1", 4, 4, 0, 7, v)
                for v in (111, 222, 333)]
    sections.append(struct.pack("<4sIII", b"TBL1", size, entry_size, 0xBAD01234) + payload)
    offsets, position = [], 0
    for section in sections:
        offsets.append(position)
        position += len(section)
    return struct.pack("<4sII4I", b"TBCR", 28, 4, *offsets) + b"".join(sections)


def first_values(pairs):
    """An index of first occurrences, independent of the recovered loop."""
    values = {}
    for key, value in reversed(pairs):
        values[key] = value or 50
    return values


def write_pair_cases(output: Path, table: Path):
    section = read(table).sections[3]
    if section.entry_size != 4 or section.entry_count != 1201 or section.remainder_size:
        raise ValueError("Unexpected reference section 3 layout")
    reference = list(struct.iter_unpack("<HH", section.payload))
    keys = sorted(first_values(reference))
    probes = [keys[i * (len(keys) - 1) // 31] for i in range(32)]
    probes += [reference[i][0] for i in (0, 1, 2, 599, 600, 1199, 1200)]
    fixtures = [("pair_reference", table.read_bytes(), reference, probes)]
    specs = [
        ("one", [(7, 65432)], 4, None),
        ("width", [(0, 65535), (7, 32768), (32768, 1), (65535, 65000)], 4, None),
        ("duplicate", [(7, 321), (7, 654), (8, 987)], 4, None),
        ("zero_first", [(7, 0), (7, 65535), (8, 0), (9, 50)], 4, None),
        ("floor", [(7, 123), (8, 456)], 4, 7),
        ("stride_eight", [(7, 123), (8, 456), (9, 789), (10, 321)], 8, None),
        ("stride_two", [(7, 123), (8, 456), (9, 789), (10, 321)], 2, 8),
        ("empty", [], 4, 0),
        ("zero_count", [(7, 123)], 4, 0),
        ("zero_stride", [(7, 123)], 0, None),
    ]
    rng = random.Random(0x1A0EA4)
    specs.append(("random", [(rng.randrange(32), rng.randrange(65536))
                             for _ in range(65)], 4, None))
    for name, pairs, stride, size in specs:
        count = (len(pairs) * 4 if size is None else size) // stride if stride else 0
        if count > len(pairs):
            raise ValueError("Fixture count exceeds readable pairs")
        fixtures.append(("pair_" + name, pair_table(pairs, entry_size=stride,
                        declared_size=size), pairs[:count], [k for k, v in pairs]))
    # Null helper results are safe here: count is zero, so no payload is read.
    missing = struct.pack("<4sII", b"TBCR", 12, 0)
    fixtures.append(("pair_missing", missing, [], [7]))
    fixtures.append(("pair_bad_container", b"NOPE" + missing[4:], [], [7]))
    invalid_section = bytearray(pair_table([(7, 123)]))
    invalid_section[88:92] = b"NOPE"  # 28-byte header + three 20-byte decoys
    fixtures.append(("pair_bad_section", bytes(invalid_section), [], [7]))
    rows, counts = ["fixture\tkey\texpected\tcount"], {}
    for name, raw, pairs, probes in fixtures:
        (output / (name + ".bin")).write_bytes(raw)
        values = first_values(pairs)
        probes = list(dict.fromkeys(probes + [0, 7, 8, 9, 10, 32768, 65535,
                     65536, 65543, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]))
        for key in probes:
            rows.append(f"{name}\t{key}\t{values.get(key, 50)}\t{len(pairs)}")
        counts[name] = len(probes)
    (output / "pairs.tsv").write_text("\n".join(rows) + "\n", encoding="ascii")
    return counts
