"""Synthetic, address-bound cases for the recovered loaded-memory helpers.

These deliberately include headers rejected by the safe file parser. Expected
results are constructed with each fixture, not calculated by that parser.
"""
from pathlib import Path
import random
import struct

TABLE = 0x800000
ORIGINALS = {"tbcr_select_section": 0x2AC358, "tbl1_payload": 0x2C0EF0,
             "tbl1_entry_count": 0x2C0EA0, "resource_select_tbcr_section": 0x2C0F18}


def write_helper_cases(output: Path) -> dict[str, int]:
    rows = ["fixture\thelper\tr0\tr1\texpected"]
    counts = {name: 0 for name in ORIGINALS}

    def fixture(name, data, registry=None):
        (output / f"{name}.bin").write_bytes(data)
        if registry is not None:
            (output / f"{name}.registry.bin").write_bytes(registry)

    def case(name, helper, r0, r1, expected):
        rows.append(f"{name}\t{helper}\t{r0}\t{r1}\t{expected}")
        counts[helper] += 1

    select, payload, count, resource = ORIGINALS
    fixture("helper_null", b"\0")
    for helper in (select, payload, count):
        case("helper_null", helper, 0, 0xFFFFFFFF, 0)
    # Four readable bytes only: magic failure must not read later header fields.
    for magic in (b"TBCR", b"TBL1", b"BAD!", b"1LBT", b"RCBT"):
        name = "magic_" + magic.hex()
        fixture(name, magic)
        if magic != b"TBCR":
            case(name, select, TABLE, 0, 0)
        if magic != b"TBL1":
            case(name, payload, TABLE, 0, 0)
            case(name, count, TABLE, 0, 0)
        else:
            # Payload accessor returns +16 even with no backing payload/header.
            case(name, payload, TABLE, 0, TABLE + 16)

    fixture("empty_container", struct.pack("<4sII", b"TBCR", 0xFFFFFFFF, 0))
    for index in (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
        case("empty_container", select, TABLE, index, 0)

    # Nonstandard base, reordered/duplicate offsets, and bad selected magic.
    data = bytearray(128)
    struct.pack_into("<4sII4I", data, 0, b"TBCR", 64, 4, 32, 0, 32, 48)
    data[64:68] = b"TBL1"
    data[96:100] = b"TBL1"
    data[112:116] = b"BAD!"
    fixture("reordered_sections", data)
    for index, expected in enumerate((TABLE + 96, TABLE + 64, TABLE + 96, 0)):
        case("reordered_sections", select, TABLE, index, expected)
    for index in (4, 5, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
        case("reordered_sections", select, TABLE, index, 0)

    # ARM additions wrap at 32 bits, including the offset-table index shift.
    fixture("null_selected_pointer", struct.pack("<4sIII", b"TBCR", 0, 1, (-TABLE) & 0xFFFFFFFF))
    case("null_selected_pointer", select, TABLE, 0, 0)
    data = struct.pack("<4sIII4s", b"TBCR", 0xFFFFFFF0, 1, 32, b"TBL1")
    fixture("wrapping_offset_sum", data)
    case("wrapping_offset_sum", select, TABLE, 0, TABLE + 16)
    data = struct.pack("<4sIII4s", b"TBCR", 16, 0xFFFFFFFF, 0, b"TBL1")
    fixture("wrapping_index_shift", data)
    for index in (0, 0x40000000, 0x80000000, 0xC0000000):
        case("wrapping_index_shift", select, TABLE, index, TABLE + 16)
    case("wrapping_index_shift", select, TABLE, 0xFFFFFFFF, 0)

    edges = [0, 1, 2, 3, 4, 7, 8, 31, 32, 255, 256, 4804,
             65535, 65536, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
    pairs = [(a, b) for a in edges for b in edges]
    rng = random.Random(0x2C0EA0)
    pairs += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(128)]
    for i, (size, stride) in enumerate(pairs):
        name = f"count_{i}"
        fixture(name, struct.pack("<4sIII", b"TBL1", size, stride, rng.getrandbits(32)))
        case(name, count, TABLE, 0, size // stride if stride else 0)
        case(name, payload, TABLE, 0, TABLE + 16)

    # Each populated boundary slot selects a distinct section. Other registry
    # fields contain a readable wrong-magic pointer to catch offset/stride errors.
    data = bytearray(0x304)
    registry = bytearray(67 * 16)
    for i in range(67):
        struct.pack_into("<4I", registry, i * 16, TABLE + 0x300, 0,
                         TABLE + 0x300, TABLE + 0x300)
    for slot, offset in ((0, 0), (1, 0x100), (66, 0x200)):
        struct.pack_into("<4sIII4s", data, offset, b"TBCR", 16, 1, 0, b"TBL1")
        struct.pack_into("<I", registry, slot * 16 + 4, TABLE + offset)
    fixture("registry_boundaries", data, registry)
    for slot in (*range(68), 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF):
        for index in (0, 1, 0xFFFFFFFF):
            expected = TABLE + {0: 0, 1: 0x100, 66: 0x200}[slot] + 16 if slot in (0, 1, 66) and index == 0 else 0
            case("registry_boundaries", resource, slot, index, expected)

    (output / "helpers.tsv").write_text("\n".join(rows) + "\n", encoding="ascii")
    return counts
