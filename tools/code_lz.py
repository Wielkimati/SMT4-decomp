"""Bounded reverse-LZ decoder for compressed ExeFS code, not recovered game code.

New project implementation from GBATEK's LZrev format description (Martin Korth),
mgba-emu/gbatek revision 64b5087aa45cd0187b8b239d77e54ee5eb2917d1, ds.md.
No external decoder code or library is incorporated; see recovery/code-decoder.md.
The input is immutable. A forward history represents the reverse output order.
This intentionally does not implement uncompressed/NDS overlay autodetection.
"""

from dataclasses import asdict, dataclass


class CodeLzError(ValueError):
    """Invalid or unsupported compressed-code stream."""


@dataclass(frozen=True)
class Footer:
    input_size: int
    compressed_span: int
    footer_size: int
    growth: int
    prefix_size: int
    payload_size: int
    output_size: int


def inspect_footer(data: bytes, *, max_output: int = 64 * 1024 * 1024) -> Footer:
    """Validate size arithmetic before allocating; the limit is host policy."""
    size = len(data)
    if size < 8:
        raise CodeLzError("Truncated footer")
    span = int.from_bytes(data[-8:-5], "little")
    footer = data[-5]
    growth = int.from_bytes(data[-4:], "little")
    if not 8 <= footer < span <= size:
        raise CodeLzError("Invalid footer/span bounds or empty payload")
    if growth == 0:
        raise CodeLzError("Zero-growth/uncompressed form is unsupported")
    if size + growth > max_output:
        raise CodeLzError("Output exceeds configured limit")
    return Footer(size, span, footer, growth, size - span, span - footer, size + growth)


def decode(data: bytes, *, max_output: int = 64 * 1024 * 1024) -> tuple[bytes, dict]:
    """Decode exactly the declared suffix; reject incomplete/excess token data.

    Footer padding and unused final flag bits are opaque. Copy distances must
    refer to already produced bytes; overlapping copies append one byte at a time.
    Diagnostics for malformed inputs are this tool's policy, not game behavior.
    """
    footer = inspect_footer(data, max_output=max_output)
    stream = data[footer.prefix_size:len(data) - footer.footer_size][::-1]
    required = footer.output_size - footer.prefix_size
    history = bytearray()
    cursor = 0
    stats = {"flag_bytes": 0, "literals": 0, "matches": 0, "copied_bytes": 0,
             "overlapping_matches": 0, "min_distance": None, "max_distance": 0,
             "min_length": None, "max_length": 0}
    while cursor < len(stream):
        flags = stream[cursor]
        cursor += 1
        stats["flag_bytes"] += 1
        if cursor == len(stream):
            raise CodeLzError("Flag byte has no token")
        for bit in range(7, -1, -1):
            if cursor == len(stream):
                break
            if len(history) == required:
                raise CodeLzError("Excess token data after declared output")
            if flags & (1 << bit):
                if cursor + 2 > len(stream):
                    raise CodeLzError("Truncated match token")
                token = int.from_bytes(stream[cursor:cursor + 2], "big")
                cursor += 2
                length = (token >> 12) + 3
                distance = (token & 0xFFF) + 3
                if distance > len(history):
                    raise CodeLzError("Match precedes produced history")
                if len(history) + length > required:
                    raise CodeLzError("Match exceeds declared output")
                for _ in range(length):
                    history.append(history[-distance])
                stats["matches"] += 1
                stats["copied_bytes"] += length
                stats["overlapping_matches"] += length > distance
                stats["min_distance"] = min(stats["min_distance"] or distance, distance)
                stats["max_distance"] = max(stats["max_distance"], distance)
                stats["min_length"] = min(stats["min_length"] or length, length)
                stats["max_length"] = max(stats["max_length"], length)
            else:
                history.append(stream[cursor])
                cursor += 1
                stats["literals"] += 1
    if len(history) != required:
        raise CodeLzError("Stream ends before declared output")
    return data[:footer.prefix_size] + bytes(reversed(history)), {
        "footer": asdict(footer), "tokens": stats,
        "padding_hex": data[len(data) - footer.footer_size:len(data) - 8].hex()}
