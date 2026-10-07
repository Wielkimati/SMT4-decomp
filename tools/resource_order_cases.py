"""Consumed-domain cases, with inverse-LCG seeds targeting remainder boundaries."""
from pathlib import Path
import random

MASK = 0xFFFFFFFF
MULTIPLIER = 0x41C64E6D
INVERSE = pow(MULTIPLIER, -1, 1 << 32)


def remainder_cases():
    pairs = set()
    for width in range(34, 67):
        values = {0, 1, 65534, 65535}
        for quotient in [1, 2, 3, 15, 16, 17, 255, 256, 257, 65535 // width]:
            values.update(quotient * width + delta for delta in [-1, 0, 1])
        for shift in [1, 4, 8, 12, 16]:
            values.update((width << shift) + delta for delta in [-1, 0, 1])
        pairs.update((v, width) for v in values if 0 <= v <= 65535)
    rng = random.Random(0x29706C)
    pairs.update((rng.randrange(65536), rng.randrange(34, 67)) for _ in range(2048))
    return [(a, b, a % b) for a, b in sorted(pairs)]


def index_cases():
    cases = set()
    # Each remainder case is also reached by an actual state update, including
    # both extremes of the ignored low 16 bits. This catches 15-bit rand masks.
    for high, width, remainder in remainder_cases():
        lower = 67 - width
        for low in [0, 65535]:
            state = (high << 16) | low
            seed = ((state - 0x3039) * INVERSE) & MASK
            cases.add((seed, lower, 66, state, lower + remainder))
    return sorted(cases)


def write_cases(output: Path):
    remainders, indices = remainder_cases(), index_cases()
    for name, header, rows in [
        ("remainders.tsv", "dividend\tdivisor\tremainder", remainders),
        ("indices.tsv", "seed\tlower\tupper\tstate\tresult", indices),
    ]:
        (output / name).write_text(header + "\n" + "".join(
            "\t".join(map(str, row)) + "\n" for row in rows), encoding="ascii")
    return len(remainders), len(indices)
