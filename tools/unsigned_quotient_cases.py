"""Synthetic uint32 division inputs; Python integer division is the oracle."""
from pathlib import Path
import random

MAX = 0xFFFFFFFF


def division_cases() -> list[tuple[int, int, int]]:
    pairs = set()
    edges = [0, 1, 2, 3, 4, 7, 8, 31, 32, 255, 256, 4804,
             65535, 65536, 0x7FFFFFFF, 0x80000000, MAX - 1, MAX]
    pairs.update((a, b) for a in edges for b in edges if b)
    # Boundaries of every quotient bit, including unsigned high-bit divisors.
    for bit in range(32):
        b = 1 << bit
        for a in [b - 1, b, b + 1, MAX]:
            if a <= MAX:
                pairs.add((a, b))
    # Original dispatch shifts and the two normalization stages. Test both
    # sides of each compare, including exact and inexact division.
    for shift in [2, 5, 8, 12, 16, 24]:
        for b in [1, 2, 3, 7, 16, 31, 255, 256, 257, 65535]:
            for delta in [-1, 0, 1]:
                a = (b << shift) + delta
                if 0 <= a <= MAX:
                    pairs.add((a, b))
    rng = random.Random(0x2C6C64)
    for _ in range(1024):
        a = rng.getrandbits(32)
        # Unrestricted divisors exercise odd/even values; small divisors
        # exercise long quotients and normalization more often.
        pairs.add((a, rng.randrange(1, MAX + 1)))
        pairs.add((a, rng.randrange(1, 65537)))
    return [(a, b, a // b) for a, b in sorted(pairs)]


def write_division_cases(output: Path) -> int:
    cases = division_cases()
    rows = ["dividend\tdivisor\texpected_quotient"]
    rows += [f"{a}\t{b}\t{q}" for a, b, q in cases]
    (output / "divisions.tsv").write_text("\n".join(rows) + "\n", encoding="ascii")
    return len(cases)
