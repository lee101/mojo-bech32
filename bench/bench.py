"""Correctness-gated benchmark for mojo-bech32.

A bech32 payload is 32 to 90 characters, so a single address is dominated by
Python-side string handling and the honest expectation there is parity or a
loss. The case that matters is a block of them, which is why the batch entry
point exists. Every case checks agreement with the real `bech32` package before
timing.
"""

from __future__ import annotations

import pathlib
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "python"))

import bech32 as real  # noqa: E402

import mojo_bech32 as mine  # noqa: E402
from mojo_bech32 import _lib  # noqa: E402


def _time(fn, repeats=5):
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def bench_checksum_block(rows: int = 20000, width: int = 32, repeats: int = 3):
    """A block of witness programs sharing one HRP."""
    rng = np.random.default_rng(0)
    block = [[int(x) for x in rng.integers(0, 32, size=width)] for _ in range(rows)]
    expect = [real.bech32_create_checksum("bc", row) for row in block]
    got = mine.bech32_create_checksums("bc", block)
    assert got == expect, "batch checksum mismatch"

    def theirs():
        for row in block:
            real.bech32_create_checksum("bc", row)

    return (
        f"checksum block {rows}x{width}",
        _time(theirs, repeats),
        _time(lambda: mine.bech32_create_checksums("bc", block), repeats),
    )


def bench_convertbits(repeats: int = 200):
    """Repacking a 32-byte witness program to 5-bit groups."""
    rng = np.random.default_rng(1)
    prog = [int(x) for x in rng.integers(0, 256, size=32, dtype="uint8")]
    assert mine.convertbits(prog, 8, 5) == real.convertbits(prog, 8, 5)

    return (
        "convertbits 32B 8->5",
        _time(lambda: real.convertbits(prog, 8, 5), repeats),
        _time(lambda: mine.convertbits(prog, 8, 5), repeats),
    )


def bench_address_round_trip(count: int = 20000, repeats: int = 3):
    """Full segwit address encode plus decode, end to end."""
    rng = np.random.default_rng(2)
    programs = [
        bytes(rng.integers(0, 256, size=32, dtype="uint8")) for _ in range(count)
    ]
    mine_addrs = [mine.encode("bc", 0, p) for p in programs]
    real_addrs = [real.encode("bc", 0, p) for p in programs]
    assert mine_addrs == real_addrs, "segwit encode mismatch"
    assert all(mine.decode("bc", a) == real.decode("bc", a) for a in real_addrs)

    def theirs():
        for p in programs:
            addr = real.encode("bc", 0, p)
            real.decode("bc", addr)

    def ours():
        for p in programs:
            addr = mine.encode("bc", 0, p)
            mine.decode("bc", addr)

    return f"segwit round trip x{count}", _time(theirs, repeats), _time(ours, repeats)


def bench_polymod_block(rows: int = 20000, width: int = 32, repeats: int = 3):
    """Verification pass over a block, without materialising the checksums."""
    rng = np.random.default_rng(3)
    block = [[int(x) for x in rng.integers(0, 32, size=width)] for _ in range(rows)]
    expand = real.bech32_hrp_expand("bc")
    expect = [real.bech32_polymod(expand + row) for row in block]
    assert _lib.polymod_batch("bc", block) == expect, "polymod batch mismatch"

    def theirs():
        for row in block:
            real.bech32_polymod(expand + row)

    return (
        f"polymod block {rows}x{width}",
        _time(theirs, repeats),
        _time(lambda: _lib.polymod_batch("bc", block), repeats),
    )


def main():
    print(f"{'case':<28}{'bech32':>12}{'mojo-bech32':>14}{'ratio':>9}")
    print("-" * 63)
    for fn in (
        bench_checksum_block,
        bench_convertbits,
        bench_address_round_trip,
        bench_polymod_block,
    ):
        label, ref, got = fn()
        print(f"{label:<28}{ref*1e3:>10.2f}ms{got*1e3:>12.2f}ms{ref/got:>8.2f}x")
    print()
    print("ratios above 1.00x favour mojo-bech32; below 1.00x is a loss")


if __name__ == "__main__":
    main()
