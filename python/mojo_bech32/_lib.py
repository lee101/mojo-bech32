"""ctypes bridge to the compiled bech32 kernels.

The shared library owns no memory. Every buffer crosses the C ABI as a 64-bit
address, so the argtypes below must stay `c_int64` for addresses; `c_int`
truncates them and segfaults. Scratch buffers are allocated here, on the Python
side, which keeps the exported Mojo symbols free of allocation and of `raises`.
"""

from __future__ import annotations

import ctypes
import pathlib

import numpy as np

_HERE = pathlib.Path(__file__).resolve()
_ROOT = _HERE.parents[2]
_LIB_PATH = _ROOT / "dist" / "libmojo-bech32.so"

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _load():
    if not _LIB_PATH.exists():
        raise RuntimeError(
            f"{_LIB_PATH} not found; run `bash build/build.sh` first"
        )
    lib = ctypes.CDLL(str(_LIB_PATH))
    i, i64, d = ctypes.c_int64, ctypes.c_int64, ctypes.c_double
    lib.b32_polymod.restype = None
    lib.b32_polymod.argtypes = [i, i, i, i, i]
    lib.b32_polymod_values.restype = None
    lib.b32_polymod_values.argtypes = [i, i, i]
    lib.b32_create_checksum.restype = None
    lib.b32_create_checksum.argtypes = [i, i, i, i, i]
    lib.b32_verify_checksum.restype = i
    lib.b32_verify_checksum.argtypes = [i, i, i, i]
    lib.b32_polymod_batch.restype = None
    lib.b32_polymod_batch.argtypes = [i, i, i, i, i, i]
    lib.b32_create_checksum_batch.restype = None
    lib.b32_create_checksum_batch.argtypes = [i, i, i, i, i, i]
    lib.b32_map_to_charset.restype = i
    lib.b32_map_to_charset.argtypes = [i, i, i, i]
    lib.b32_map_from_charset.restype = i
    lib.b32_map_from_charset.argtypes = [i, i, i, i]
    lib.b32_convertbits.restype = i
    lib.b32_convertbits.argtypes = [i, i, i, i, i, i, i]
    del d
    return lib


lib = _load()

_CHARSET_BYTES = np.frombuffer(CHARSET.encode("ascii"), dtype=np.uint8)


def _dmap() -> np.ndarray:
    table = np.full(256, -1, dtype=np.int32)
    for index, char in enumerate(CHARSET.encode("ascii")):
        table[char] = index
    return table


_DMAP = _dmap()


def _hrp_array(hrp: str) -> np.ndarray:
    return np.frombuffer(
        np.array([ord(c) for c in hrp], dtype=np.int32).tobytes(), dtype=np.int32
    )


def _i32(values) -> np.ndarray:
    return np.asarray(list(values), dtype=np.int32)


def _i64(values) -> np.ndarray:
    return np.asarray(list(values), dtype=np.int64)


def polymod_values(values) -> int:
    """Polymod over a bare value list, no HRP expansion."""
    arr = _i64(values)
    slot = np.zeros(1, dtype=np.int64)
    lib.b32_polymod_values(arr.ctypes.data, arr.size, slot.ctypes.data)
    return int(slot[0])


def polymod(hrp: str, values) -> int:
    """Polymod over expand(hrp) + values."""
    h = _hrp_array(hrp)
    arr = _i32(values)
    slot = np.zeros(1, dtype=np.int64)
    lib.b32_polymod(h.ctypes.data, h.size, arr.ctypes.data, arr.size, slot.ctypes.data)
    return int(slot[0])


def verify_checksum(hrp: str, values) -> bool:
    h = _hrp_array(hrp)
    arr = _i32(values)
    return bool(lib.b32_verify_checksum(h.ctypes.data, h.size, arr.ctypes.data, arr.size))


def create_checksum(hrp: str, values) -> list[int]:
    h = _hrp_array(hrp)
    arr = _i32(values)
    dst = np.zeros(6, dtype=np.int32)
    lib.b32_create_checksum(
        h.ctypes.data, h.size, arr.ctypes.data, arr.size, dst.ctypes.data
    )
    return [int(v) for v in dst]


def polymod_batch(hrp: str, rows) -> list[int]:
    """Polymod for equal-length rows sharing one HRP, in a single call."""
    block = _i32([v for row in rows for v in row])
    if not rows:
        return []
    stride = len(rows[0])
    dst = np.zeros(len(rows), dtype=np.int64)
    h = _hrp_array(hrp)
    lib.b32_polymod_batch(
        h.ctypes.data, h.size, block.ctypes.data, stride, len(rows), dst.ctypes.data
    )
    return [int(v) for v in dst]


def create_checksum_batch(hrp: str, rows) -> list[list[int]]:
    """Six checksum words per row, row-major, in a single call."""
    if not rows:
        return []
    block = _i32([v for row in rows for v in row])
    stride = len(rows[0])
    dst = np.zeros(len(rows) * 6, dtype=np.int32)
    h = _hrp_array(hrp)
    lib.b32_create_checksum_batch(
        h.ctypes.data, h.size, block.ctypes.data, stride, len(rows), dst.ctypes.data
    )
    return [[int(v) for v in dst[r * 6 : r * 6 + 6]] for r in range(len(rows))]


def map_to_charset(values) -> bytes:
    arr = _i32(values)
    dst = np.zeros(arr.size, dtype=np.uint8)
    lib.b32_map_to_charset(
        arr.ctypes.data, arr.size, _CHARSET_BYTES.ctypes.data, dst.ctypes.data
    )
    return dst.tobytes()


def map_from_charset(text: str):
    """Return the 5-bit values, or None if a character is outside the charset."""
    raw = text.encode("ascii", "replace")
    arr = np.frombuffer(raw, dtype=np.uint8)
    dst = np.zeros(arr.size, dtype=np.int32)
    got = lib.b32_map_from_charset(
        arr.ctypes.data, arr.size, _DMAP.ctypes.data, dst.ctypes.data
    )
    if got < 0:
        return None
    return [int(v) for v in dst]


def convertbits(data, frombits: int, tobits: int, pad: bool = True):
    """Repack a bit stream, or None when the input or padding is illegal."""
    if frombits < 1 or tobits < 1 or frombits + tobits - 1 > 62:
        raise ValueError("frombits + tobits - 1 must be in 1..62")
    try:
        arr = _i64(data)
    except (OverflowError, TypeError, ValueError):
        return None
    # n groups of `frombits` bits become n * frombits / tobits groups.
    cap = (arr.size * frombits) // tobits + 2
    dst = np.zeros(cap, dtype=np.int64)
    got = lib.b32_convertbits(
        arr.ctypes.data, arr.size, frombits, tobits, 1 if pad else 0,
        dst.ctypes.data, cap,
    )
    if got < 0:
        return None
    return [int(v) for v in dst[:got]]
