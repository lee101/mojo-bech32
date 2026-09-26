"""Bech32 and segwit addresses with the checksum and bit packing in Mojo.

The public names, return conventions and validation order mirror
`bech32` 1.2.0, so this package imports alongside the real one and the parity
tests compare the two directly. What moved into the compiled library is the
numeric part: the BCH checksum recurrence, the charset codebook and the bit
repacking between 5-bit and 8-bit groups. String policy — the case check, the
`1` separator search, the length limits — stays in Python, because that is
control flow rather than arithmetic.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Tuple, Union

from . import _lib

__all__ = [
    "CHARSET",
    "bech32_create_checksum",
    "bech32_create_checksums",
    "bech32_decode",
    "bech32_encode",
    "bech32_hrp_expand",
    "bech32_polymod",
    "bech32_verify_checksum",
    "convertbits",
    "decode",
    "encode",
]

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values: Iterable[int]) -> int:
    """Internal function that computes the Bech32 checksum."""
    return _lib.polymod_values(values)


def bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data: Iterable[int]) -> bool:
    """Verify a checksum given HRP and converted data characters."""
    return _lib.verify_checksum(hrp, data)


def bech32_create_checksum(hrp: str, data: Iterable[int]) -> List[int]:
    """Compute the checksum values given HRP and data."""
    return _lib.create_checksum(hrp, data)


def bech32_create_checksums(hrp: str, rows) -> List[List[int]]:
    """Checksums for many equal-length data rows sharing one HRP, in one call.

    Same recurrence as `bech32_create_checksum`, applied to a block of rows so a
    block validator crosses the FFI boundary once instead of once per address.
    """
    return _lib.create_checksum_batch(hrp, rows)


def bech32_encode(hrp: str, data: Iterable[int]) -> str:
    """Compute a Bech32 string given HRP and data values."""
    data = list(data)
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + _lib.map_to_charset(combined).decode("ascii")


def bech32_decode(bech: str) -> Union[Tuple[None, None], Tuple[str, List[int]]]:
    """Validate a Bech32 string, and determine HRP and data."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos > 83 or pos + 7 > len(bech):  # or len(bech) > 90:
        return (None, None)
    data = _lib.map_from_charset(bech[pos + 1 :])
    if data is None:
        return (None, None)
    hrp = bech[:pos]
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])


def convertbits(
    data: Iterable[int], frombits: int, tobits: int, pad: bool = True
) -> Optional[List[int]]:
    """General power-of-2 base conversion."""
    return _lib.convertbits(data, frombits, tobits, pad)


def decode(hrp: str, addr: str) -> Union[Tuple[None, None], Tuple[int, List[int]]]:
    """Decode a segwit address."""
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    assert data is not None
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    return (data[0], decoded)


def encode(hrp: str, witver: int, witprog: Iterable[int]) -> Optional[str]:
    """Encode a segwit address."""
    five_bit_witprog = convertbits(witprog, 8, 5)
    if five_bit_witprog is None:
        return None
    ret = bech32_encode(hrp, [witver] + five_bit_witprog)
    if decode(hrp, ret) == (None, None):
        return None
    return ret
