"""mojo-bech32: Bech32 and segwit addresses with the arithmetic in Mojo.

Installable alongside the real `bech32` package, which the parity tests compare
against.
"""

from .core import (
    CHARSET,
    bech32_create_checksum,
    bech32_create_checksums,
    bech32_decode,
    bech32_encode,
    bech32_hrp_expand,
    bech32_polymod,
    bech32_verify_checksum,
    convertbits,
    decode,
    encode,
)

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
__version__ = "0.1.0"
