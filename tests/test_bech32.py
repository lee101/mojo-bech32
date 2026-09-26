"""Parity against the real `bech32` package, plus BIP-173 test vectors.

Every quantity here is a small integer or a character code, so the comparisons
are exact: `rtol=0, atol=0` territory. Nothing in bech32 is floating point, so
there is no FMA caveat to manage.
"""

import bech32 as real
import numpy as np
import pytest

import mojo_bech32 as mine

# BIP-173 valid bech32 strings (not segwit addresses).
BECH32_VALID = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcluded"
    "charactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

# BIP-173 valid segwit addresses with their expected witness program lengths.
SEGWIT_VALID = [
    ("bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 20),
    ("tb", "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", 32),
    (
        "bc",
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
        40,
    ),
]


def test_charset_matches_upstream():
    assert mine.CHARSET == real.CHARSET
    assert len(mine.CHARSET) == 32
    assert len(set(mine.CHARSET)) == 32


@pytest.mark.parametrize("text", BECH32_VALID)
def test_bip173_valid_strings_decode(text):
    hrp, data = mine.bech32_decode(text)
    assert (hrp, data) == real.bech32_decode(text)
    assert hrp is not None


@pytest.mark.parametrize("text", BECH32_VALID)
def test_bip173_strings_re_encode_to_the_reference_value(text):
    """Decoding lowercases the data, so the round trip is against upstream.

    `bech32_decode` returns the lowercased HRP for a mixed-case input, so
    re-encoding `A12UEL5L` gives `A12uel5l` in both packages. Comparing against
    the reference rather than against the input string is the real contract.
    """
    hrp, data = mine.bech32_decode(text)
    assert mine.bech32_encode(hrp, data) == real.bech32_encode(hrp, data)


@pytest.mark.parametrize("hrp,address,prog_len", SEGWIT_VALID)
def test_bip173_segwit_addresses_decode(hrp, address, prog_len):
    got = mine.decode(hrp, address)
    assert got == real.decode(hrp, address)
    witver, prog = got
    assert witver is not None
    assert len(prog) == prog_len


def test_segwit_encode_matches_upstream():
    rng = np.random.default_rng(11)
    for witver, length in ((0, 20), (0, 32), (1, 32), (2, 32)):
        for _ in range(20):
            prog = bytes(rng.integers(0, 256, size=length, dtype="uint8"))
            assert mine.encode("bc", witver, prog) == real.encode("bc", witver, prog)


def test_checksum_matches_the_reference_definition():
    """The six zero words are LFSR steps, not a no-op.

    `bech32_create_checksum` is defined as
    `[(polymod(expand(hrp) + data + [0]*6) ^ 1) >> 5*(5-i) & 31]`. A kernel that
    computes `polymod(expand(hrp) + data) ^ 1` instead, which is the tempting
    shortcut, still produces six plausible-looking words and still round-trips
    through its own verifier, so only the definition catches it.
    """
    for hrp, data in (
        ("bc", []),
        ("bc", [0]),
        ("bc", list(range(32))),
        ("bc", [17, 2, 3, 4, 5]),
        ("a", [31, 31, 31]),
        ("longhrp", [1, 2, 3, 4, 5, 6, 7, 8, 9]),
    ):
        pm = real.bech32_polymod(real.bech32_hrp_expand(hrp) + list(data) + [0] * 6)
        expect = [(pm ^ 1) >> 5 * (5 - i) & 31 for i in range(6)]
        assert mine.bech32_create_checksum(hrp, data) == expect
        assert mine.bech32_create_checksum(hrp, data) == real.bech32_create_checksum(
            hrp, data
        )


def test_polymod_matches_the_reference_definition():
    for hrp in ("bc", "tb", "a", "abcdefg"):
        for data in ([], [0], list(range(32)), [3, 3, 3, 3, 3, 3, 3, 3]):
            expect = real.bech32_polymod(real.bech32_hrp_expand(hrp) + data)
            assert mine._lib.polymod(hrp, data) == expect
            assert mine.bech32_polymod(real.bech32_hrp_expand(hrp) + data) == expect


def test_hrp_expansion_order_matters():
    """High bits, separator, then low bits.

    Reordering these three parts still yields a six-word checksum and still
    round-trips through the package's own verifier, so the order has to be
    pinned against the reference definition rather than against a round trip.
    """
    hrp = "bc"
    expand = real.bech32_hrp_expand(hrp)
    assert expand == [ord("b") >> 5, ord("c") >> 5, 0, ord("b") & 31, ord("c") & 31]
    assert mine.bech32_hrp_expand(hrp) == expand
    assert mine._lib.polymod(hrp, [0]) != mine._lib.polymod(hrp, [0, 0])


def test_verify_checksum_rejects_a_single_flipped_word():
    data = list(range(1, 21))
    checksum = mine.bech32_create_checksum("bc", data)
    assert mine.bech32_verify_checksum("bc", data + checksum)
    for index in (0, 5, 19):
        broken = list(data)
        broken[index] = (broken[index] + 1) % 32
        assert not mine.bech32_verify_checksum("bc", broken + checksum)
    for index in (0, 3, 5):
        broken = list(checksum)
        broken[index] = (broken[index] + 1) % 32
        assert not mine.bech32_verify_checksum("bc", data + broken)


def test_verify_checksum_is_hrp_specific():
    data = list(range(1, 21))
    checksum = mine.bech32_create_checksum("bc", data)
    assert mine.bech32_verify_checksum("bc", data + checksum)
    assert not mine.bech32_verify_checksum("tb", data + checksum)


@pytest.mark.parametrize("bad", ["", "1", "a1qqqqqq", "A12UEL5", "x1b0"])
def test_decode_rejects_malformed_strings(bad):
    assert mine.bech32_decode(bad) == real.bech32_decode(bad)
    assert mine.bech32_decode(bad) == (None, None)


def test_decode_rejects_mixed_case():
    assert mine.bech32_decode("A12uel5l") == real.bech32_decode("A12uel5l")
    assert mine.bech32_decode("A12uel5l") == (None, None)


def test_decode_rejects_characters_outside_the_printable_range():
    assert mine.bech32_decode("A12UEL5L\x7f") == real.bech32_decode("A12UEL5L\x7f")
    assert mine.bech32_decode("A12UEL5L\x00") == real.bech32_decode("A12UEL5L\x00")
    assert mine.bech32_decode("A12UEL5L\x00") == (None, None)


@pytest.mark.parametrize(
    "frombits,tobits", [(5, 8), (8, 5), (5, 5), (1, 8), (8, 1), (3, 7)]
)
@pytest.mark.parametrize("pad", [True, False])
def test_convertbits_matches_upstream(frombits, tobits, pad):
    rng = np.random.default_rng(frombits * 100 + tobits)
    limit = 1 << min(frombits, 8)
    for n in (0, 1, 2, 3, 7, 8, 20, 64):
        data = [int(x) for x in rng.integers(0, limit, size=n)]
        assert mine.convertbits(data, frombits, tobits, pad) == real.convertbits(
            data, frombits, tobits, pad
        )


def test_convertbits_rejects_out_of_range_and_negative_values():
    for data in ([-1], [32], [1 << 40], [0, 99]):
        assert mine.convertbits(data, 5, 8) == real.convertbits(data, 5, 8)
        assert mine.convertbits(data, 5, 8) is None


def test_convertbits_unpadded_rejects_a_stray_partial_group():
    """Five 5-bit groups are 25 bits, so unpadded 8-bit unpacking must refuse.

    Padding them would invent a byte that was never in the input, which is
    exactly what a witness program must not tolerate.
    """
    assert mine.convertbits([31] * 5, 5, 8, False) is None
    assert real.convertbits([31] * 5, 5, 8, False) is None
    assert mine.convertbits([31] * 8, 5, 8, False) is not None


@pytest.mark.parametrize("length", [5, 20, 40])
def test_convertbits_preserves_the_bit_stream(length):
    """Repacking 8->5->8 with padding must return the original bytes.

    Only byte counts that are a multiple of five survive: 5 bytes is 40 bits,
    which is eight whole 5-bit groups with nothing left over to pad.
    """
    rng = np.random.default_rng(5)
    data = [int(x) for x in rng.integers(0, 256, size=length, dtype="uint8")]
    packed = mine.convertbits(data, 8, 5)
    assert mine.convertbits(packed, 5, 8, True) == data
    assert mine.convertbits(packed, 5, 8, True) == real.convertbits(packed, 5, 8, True)


def test_charset_round_trip():
    for values in ([], [0], list(range(32)), [5] * 9):
        text = mine._lib.map_to_charset(values).decode("ascii")
        assert text == "".join(real.CHARSET[v] for v in values)
        assert mine._lib.map_from_charset(text) == values


def test_unknown_charset_character_is_rejected():
    assert mine._lib.map_from_charset("qqb") is None
    assert mine._lib.map_from_charset("qqI") is None
    assert mine.bech32_decode("bc1qqIb") == (None, None)
    assert real.bech32_decode("bc1qqIb") == (None, None)


def test_batch_checksum_equals_the_scalar_path():
    rng = np.random.default_rng(19)
    rows = [[int(x) for x in rng.integers(0, 32, size=32)] for _ in range(64)]
    batched = mine.bech32_create_checksums("bc", rows)
    assert batched == [real.bech32_create_checksum("bc", row) for row in rows]
    from mojo_bech32 import _lib

    assert _lib.polymod_batch("bc", rows) == [
        real.bech32_polymod(real.bech32_hrp_expand("bc") + row) for row in rows
    ]


def test_batch_on_an_empty_block():
    assert mine.bech32_create_checksums("bc", []) == []


def test_random_payloads_match_upstream():
    rng = np.random.default_rng(20260926)
    for _ in range(300):
        n = int(rng.integers(0, 60))
        data = [int(x) for x in rng.integers(0, 32, size=n)]
        hrp = "".join(
            chr(int(x)) for x in rng.integers(97, 123, size=int(rng.integers(1, 6)))
        )
        assert mine.bech32_create_checksum(hrp, data) == real.bech32_create_checksum(
            hrp, data
        )
        assert mine.bech32_encode(hrp, data) == real.bech32_encode(hrp, data)
        assert mine.bech32_decode(mine.bech32_encode(hrp, data)) == real.bech32_decode(
            real.bech32_encode(hrp, data)
        )
