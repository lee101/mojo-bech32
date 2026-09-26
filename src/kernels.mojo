"""Bech32 checksum, charset mapping and bit repacking in compiled Mojo.

Bech32 is numeric work end to end: the checksum is a linear feedback shift
register over GF(2), the charset is a 32-entry codebook, and the segwit payload
is a bit repacking between 5-bit and 8-bit groups. Each of those is a loop over
an array of small integers, which is what the kernels below do.

Buffers cross the C ABI as 64-bit addresses and are rebuilt inside each body,
because `@export` rejects a function whose parameter types are inferred. Nothing
here allocates, so no exported symbol is `raises`.
"""

comptime BPtr = Pointer[UInt8, AnyOrigin[mut=True]]
comptime I32 = Pointer[Int32, AnyOrigin[mut=True]]
comptime I64 = Pointer[Int64, AnyOrigin[mut=True]]

comptime GEN0 = Int64(0x3B6A57B2)
comptime GEN1 = Int64(0x26508E6D)
comptime GEN2 = Int64(0x1EA119FA)
comptime GEN3 = Int64(0x3D4233DD)
comptime GEN4 = Int64(0x2A1462B3)


def bu8(addr: Int) -> BPtr:
    return BPtr(unsafe_from_address=addr)


def bi32(addr: Int) -> I32:
    return I32(unsafe_from_address=addr)


def bi64(addr: Int) -> I64:
    return I64(unsafe_from_address=addr)


def polymod_step(chk: Int64, value: Int64) -> Int64:
    """One BCH round: shift a value in, then fold the five generator taps."""
    var top = chk >> Int64(25)
    var c = ((chk & Int64(0x1FFFFFF)) << Int64(5)) ^ value
    for i in range(5):
        if (top >> Int64(i)) & 1:
            c = c ^ (
                GEN0 if i == 0
                else GEN1 if i == 1
                else GEN2 if i == 2
                else GEN3 if i == 3
                else GEN4
            )
    return c


def polymod_run(hrp: I32, hrp_len: Int, vals: I32, n: Int, offset: Int,
                tail_zeros: Int = 0) -> Int64:
    """Polymod over expand(hrp), then `n` values from `offset`, then `tail_zeros`.

    The HRP expansion is the reference definition: high five bits of each code
    point, a zero separator, then the low five bits. `tail_zeros` is the six
    zero words the checksum definition appends; they are real LFSR steps, not a
    no-op, so they have to be fed through rather than folded in afterwards. The
    accumulator stays under 2**30 because the mask keeps 25 bits before the
    five-bit shift.
    """
    var chk = Int64(1)
    for i in range(hrp_len):
        chk = polymod_step(chk, Int64(hrp[unsafe_offset=i]) >> Int64(5))
    chk = polymod_step(chk, Int64(0))
    for i in range(hrp_len):
        chk = polymod_step(chk, Int64(hrp[unsafe_offset=i]) & Int64(31))
    for i in range(n):
        chk = polymod_step(chk, Int64(vals[unsafe_offset=offset + i]))
    for _ in range(tail_zeros):
        chk = polymod_step(chk, Int64(0))
    return chk


def write_checksum(dst: I32, at: Int, pm: Int64):
    for i in range(6):
        dst[unsafe_offset=at + i] = Int32((pm >> Int64(5 * (5 - i))) & Int64(31))


@export("b32_polymod")
def b32_polymod(hrp_addr: Int, hrp_len: Int, data_addr: Int, n: Int,
                 out_addr: Int) abi("C"):
    """Write polymod(expand(hrp) + data) as one int64."""
    bi64(out_addr)[unsafe_offset=0] = polymod_run(
        bi32(hrp_addr), hrp_len, bi32(data_addr), n, 0
    )


@export("b32_polymod_values")
def b32_polymod_values(data_addr: Int, n: Int, out_addr: Int) abi("C"):
    """Polymod over a bare value list, with no HRP expansion in front of it.

    This is the `bech32_polymod(values)` entry point, where the caller has
    already built the expansion.
    """
    var vals = bi64(data_addr)
    var chk = Int64(1)
    for i in range(n):
        chk = polymod_step(chk, vals[unsafe_offset=i])
    bi64(out_addr)[unsafe_offset=0] = chk


@export("b32_create_checksum")
def b32_create_checksum(hrp_addr: Int, hrp_len: Int, data_addr: Int, n: Int,
                        out_addr: Int) abi("C"):
    """Write the six checksum words for expand(hrp) + data."""
    var pm = polymod_run(
        bi32(hrp_addr), hrp_len, bi32(data_addr), n, 0, 6
    ) ^ Int64(1)
    write_checksum(bi32(out_addr), 0, pm)


@export("b32_verify_checksum")
def b32_verify_checksum(hrp_addr: Int, hrp_len: Int, data_addr: Int,
                        n: Int) abi("C") -> Int:
    """1 when polymod(expand(hrp) + data) == 1, else 0."""
    if polymod_run(bi32(hrp_addr), hrp_len, bi32(data_addr), n, 0) == 1:
        return 1
    return 0


@export("b32_polymod_batch")
def b32_polymod_batch(hrp_addr: Int, hrp_len: Int, data_addr: Int, stride: Int,
                      count: Int, out_addr: Int) abi("C"):
    """Polymod for `count` equal-length rows sharing one HRP, written in place.

    This is the same recurrence as `b32_polymod` applied to a block of rows, so
    a validator checking a whole block pays one call instead of one per address.
    """
    var hrp = bi32(hrp_addr)
    var vals = bi32(data_addr)
    var out = bi64(out_addr)
    for r in range(count):
        out[unsafe_offset=r] = polymod_run(hrp, hrp_len, vals, stride, r * stride)


@export("b32_create_checksum_batch")
def b32_create_checksum_batch(hrp_addr: Int, hrp_len: Int, data_addr: Int,
                              stride: Int, count: Int, out_addr: Int) abi("C"):
    """Six checksum words per row, row-major, for `count` rows of `stride`."""
    var hrp = bi32(hrp_addr)
    var vals = bi32(data_addr)
    var out = bi32(out_addr)
    for r in range(count):
        var pm = polymod_run(
            hrp, hrp_len, vals, stride, r * stride, 6
        ) ^ Int64(1)
        write_checksum(out, r * 6, pm)


@export("b32_map_to_charset")
def b32_map_to_charset(data_addr: Int, n: Int, charset_addr: Int,
                       out_addr: Int) abi("C") -> Int:
    """Map each 5-bit value to its charset character."""
    var vals = bi32(data_addr)
    var cs = bu8(charset_addr)
    var out = bu8(out_addr)
    for i in range(n):
        out[unsafe_offset=i] = cs[unsafe_offset=vals[unsafe_offset=i]]
    return 0


@export("b32_map_from_charset")
def b32_map_from_charset(chars_addr: Int, n: Int, dmap_addr: Int,
                         out_addr: Int) abi("C") -> Int:
    """Map each byte to its 5-bit value, or return -(2 + index) if unknown."""
    var chars = bu8(chars_addr)
    var dmap = bi32(dmap_addr)
    var out = bi32(out_addr)
    for i in range(n):
        var v = dmap[unsafe_offset=chars[unsafe_offset=i]]
        if v < 0:
            return -(2 + i)
        out[unsafe_offset=i] = v
    return n


@export("b32_convertbits")
def b32_convertbits(data_addr: Int, n: Int, frombits: Int, tobits: Int, pad: Int,
                    out_addr: Int, out_cap: Int) abi("C") -> Int:
    """Repack a bit stream from `frombits`-wide groups to `tobits`-wide groups.

    Returns the number of values written, -1 if `out_cap` is too small, -2 if the
    requested group widths cannot be held in the accumulator or the unpadded
    tail is not a legal encoding, and -(3 + i) if input value `i` does not fit
    in `frombits` bits. Widths and values are int64, so frombits + tobits - 1
    must not exceed 62.
    """
    if frombits < 1 or tobits < 1 or frombits + tobits - 1 > 62:
        return -2
    var vals = bi64(data_addr)
    var dst = bi64(out_addr)
    var maxv = (Int64(1) << Int64(tobits)) - Int64(1)
    var max_acc = (Int64(1) << Int64(frombits + tobits - 1)) - Int64(1)
    var acc = Int64(0)
    var bits = 0
    var k = 0
    for i in range(n):
        var value = vals[unsafe_offset=i]
        if value < 0 or (value >> Int64(frombits)) != 0:
            return -(3 + i)
        acc = ((acc << Int64(frombits)) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            if k >= out_cap:
                return -1
            dst[unsafe_offset=k] = (acc >> Int64(bits)) & maxv
            k += 1
    if pad != 0:
        if bits != 0:
            if k >= out_cap:
                return -1
            dst[unsafe_offset=k] = (acc << Int64(tobits - bits)) & maxv
            k += 1
    elif bits >= frombits or ((acc << Int64(tobits - bits)) & maxv) != 0:
        return -2
    return k
