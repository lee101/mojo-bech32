# mojo-bech32

`mojo-bech32` is a drop-in replacement for [bech32](https://pypi.org/project/bech32/)
1.2.0 with the checksum, charset mapping and bit repacking running as compiled
Mojo. The public names, return conventions and validation order are unchanged,
so it imports alongside the real package; the parity tests compare the two
directly.

```python
import mojo_bech32 as bech32

bech32.encode("bc", 0, bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6"))
# 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
bech32.decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
# (0, [0x75, 0x1e, ...])
bech32.bech32_create_checksum("bc", [0, 1, 2, 3, 4, 5])
# [3, 30, 31, 6, 28, 10]
```

## Why this is a real port

Bech32 is arithmetic all the way down. The checksum is a five-tap linear
feedback shift register over GF(2) run once per 5-bit word; the charset is a
32-entry codebook; and a segwit payload is a bit stream repacked between 5-bit
words and 8-bit bytes. Each is a loop over an array of small integers with a
serial dependency — exactly the shape a compiled inner loop improves, and
exactly the shape that makes a pure-Python `for` loop expensive when a block
validator has to run it tens of thousands of times.

The one structural thing that is *not* ported is string policy: the printable
range check, the mixed-case rejection, the search for the `1` separator and the
`pos` length limits. That is control flow over a 90-character string, not
arithmetic, and moving it would change the code without changing the cost.

## Covered subset

| area | implemented API | where the work happens |
| --- | --- | --- |
| Checksum | `bech32_polymod`, `bech32_create_checksum`, `bech32_verify_checksum` | Mojo: the BCH recurrence and the HRP expansion |
| Checksum, block form | `bech32_create_checksums` | Mojo: the same recurrence over many rows in one call |
| Encoding | `bech32_encode` | Mojo: checksum plus charset mapping; Python joins the strings |
| Decoding | `bech32_decode` | Mojo: charset mapping and checksum verification; Python does the string validation |
| Segwit | `encode`, `decode` | Mojo: `convertbits` both directions; Python keeps the length rules |
| Bit packing | `convertbits` | Mojo: generic `frombits`/`tobits` accumulator |
| Charset | `CHARSET` | Python constant, identical to upstream |

Not implemented, and not invented:

- No bech32m. `bech32` 1.2.0 has no bech32m constant and neither does this; a
  port that added one would be claiming coverage the upstream package does not
  have.
- No address validation beyond the reference rules. BIP-173's `m`/limit checks
  beyond the 90-character cap stay commented out upstream and stay out here.
- `convertbits` is limited to `frombits + tobits - 1 <= 62` and int64 values,
  because the accumulator is a 64-bit register. That covers every width segwit
  and every width in the reference tests. A wider request raises `ValueError`
  rather than silently truncating.

## Install

The repository pins its own Mojo toolchain:

```bash
pixi install
pixi run build
pixi run test
```

`pixi run build` produces `dist/libmojo-bech32.so`. Set `PYTHONPATH=python` when
using the package outside a Pixi task.

## Performance

Best-of-N wall clock in one process, against the real `bech32` package. Every
case verifies agreement with upstream before timing.

| case | bech32 | mojo-bech32 | ratio |
| --- | ---: | ---: | ---: |
| checksum block 20000 x 32 | 1982.33 ms | 222.13 ms | 8.92x faster |
| polymod block 20000 x 32 | 1559.25 ms | 88.74 ms | 17.57x faster |
| segwit encode+decode x 20000 | 17650.13 ms | 10538.17 ms | 1.67x faster |
| convertbits 32 B, 8->5 | 0.02 ms | 0.02 ms | 0.63x slower |

The `convertbits` row is a loss and is reported as one. A 32-byte witness
program is 32 input words and 52 output words; at that size the ctypes crossing
and the two NumPy scratch allocations cost more than the loop they replace. The
block rows are the reason the batch entry points exist: the same recurrence over
20 000 rows is 9x to 18x faster because it crosses the FFI boundary once, and
because the per-row cost stops being Python interpreter time.

The segwit round trip only reaches 1.67x because most of it is Python: string
validation, `CHARSET` joins and the length rules stay on this side by design.

Reproduce with:

```bash
pixi run bench
```

## How it works

All kernels live in `src/kernels.mojo`, one compilation unit, because shared
library build cost is largely fixed. `build/build.sh` compiles it with
`mojo build --emit shared-lib` into `dist/libmojo-bech32.so`.

The Python layer owns every array. Scratch buffers are allocated per call, which
keeps the exported symbols free of allocation and therefore free of `raises` — an
`@export ... abi("C")` function cannot be `raises`. Buffers cross the C ABI as
64-bit addresses and are rebuilt in Mojo as `Pointer[T, AnyOrigin[mut=True]]`,
because `@export` rejects a function whose parameter types are inferred.

One detail is easy to get wrong and is pinned by a test: the checksum is
defined as `polymod(expand(hrp) + data + [0]*6) ^ 1`. Those six zero words are
real LFSR steps, not padding, so they have to be fed through the recurrence
before the XOR. Folding the XOR in first still produces six plausible words and
still passes the package's own verifier, which is why the test compares against
the reference definition rather than against a round trip.

Every quantity here is a small integer or a character code, so nothing is
floating point and the usual FMA caveat does not apply. The parity tests assert
exact equality throughout.

## Tests

```bash
pixi run test
```

51 tests: the BIP-173 valid-string and segwit-address vectors, the checksum and
polymod pinned against the reference definition rather than against a round
trip, the HRP expansion order, single-word checksum corruption at every
position, `convertbits` across six width pairs with and without padding,
charset round trips, batch-versus-scalar agreement, and 300 randomised
HRP/payload comparisons.

## License

MIT
