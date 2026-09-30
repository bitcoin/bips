#!/usr/bin/env python3
"""Unit tests for BIP-375 field lengths in the structure validator."""

import unittest

# Reuse the test runner's dependency setup.
from test_runner import validate_psbt_structure
from deps.bitcoin_test.psbt import PSBT_OUT_SCRIPT
from validator.psbt_bip375 import (
    BIP375PSBT,
    BIP375PSBTMap,
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
)


class ScanKeyLengthTests(unittest.TestCase):
    FIELDS = (
        (PSBT_GLOBAL_SP_ECDH_SHARE, True, 33, "Global ECDH share"),
        (PSBT_GLOBAL_SP_DLEQ, True, 64, "Global DLEQ proof"),
        (PSBT_IN_SP_ECDH_SHARE, False, 33, "Input 1 ECDH share"),
        (PSBT_IN_SP_DLEQ, False, 64, "Input 1 DLEQ proof"),
    )

    def make_psbt(self, key, is_global, value_length):
        # These maps exercise structure checks only, not cryptographic validity.
        psbt = BIP375PSBT(
            g=BIP375PSBTMap(),
            i=[BIP375PSBTMap(), BIP375PSBTMap()],
            o=[BIP375PSBTMap(map={PSBT_OUT_SCRIPT: b"\x51"})],
        )
        target = psbt.g if is_global else psbt.i[1]
        target.map[key] = bytes(value_length)
        return psbt

    def test_invalid_scan_key_lengths(self):
        for field, is_global, value_length, context in self.FIELDS:
            # Empty keydata can be represented by an int or a one-byte key.
            keys = [(field, 0)] + [
                (bytes([field]) + bytes(length), length)
                for length in (0, 32, 34, 65)
            ]
            for key, length in keys:
                with self.subTest(field=field, length=length, key_type=type(key)):
                    psbt = self.make_psbt(key, is_global, value_length)
                    self.assertEqual(
                        validate_psbt_structure(psbt),
                        (
                            False,
                            f"{context} scan key has wrong length ({length} bytes, expected 33)",
                        ),
                    )

    def test_valid_scan_key_lengths(self):
        for field, is_global, value_length, _ in self.FIELDS:
            with self.subTest(field=field):
                key = bytes([field]) + bytes(33)
                psbt = self.make_psbt(key, is_global, value_length)
                self.assertEqual(validate_psbt_structure(psbt), (True, None))

    def test_invalid_value_lengths(self):
        for field, is_global, value_length, context in self.FIELDS:
            for length in (value_length - 1, value_length + 1):
                with self.subTest(field=field, length=length):
                    key = bytes([field]) + bytes(33)
                    psbt = self.make_psbt(key, is_global, length)
                    self.assertEqual(
                        validate_psbt_structure(psbt),
                        (
                            False,
                            f"{context} has wrong length ({length} bytes, expected {value_length})",
                        ),
                    )


if __name__ == "__main__":
    unittest.main()
