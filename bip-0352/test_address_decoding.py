#!/usr/bin/env python3

import unittest

from bech32m import Encoding, bech32_encode, convertbits
from reference import decode_silent_payment_address
from secp256k1lab.secp256k1 import GE


SCAN_KEY = bytes.fromhex("0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4")
SPEND_KEY = bytes.fromhex("025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36")
PAYLOAD = SCAN_KEY + SPEND_KEY


def make_address(version, payload=PAYLOAD, spec=Encoding.BECH32M):
    data = convertbits(payload, 8, 5)
    return bech32_encode("tsp", [version] + data, spec)


class SilentPaymentAddressDecodingTest(unittest.TestCase):
    def test_accepts_higher_forward_compatible_version(self):
        scan, spend = decode_silent_payment_address(make_address(17))
        self.assertEqual(scan, GE.from_bytes_compressed(SCAN_KEY))
        self.assertEqual(spend, GE.from_bytes_compressed(SPEND_KEY))

    def test_discards_forward_compatible_extension_data(self):
        scan, spend = decode_silent_payment_address(make_address(1, PAYLOAD + b"extension"))
        self.assertEqual(scan, GE.from_bytes_compressed(SCAN_KEY))
        self.assertEqual(spend, GE.from_bytes_compressed(SPEND_KEY))

    def test_rejects_bech32_for_version_zero(self):
        scan, spend = decode_silent_payment_address(make_address(0, spec=Encoding.BECH32))
        self.assertTrue(scan.infinity)
        self.assertTrue(spend.infinity)

    def test_rejects_extra_data_for_version_zero(self):
        scan, spend = decode_silent_payment_address(make_address(0, PAYLOAD + b"extension"))
        self.assertTrue(scan.infinity)
        self.assertTrue(spend.infinity)

    def test_rejects_version_31(self):
        scan, spend = decode_silent_payment_address(make_address(31))
        self.assertTrue(scan.infinity)
        self.assertTrue(spend.infinity)


if __name__ == "__main__":
    unittest.main()
