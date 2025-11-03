#! /usr/bin/env python3

import json
import os
import sys

from _bip327 import cbytes, key_agg
from _xpub import ExtendedKey

CHAINCODE = bytes.fromhex("868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965")

def aggregate_to_xpub(aggregate: bytes) -> ExtendedKey:
    return ExtendedKey(ExtendedKey.MAINNET_PUBLIC, 0, b"\x00\x00\x00\x00", 0, CHAINCODE, None, aggregate)

def test_aggregate_to_xpub():
    with open(os.path.join(sys.path[0], "vectors.json"), "r") as f:
        test_data = json.load(f)

    for test_case in test_data:
        keys = [bytes.fromhex(k) for k in test_case["keys"]]

        agg_ctx = key_agg(keys)
        pub = cbytes(agg_ctx.Q)
        assert pub.hex() == test_case["aggregate_pubkey"]

        xpub = aggregate_to_xpub(pub)
        assert xpub.to_string() == test_case["xpub"]

if __name__ == "__main__":
    test_aggregate_to_xpub()
