#!/usr/bin/env python3
"""
BIP-375 PSBT map extensions

BIP375PSBTMap (a PSBTMap subclass with BIP-375 field access helpers)
BIP375PSBT (a PSBT subclass that deserializes into BIP375PSBTMap instances)
"""

from io import BytesIO
import struct
from typing import List, Optional, Tuple

from deps.bitcoin_test.messages import CTransaction, deser_compact_size, from_binary
from deps.bitcoin_test.psbt import (
    PSBT,
    PSBTMap,
    PSBT_GLOBAL_VERSION,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_UNSIGNED_TX,
)

PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
PSBT_GLOBAL_SP_DLEQ = 0x08

PSBT_IN_SP_ECDH_SHARE = 0x1D
PSBT_IN_SP_DLEQ = 0x1E

PSBT_OUT_SP_V0_INFO = 0x09
PSBT_OUT_SP_V0_LABEL = 0x0A


class BIP375PSBTMap(PSBTMap):
    """PSBTMap with BIP-375 field access helpers"""

    def __getitem__(self, key):
        return self.map[key]

    def __contains__(self, key):
        return key in self.map

    def get(self, key, default=None):
        return self.map.get(key, default)

    def get_all_by_type(self, key_type: int) -> List[Tuple[bytes, bytes]]:
        """
        Get all entries with the given key_type

        Returns list of (key_data, value_data) tuples. For single-byte keys (no
        key_data), key_data is b''.
        """
        result = []
        for key, value_data in self.map.items():
            if isinstance(key, int) and key == key_type:
                result.append((b"", value_data))
            elif isinstance(key, bytes) and len(key) > 0 and key[0] == key_type:
                result.append((key[1:], value_data))
        return result

    def get_by_key(self, key_type: int, key_data: bytes) -> Optional[bytes]:
        """Get value_data for a specific key_type + key_data combination"""
        if key_data == b"":
            return self.map.get(key_type)
        return self.map.get(bytes([key_type]) + key_data)


class BIP375PSBT(PSBT):
    """PSBT that deserializes maps as BIP375PSBTMap instances"""

    def deserialize(self, f):
        assert f.read(5) == b"psbt\xff"
        self.g = from_binary(BIP375PSBTMap, f)

        self.version = 0
        if PSBT_GLOBAL_VERSION in self.g.map:
            assert PSBT_GLOBAL_INPUT_COUNT in self.g.map
            assert PSBT_GLOBAL_OUTPUT_COUNT in self.g.map
            self.version = struct.unpack("<I", self.g.map[PSBT_GLOBAL_VERSION])[0]
            assert self.version in [0, 2]
        if self.version == 2:
            self.in_count = deser_compact_size(
                BytesIO(self.g.map[PSBT_GLOBAL_INPUT_COUNT])
            )
            self.out_count = deser_compact_size(
                BytesIO(self.g.map[PSBT_GLOBAL_OUTPUT_COUNT])
            )
        else:
            assert PSBT_GLOBAL_UNSIGNED_TX in self.g.map
            tx = from_binary(CTransaction, self.g.map[PSBT_GLOBAL_UNSIGNED_TX])
            self.in_count = len(tx.vin)
            self.out_count = len(tx.vout)

        self.i = [from_binary(BIP375PSBTMap, f) for _ in range(self.in_count)]
        self.o = [from_binary(BIP375PSBTMap, f) for _ in range(self.out_count)]
        return self
