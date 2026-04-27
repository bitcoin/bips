#!/usr/bin/env python3
"""BIP-376 PSBT helpers."""

from io import BytesIO
import struct
from typing import Optional

from deps.bitcoin_test.messages import CTransaction, CTxOut, deser_compact_size, from_binary
from deps.bitcoin_test.psbt import (
    PSBT,
    PSBTMap,
    PSBT_GLOBAL_INPUT_COUNT,
    PSBT_GLOBAL_OUTPUT_COUNT,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_VERSION,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_WITNESS_UTXO,
)

PSBT_IN_SP_SPEND_BIP32_DERIVATION = 0x1F
PSBT_IN_SP_TWEAK = 0x20


class BIP376PSBTMap(PSBTMap):
    """PSBTMap with helpers for BIP-376 field access."""

    def __getitem__(self, key):
        return self.map[key]

    def __contains__(self, key):
        return key in self.map

    def get(self, key, default=None):
        return self.map.get(key, default)

    def get_by_key(self, key_type: int, key_data: bytes = b"") -> Optional[bytes]:
        if key_data == b"":
            return self.map.get(key_type)
        return self.map.get(bytes([key_type]) + key_data)

    def set_by_key(self, key_type: int, value_data: bytes, key_data: bytes = b"") -> None:
        if key_data == b"":
            self.map[key_type] = value_data
        else:
            self.map[bytes([key_type]) + key_data] = value_data


class BIP376PSBT(PSBT):
    """PSBT that deserializes maps as BIP376PSBTMap instances."""

    def deserialize(self, f):
        assert f.read(5) == b"psbt\xff"
        self.g = from_binary(BIP376PSBTMap, f)

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

        self.i = [from_binary(BIP376PSBTMap, f) for _ in range(self.in_count)]
        self.o = [from_binary(BIP376PSBTMap, f) for _ in range(self.out_count)]
        return self


def get_p2tr_witness_utxo_output_key(input_map: BIP376PSBTMap) -> bytes:
    witness_utxo = input_map.get(PSBT_IN_WITNESS_UTXO)
    if witness_utxo is None:
        raise ValueError("missing PSBT_IN_WITNESS_UTXO")

    txout = from_binary(CTxOut, witness_utxo)
    script_pubkey = txout.scriptPubKey
    if len(script_pubkey) != 34 or script_pubkey[:2] != b"\x51\x20":
        raise ValueError("PSBT_IN_WITNESS_UTXO is not a P2TR output")
    return script_pubkey[2:]


def get_sp_tweak(input_map: BIP376PSBTMap) -> bytes:
    tweak = input_map.get(PSBT_IN_SP_TWEAK)
    if tweak is None:
        raise ValueError("missing PSBT_IN_SP_TWEAK")
    if len(tweak) != 32:
        raise ValueError("PSBT_IN_SP_TWEAK must be 32 bytes")
    return tweak


def set_tap_key_sig(input_map: BIP376PSBTMap, signature: bytes) -> None:
    if len(signature) not in (64, 65):
        raise ValueError("PSBT_IN_TAP_KEY_SIG must be 64 or 65 bytes")
    input_map.set_by_key(PSBT_IN_TAP_KEY_SIG, signature)
