#!/usr/bin/env python3
"""
PSBT input utility functions
"""

import struct
from typing import Optional, Tuple

from deps.bitcoin_test.messages import CTransaction, CTxOut, from_binary
from deps.bitcoin_test.psbt import (
    PSBT,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_WITNESS_UTXO,
)
from secp256k1lab.secp256k1 import GE

from .psbt_bip375 import BIP375PSBTMap, PSBT_GLOBAL_SP_ECDH_SHARE, PSBT_IN_SP_ECDH_SHARE


def collect_input_ecdh_and_pubkey(
    psbt: PSBT, scan_key: bytes
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Collect combined ECDH share and summed pubkey for a scan key.

    Checks global ECDH share first, falls back to per-input shares.
    Returns (ecdh_share_bytes, summed_pubkey_bytes) or (None, None).
    """
    # Check for global ECDH share
    summed_pubkey = None
    ecdh_share = psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key)
    if ecdh_share:
        summed_pubkey = None
        for input_map in psbt.i:
            pubkey = pubkey_from_eligible_input(input_map)
            if pubkey is not None:
                summed_pubkey = (
                    pubkey if summed_pubkey is None else summed_pubkey + pubkey
                )

        if summed_pubkey:
            return ecdh_share, summed_pubkey.to_bytes_compressed()

    # Check for per-input ECDH shares
    combined_ecdh = None
    for input_map in psbt.i:
        input_ecdh = input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
        if input_ecdh:
            if not is_input_eligible(input_map):
                continue # skip ineligible inputs
            ecdh_point = GE.from_bytes(input_ecdh)
            combined_ecdh = (
                ecdh_point if combined_ecdh is None else combined_ecdh + ecdh_point
            )
            pubkey = pubkey_from_eligible_input(input_map)
            if pubkey is not None:
                summed_pubkey = (
                    pubkey if summed_pubkey is None else summed_pubkey + pubkey
                )

    if combined_ecdh and summed_pubkey:
        return combined_ecdh.to_bytes_compressed(), summed_pubkey.to_bytes_compressed()
    return None, None


def pubkey_from_eligible_input(input_map: BIP375PSBTMap) -> Optional[GE]:
    """
    Extract the public key from a PSBT input map if eligible for silent payments

    Returns a GE point (public key), or None if not found
    """
    if not is_input_eligible(input_map):
        return None

    # Try BIP32 derivation first (key_data is the pubkey)
    derivations = input_map.get_all_by_type(PSBT_IN_BIP32_DERIVATION)
    if derivations:
        pubkey, _ = derivations[0]
        if len(pubkey) == 33:
            return GE.from_bytes(pubkey)

    # Try PSBT_IN_WITNESS_UTXO for P2TR inputs
    spk = parse_witness_utxo(input_map[PSBT_IN_WITNESS_UTXO])
    if spk and _is_p2tr(spk):
        return GE.from_bytes(bytes([0x02]) + spk[2:34])
    return None


# ============================================================================
# scriptPubKey helpers
# ============================================================================


def _script_pubkey_from_psbt_input(input_map: BIP375PSBTMap) -> Optional[bytes]:
    """Extract scriptPubKey from PSBT input fields"""
    script_pubkey = None

    # Try WITNESS_UTXO first
    if PSBT_IN_WITNESS_UTXO in input_map:
        script_pubkey = parse_witness_utxo(input_map[PSBT_IN_WITNESS_UTXO])

    # Try NON_WITNESS_UTXO for legacy inputs
    elif PSBT_IN_NON_WITNESS_UTXO in input_map:
        non_witness_utxo = input_map[PSBT_IN_NON_WITNESS_UTXO]
        # Get the output index from PSBT_IN_OUTPUT_INDEX field
        if PSBT_IN_OUTPUT_INDEX in input_map:
            output_index_bytes = input_map[PSBT_IN_OUTPUT_INDEX]
            if len(output_index_bytes) == 4:
                output_index = struct.unpack("<I", output_index_bytes)[0]
                script_pubkey = _parse_non_witness_utxo(non_witness_utxo, output_index)
    return script_pubkey


def parse_witness_utxo(witness_utxo: bytes) -> bytes:
    """Extract scriptPubKey from witness_utxo"""
    utxo = from_binary(CTxOut, witness_utxo)
    return utxo.scriptPubKey


def _parse_non_witness_utxo(non_witness_utxo: bytes, output_index: int) -> bytes:
    """Extract scriptPubKey from non_witness_utxo"""
    tx = from_binary(CTransaction, non_witness_utxo)
    assert output_index < len(tx.vout), "Invalid output index"
    return tx.vout[output_index].scriptPubKey


# ============================================================================
# Input eligibility helpers
# ============================================================================


def is_input_eligible(input_map: BIP375PSBTMap) -> bool:
    """Check if input is eligible for silent payments"""
    script_pubkey = _script_pubkey_from_psbt_input(input_map)
    assert script_pubkey is not None, (
        "scriptPubKey could not be extracted from PSBT input"
    )

    if not _has_eligible_script_type(script_pubkey):
        return False

    NUMS_H = bytes.fromhex(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    if _is_p2tr(script_pubkey):
        tap_internal_key = input_map.get(PSBT_IN_TAP_INTERNAL_KEY)
        if tap_internal_key == NUMS_H:
            return False

    if _is_p2sh(script_pubkey):
        if PSBT_IN_REDEEM_SCRIPT in input_map:
            redeem_script = input_map[PSBT_IN_REDEEM_SCRIPT]
            if not _is_p2wpkh(redeem_script):
                return False
        else:
            assert False
    return True


def _has_eligible_script_type(script_pubkey: bytes) -> bool:
    """True if scriptPubKey is eligible for silent payments"""
    return (
        _is_p2pkh(script_pubkey)
        or _is_p2wpkh(script_pubkey)
        or _is_p2tr(script_pubkey)
        or _is_p2sh(script_pubkey)
    )


def _is_p2tr(spk: bytes) -> bool:
    if len(spk) != 34:
        return False
    # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return (spk[0] == 0x51) & (spk[1] == 0x20)


def _is_p2wpkh(spk: bytes) -> bool:
    if len(spk) != 22:
        return False
    # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return (spk[0] == 0x00) & (spk[1] == 0x14)


def _is_p2sh(spk: bytes) -> bool:
    if len(spk) != 23:
        return False
    # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return (spk[0] == 0xA9) & (spk[1] == 0x14) & (spk[-1] == 0x87)


def _is_p2pkh(spk: bytes) -> bool:
    if len(spk) != 25:
        return False
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (
        (spk[0] == 0x76)
        & (spk[1] == 0xA9)
        & (spk[2] == 0x14)
        & (spk[-2] == 0x88)
        & (spk[-1] == 0xAC)
    )
