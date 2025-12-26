#!/usr/bin/env python3
"""
BIP 375: Input Validation Helpers

Functions for validating PSBT input types and checking segwit versions.
"""

import struct
from typing import Optional

from constants import PSBTFieldType


def check_invalid_segwit_version(witness_utxo: bytes) -> bool:
    """Check if witness UTXO uses invalid segwit version for silent payments"""

    # Skip amount (8 bytes) and script length
    if len(witness_utxo) < 9:
        return False

    offset = 8  # Skip amount
    script_len = witness_utxo[offset]
    offset += 1

    if offset + script_len > len(witness_utxo):
        return False

    script = witness_utxo[offset : offset + script_len]

    # Check if it's segwit v2 or higher
    if len(script) >= 2 and script[0] >= 0x52:  # OP_2 or higher
        return True

    return False


def get_input_script_pubkey(input_fields: dict) -> Optional[bytes]:
    """Extract scriptPubKey from PSBT input fields"""
    script_pubkey = None

    # Try WITNESS_UTXO first (segwit inputs)
    if PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
        witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
        # Extract scriptPubKey from witness_utxo (skip 8-byte amount + 1-byte length)
        if len(witness_utxo) >= 9:
            script_len = witness_utxo[8]
            script_pubkey = witness_utxo[9 : 9 + script_len]

    # Try NON_WITNESS_UTXO for legacy inputs (P2PKH, P2SH)
    elif PSBTFieldType.PSBT_IN_NON_WITNESS_UTXO in input_fields:
        non_witness_utxo = input_fields[PSBTFieldType.PSBT_IN_NON_WITNESS_UTXO]
        # Get the output index from PSBT_IN_OUTPUT_INDEX field
        if PSBTFieldType.PSBT_IN_OUTPUT_INDEX in input_fields:
            output_index_bytes = input_fields[PSBTFieldType.PSBT_IN_OUTPUT_INDEX]
            if len(output_index_bytes) == 4:
                output_index = struct.unpack("<I", output_index_bytes)[0]
                script_pubkey = parse_non_witness_utxo(non_witness_utxo, output_index)

    return script_pubkey


def validate_input_eligibility(
    input_fields: dict, input_index: int
) -> tuple[bool, str]:
    """Validate that input is an eligible type for silent payments"""

    script_pubkey = get_input_script_pubkey(input_fields)

    if script_pubkey is None:
        return False, f"Input {input_index} missing UTXO information"

    if not is_eligible_input_type(script_pubkey):
        return False, f"Input {input_index} uses ineligible input type"

    # For P2SH, verify it's P2SH-P2WPKH
    if is_p2sh(script_pubkey):
        if PSBTFieldType.PSBT_IN_REDEEM_SCRIPT in input_fields:
            redeem_script = input_fields[PSBTFieldType.PSBT_IN_REDEEM_SCRIPT]
            # Verify redeemScript is P2WPKH
            if not is_p2wpkh(redeem_script):
                return False, f"Input {input_index} P2SH is not P2SH-P2WPKH"
        else:
            return False, f"Input {input_index} P2SH missing PSBT_IN_REDEEM_SCRIPT"

    return True, "Input is eligible"


# =====================================================
# Silent Payments Utilities
# =====================================================

def is_p2tr(spk: bytes) -> bool:
    if len(spk) != 34:
        return False
    # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return (spk[0] == 0x51) & (spk[1] == 0x20)


def is_p2wpkh(spk: bytes) -> bool:
    if len(spk) != 22:
        return False
    # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return (spk[0] == 0x00) & (spk[1] == 0x14)


def is_p2sh(spk: bytes) -> bool:
    if len(spk) != 23:
        return False
    # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return (spk[0] == 0xA9) & (spk[1] == 0x14) & (spk[-1] == 0x87)


def is_p2pkh(spk: bytes) -> bool:
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


def is_eligible_input_type(script_pubkey: bytes) -> bool:
    """Check if scriptPubKey is an eligible input type for silent payments per BIP-352"""
    return (
        is_p2pkh(script_pubkey)
        or is_p2wpkh(script_pubkey)
        or is_p2tr(script_pubkey)
        or is_p2sh(script_pubkey)
    )


def parse_non_witness_utxo(non_witness_utxo: bytes, output_index: int) -> bytes:
    """Extract scriptPubKey from NON_WITNESS_UTXO field"""
    try:
        offset = 0

        # Skip version (4 bytes)
        if len(non_witness_utxo) < 4:
            return None
        offset += 4

        # Parse input count (compact size)
        if offset >= len(non_witness_utxo):
            return None

        input_count = non_witness_utxo[offset]
        offset += 1
        if input_count >= 0xFD:
            # Handle larger compact size (simplified - just skip)
            if input_count == 0xFD:
                offset += 2
            elif input_count == 0xFE:
                offset += 4
            else:
                offset += 8
            input_count = (
                struct.unpack("<H", non_witness_utxo[offset - 2 : offset])[0]
                if input_count == 0xFD
                else 0
            )

        # Skip all inputs
        for _ in range(input_count):
            # Skip txid (32) + vout (4)
            offset += 36
            if offset >= len(non_witness_utxo):
                return None

            # Skip scriptSig
            script_len = non_witness_utxo[offset]
            offset += 1
            if script_len >= 0xFD:
                return None  # Simplified - don't handle large scripts
            offset += script_len

            # Skip sequence (4)
            offset += 4
            if offset > len(non_witness_utxo):
                return None

        # Parse output count
        if offset >= len(non_witness_utxo):
            return None
        output_count = non_witness_utxo[offset]
        offset += 1
        if output_count >= 0xFD:
            if output_count == 0xFD:
                output_count = struct.unpack(
                    "<H", non_witness_utxo[offset : offset + 2]
                )[0]
                offset += 2
            else:
                return None  # Simplified

        # Find the output at output_index
        for i in range(output_count):
            # Skip amount (8 bytes)
            if offset + 8 >= len(non_witness_utxo):
                return None
            offset += 8

            # Parse scriptPubKey length
            if offset >= len(non_witness_utxo):
                return None
            script_len = non_witness_utxo[offset]
            offset += 1
            if script_len >= 0xFD:
                if script_len == 0xFD:
                    script_len = struct.unpack(
                        "<H", non_witness_utxo[offset : offset + 2]
                    )[0]
                    offset += 2
                else:
                    return None

            # Extract scriptPubKey if this is our output
            if i == output_index:
                if offset + script_len > len(non_witness_utxo):
                    return None
                return non_witness_utxo[offset : offset + script_len]

            # Otherwise skip to next output
            offset += script_len
            if offset > len(non_witness_utxo):
                return None

        return None
    except Exception:
        return None
