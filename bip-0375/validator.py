#!/usr/bin/env python3
"""
BIP 375: PSBT Validator

Complete BIP 375 validation for PSBTs with silent payment outputs.
"""

import struct
from typing import Tuple

from constants import PSBTFieldType
from parser import parse_psbt_structure
from inputs import validate_input_eligibility, check_invalid_segwit_version
from dleq import validate_global_dleq_proof, validate_input_dleq_proof


def validate_bip375_psbt(psbt_data: bytes) -> Tuple[bool, str]:
    """Validate a PSBT according to BIP 375 rules"""

    # Basic PSBT structure validation
    if len(psbt_data) < 5 or psbt_data[:5] != b"psbt\xff":
        return False, "Invalid PSBT magic"

    # Parse PSBT fields
    global_fields, input_maps, output_maps = parse_psbt_structure(psbt_data)

    # Check if silent payment outputs exist
    # Either SP_V0_INFO or SP_V0_LABEL indicates silent payment intent
    has_silent_outputs = any(
        PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields
        or PSBTFieldType.PSBT_OUT_SP_V0_LABEL in output_fields
        for output_fields in output_maps
    )

    if not has_silent_outputs:
        # If no silent payment outputs, this is just a regular PSBT v2
        return True, "Valid PSBT v2 (no silent payments)"

    # Critical structural validation - SP_V0_INFO field sizes and PSBT_OUT_SCRIPT requirements
    for i, output_fields in enumerate(output_maps):
        # BIP375: Each output must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO (or both)
        has_script = PSBTFieldType.PSBT_OUT_SCRIPT in output_fields
        has_sp_info = PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields
        has_sp_label = PSBTFieldType.PSBT_OUT_SP_V0_LABEL in output_fields

        if not has_script and not has_sp_info:
            return (
                False,
                f"Output {i} must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO",
            )

        # PSBT_OUT_SP_V0_LABEL requires PSBT_OUT_SP_V0_INFO
        if has_sp_label and not has_sp_info:
            return (
                False,
                f"Output {i} has PSBT_OUT_SP_V0_LABEL but missing PSBT_OUT_SP_V0_INFO",
            )

        if has_sp_info:
            sp_info = output_fields[PSBTFieldType.PSBT_OUT_SP_V0_INFO]
            if len(sp_info) != 66:  # 33 + 33 bytes for scan_key + spend_key
                return (
                    False,
                    f"Output {i} SP_V0_INFO has wrong size ({len(sp_info)} bytes, expected 66)",
                )

    # ECDH shares must exist
    has_global_ecdh = PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE in global_fields
    has_input_ecdh = any(
        PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields
        for input_fields in input_maps
    )

    if not has_global_ecdh and not has_input_ecdh:
        return False, "Silent payment outputs present but no ECDH shares found"

    # Cannot have both global and per-input ECDH shares for same scan key
    if has_global_ecdh and has_input_ecdh:
        # Extract scan key from global ECDH share
        global_ecdh_field = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE]
        global_scan_key = global_ecdh_field["key"]

        # Check if any input has ECDH share for the same scan key
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                input_ecdh_field = input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE]
                input_scan_key = input_ecdh_field["key"]
                if input_scan_key == global_scan_key:
                    return (
                        False,
                        "Cannot have both global and per-input ECDH shares for same scan key",
                    )

    # DLEQ proofs must exist for ECDH shares
    if has_global_ecdh:
        has_global_dleq = PSBTFieldType.PSBT_GLOBAL_SP_DLEQ in global_fields
        if not has_global_dleq:
            return False, "Global ECDH share present but missing DLEQ proof"

    if has_input_ecdh:
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                if PSBTFieldType.PSBT_IN_SP_DLEQ not in input_fields:
                    return False, f"Input {i} has ECDH share but missing DLEQ proof"

    # Verify DLEQ proofs
    if has_global_ecdh:
        if not validate_global_dleq_proof(global_fields, input_maps):
            return False, "Global DLEQ proof verification failed"

    if has_input_ecdh:
        for i, input_fields in enumerate(input_maps):
            if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                if not validate_input_dleq_proof(input_fields, None, i):
                    return False, f"Input {i} DLEQ proof verification failed"

    # Segwit version restrictions
    for i, input_fields in enumerate(input_maps):
        if PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
            witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
            if check_invalid_segwit_version(witness_utxo):
                return False, f"Input {i} uses segwit version > 1 with silent payments"

    # Eligible input type requirement
    # When silent payment outputs exist, ALL inputs must be eligible types
    for i, input_fields in enumerate(input_maps):
        is_valid, error_msg = validate_input_eligibility(input_fields, i)
        if not is_valid:
            return False, error_msg

    # SIGHASH_ALL requirement
    for i, input_fields in enumerate(input_maps):
        if PSBTFieldType.PSBT_IN_SIGHASH_TYPE in input_fields:
            sighash = input_fields[PSBTFieldType.PSBT_IN_SIGHASH_TYPE]
            if len(sighash) >= 4:
                sighash_type = struct.unpack("<I", sighash[:4])[0]
                if sighash_type != 1:  # SIGHASH_ALL
                    return (
                        False,
                        f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments",
                    )

    return True, "Valid BIP 375 PSBT"
