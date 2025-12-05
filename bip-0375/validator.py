#!/usr/bin/env python3
"""
BIP 375: PSBT Validator

Complete BIP 375 validation for PSBTs with silent payment outputs.
"""

import hashlib
import struct
from typing import Tuple, List, Dict, Optional

from constants import PSBTFieldType
from dleq import validate_global_dleq_proof, validate_input_dleq_proof
from inputs import validate_input_eligibility, check_invalid_segwit_version
from parser import parse_psbt_structure
# External references bip-0374
from secp256k1 import GE, G


def validate_bip375_psbt(
    psbt_data: bytes,
    input_keys: Optional[List[Dict]] = None,
) -> Tuple[bool, str]:
    """Validate a PSBT according to BIP 375 rules

    Args:
        psbt_data: Raw PSBT bytes
        input_keys: Optional list of input key material for BIP-352 validation
    """

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

    # Validate BIP-352 output scripts if test material provided
    if input_keys:
        is_valid, error_msg = validate_bip352_outputs(
            global_fields, input_maps, output_maps, input_keys
        )
        if not is_valid:
            return False, error_msg

    return True, "Valid BIP 375 PSBT"


def validate_bip352_outputs(
    global_fields: Dict,
    input_maps: List[Dict],
    output_maps: List[Dict],
    input_keys: List[Dict],
) -> Tuple[bool, str]:
    """Validate BIP-352 output script derivation (requires input_keys test material)"""

    # Build outpoints list from PSBT inputs
    outpoints = []
    for input_fields in input_maps:
        if PSBTFieldType.PSBT_IN_PREVIOUS_TXID in input_fields:
            txid = input_fields[PSBTFieldType.PSBT_IN_PREVIOUS_TXID]
            output_index_bytes = input_fields.get(PSBTFieldType.PSBT_IN_OUTPUT_INDEX)
            if output_index_bytes and len(output_index_bytes) == 4:
                output_index = struct.unpack("<I", output_index_bytes)[0]
                outpoints.append((txid, output_index))

    # Validate each silent payment output
    for output_idx, output_fields in enumerate(output_maps):
        # Only validate outputs with SP_V0_INFO (silent payment outputs)
        if PSBTFieldType.PSBT_OUT_SP_V0_INFO not in output_fields:
            continue

        sp_info = output_fields[PSBTFieldType.PSBT_OUT_SP_V0_INFO]
        if len(sp_info) != 66:
            continue

        scan_pubkey_bytes = sp_info[:33]
        spend_pubkey_bytes = sp_info[33:]

        # Find matching ECDH share for this scan key
        ecdh_share_bytes = None
        summed_pubkey_bytes = None

        # Check for global ECDH share
        if PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE in global_fields:
            global_ecdh = global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE]
            if (
                isinstance(global_ecdh, dict)
                and global_ecdh.get("key") == scan_pubkey_bytes
            ):
                ecdh_share_bytes = global_ecdh["value"]
                # Combine all input public keys
                summed_pubkey = None
                for input_key in input_keys:
                    pubkey_bytes = bytes.fromhex(input_key["public_key"])
                    pubkey = GE.from_bytes(pubkey_bytes)
                    summed_pubkey = (
                        pubkey if summed_pubkey is None else summed_pubkey + pubkey
                    )
                if summed_pubkey:
                    summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

        # Check for per-input ECDH shares (if no global share found)
        # BIP-375: When using per-input shares, sum all shares for the same scan key
        if not ecdh_share_bytes:
            summed_ecdh_share = None
            summed_pubkey = None

            for input_idx, input_fields in enumerate(input_maps):
                if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE in input_fields:
                    input_ecdh = input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE]
                    if (
                        isinstance(input_ecdh, dict)
                        and input_ecdh.get("key") == scan_pubkey_bytes
                    ):
                        # Add this ECDH share to the sum
                        ecdh_share_point = GE.from_bytes(input_ecdh["value"])
                        summed_ecdh_share = (
                            ecdh_share_point
                            if summed_ecdh_share is None
                            else summed_ecdh_share + ecdh_share_point
                        )

                        # Add this input's public key to the sum
                        if input_idx < len(input_keys):
                            pubkey_bytes = bytes.fromhex(input_keys[input_idx]["public_key"])
                            pubkey = GE.from_bytes(pubkey_bytes)
                            summed_pubkey = (
                                pubkey if summed_pubkey is None else summed_pubkey + pubkey
                            )

            if summed_ecdh_share and summed_pubkey:
                ecdh_share_bytes = summed_ecdh_share.to_bytes_compressed()
                summed_pubkey_bytes = summed_pubkey.to_bytes_compressed()

        # If we found ECDH share and summed pubkey, compute and verify output script
        if ecdh_share_bytes and summed_pubkey_bytes and outpoints:
            computed_script = compute_bip352_output_script(
                outpoints=outpoints,
                summed_pubkey_bytes=summed_pubkey_bytes,
                ecdh_share_bytes=ecdh_share_bytes,
                spend_pubkey_bytes=spend_pubkey_bytes,
                k=output_idx,  # Use output index for k parameter
            )

            # Compare with actual PSBT output script
            if PSBTFieldType.PSBT_OUT_SCRIPT in output_fields:
                actual_script = output_fields[PSBTFieldType.PSBT_OUT_SCRIPT]
                if actual_script != computed_script:
                    return (
                        False,
                        f"Output {output_idx} script doesn't match BIP-352 derivation",
                    )

    return True, "BIP-352 output validation passed"


def compute_bip352_output_script(
    outpoints: List[Tuple[bytes, int]],
    summed_pubkey_bytes: bytes,
    ecdh_share_bytes: bytes,
    spend_pubkey_bytes: bytes,
    k: int = 0,
) -> bytes:
    """Compute BIP-352 silent payment output script"""
    # Find smallest outpoint lexicographically
    serialized_outpoints = [txid + struct.pack("<I", idx) for txid, idx in outpoints]
    smallest_outpoint = min(serialized_outpoints)

    # Compute input_hash = hash_BIP0352/Inputs(smallest_outpoint || A)
    tag_data = b"BIP0352/Inputs"
    tag_hash = hashlib.sha256(tag_data).digest()
    input_hash_preimage = tag_hash + tag_hash + smallest_outpoint + summed_pubkey_bytes
    input_hash_bytes = hashlib.sha256(input_hash_preimage).digest()
    input_hash = int.from_bytes(input_hash_bytes, "big")

    # Compute shared_secret = input_hash * ecdh_share
    ecdh_point = GE.from_bytes(ecdh_share_bytes)
    shared_secret_point = input_hash * ecdh_point
    shared_secret_bytes = shared_secret_point.to_bytes_compressed()

    # Compute t_k = hash_BIP0352/SharedSecret(shared_secret || k)
    tag_data = b"BIP0352/SharedSecret"
    tag_hash = hashlib.sha256(tag_data).digest()
    t_preimage = tag_hash + tag_hash + shared_secret_bytes + k.to_bytes(4, "big")
    t_k_bytes = hashlib.sha256(t_preimage).digest()
    t_k = int.from_bytes(t_k_bytes, "big")

    # Compute P_k = B_spend + t_k * G
    B_spend = GE.from_bytes(spend_pubkey_bytes)
    P_k = B_spend + (t_k * G)

    # Create P2TR script (x-only pubkey)
    x_only = P_k.to_bytes_compressed()[1:]  # Remove parity byte
    return bytes([0x51, 0x20]) + x_only
