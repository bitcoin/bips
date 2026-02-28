#!/usr/bin/env python3
"""
BIP 375: DLEQ Proof Validation

Functions for validating DLEQ proofs on ECDH shares in PSBTs.
"""

from typing import Dict, List, Optional, Tuple

from constants import PSBTFieldType
# External references bip-0374
from reference import dleq_verify_proof
from secp256k1 import GE


def extract_dleq_components(
    dleq_field: Dict, ecdh_field: Dict
) -> Tuple[bytes, bytes, bytes]:
    """Extract and validate DLEQ proof components from PSBT fields"""

    # Extract key and value components
    proof = dleq_field["value"]
    dleq_scan_key_bytes = dleq_field["key"]
    ecdh_share_bytes = ecdh_field["value"]
    ecdh_scan_key_bytes = ecdh_field["key"]

    # Validate proof length
    if len(proof) != 64:
        raise ValueError(f"Invalid DLEQ proof length: {len(proof)} bytes (expected 64)")

    # Validate BIP 375 key-value structure
    if len(ecdh_scan_key_bytes) != 33:
        raise ValueError(
            f"Invalid ECDH scan key length: {len(ecdh_scan_key_bytes)} bytes (expected 33)"
        )
    if len(ecdh_share_bytes) != 33:
        raise ValueError(
            f"Invalid ECDH share length: {len(ecdh_share_bytes)} bytes (expected 33)"
        )
    if len(dleq_scan_key_bytes) != 33:
        raise ValueError(
            f"Invalid DLEQ scan key length: {len(dleq_scan_key_bytes)} bytes (expected 33)"
        )

    # Verify scan keys match between ECDH and DLEQ fields
    if ecdh_scan_key_bytes != dleq_scan_key_bytes:
        raise ValueError("Scan key mismatch between ECDH and DLEQ fields")

    return proof, ecdh_scan_key_bytes, ecdh_share_bytes


def get_pubkey_from_input(input_fields: Dict[int, bytes]) -> Optional[GE]:
    """Extract public key from PSBT input fields"""
    # Try BIP32 derivation field (highest priority, BIP-174 standard)
    if PSBTFieldType.PSBT_IN_BIP32_DERIVATION in input_fields:
        derivation_data = input_fields[PSBTFieldType.PSBT_IN_BIP32_DERIVATION]
        if isinstance(derivation_data, dict):
            pubkey_candidate = derivation_data.get("key", b"")
            if len(pubkey_candidate) == 33:
                return GE.from_bytes(pubkey_candidate)

    return None


def validate_global_dleq_proof(
    global_fields: Dict[int, bytes],
    input_maps: List[Dict[int, bytes]] = None,
    input_keys: List[Dict] = None,
) -> bool:
    """Validate global DLEQ proof using BIP 374 implementation"""

    if PSBTFieldType.PSBT_GLOBAL_SP_DLEQ not in global_fields:
        return False
    if PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE not in global_fields:
        return False

    # Extract and validate components
    try:
        proof, scan_key_bytes, ecdh_share_bytes = extract_dleq_components(
            global_fields[PSBTFieldType.PSBT_GLOBAL_SP_DLEQ],
            global_fields[PSBTFieldType.PSBT_GLOBAL_SP_ECDH_SHARE],
        )
    except ValueError:
        return False

    # Convert to GE points
    B = GE.from_bytes(scan_key_bytes)  # scan key
    C = GE.from_bytes(ecdh_share_bytes)  # ECDH result

    # For global ECDH shares, we need to combine all input public keys
    # According to BIP 375: "Let A_n be the sum of the public keys A of all eligible inputs"
    A_combined = None

    # Extract and combine public keys from PSBT fields (preferred, BIP-174 standard)
    for input_fields in input_maps:
        input_pubkey = get_pubkey_from_input(input_fields)

        if input_pubkey is not None:
            if A_combined is None:
                A_combined = input_pubkey
            else:
                A_combined = A_combined + input_pubkey

    if A_combined is None:
        return False

    return dleq_verify_proof(A_combined, B, C, proof)


def validate_input_dleq_proof(
    input_fields: Dict[int, bytes],
    input_keys: List[Dict] = None,
    input_index: int = None,
) -> bool:
    """Validate input DLEQ proof using BIP 374 implementation"""

    if PSBTFieldType.PSBT_IN_SP_DLEQ not in input_fields:
        return False
    if PSBTFieldType.PSBT_IN_SP_ECDH_SHARE not in input_fields:
        return False

    # Extract and validate components
    try:
        proof, scan_key_bytes, ecdh_share_bytes = extract_dleq_components(
            input_fields[PSBTFieldType.PSBT_IN_SP_DLEQ],
            input_fields[PSBTFieldType.PSBT_IN_SP_ECDH_SHARE],
        )
    except ValueError:
        return False

    # Convert to GE points
    B = GE.from_bytes(scan_key_bytes)  # scan key
    C = GE.from_bytes(ecdh_share_bytes)  # ECDH result

    # Extract input public key A from available sources
    A = get_pubkey_from_input(input_fields)

    if A is None:
        return False

    # Perform DLEQ verification
    return dleq_verify_proof(A, B, C, proof)
