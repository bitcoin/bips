#!/usr/bin/env python3
"""
Validates PSBTs according to BIP-375 rules

Provides independent checks for PSBT structure, ECDH share coverage,
input eligibility, and output script correctness.
"""

from typing import Tuple

from deps.bitcoin_test.psbt import (
    PSBT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_OUT_SCRIPT,
)
from deps.dleq import dleq_verify_proof
from secp256k1lab.secp256k1 import GE

from .inputs import is_input_eligible, pubkey_from_eligible_input
from .psbt_bip375 import (
    PSBT_GLOBAL_SP_ECDH_SHARE,
    PSBT_GLOBAL_SP_DLEQ,
    PSBT_IN_SP_ECDH_SHARE,
    PSBT_IN_SP_DLEQ,
    PSBT_OUT_SP_V0_INFO,
    PSBT_OUT_SP_V0_LABEL,
)


def validate_psbt_structure(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate PSBT structure requirements

    Checks:
    - Each output must have PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO
    - PSBT_OUT_SP_V0_LABEL requires PSBT_OUT_SP_V0_INFO
    - SP_V0_INFO must be 66 bytes (33-byte scan key + 33-byte spend key)
    - ECDH shares must be 33 bytes
    - DLEQ proofs must be 64 bytes
    - TX_MODIFIABLE is zero when PSBT_OUT_SCRIPT set for SP output
    """
    # Check output requirements
    for i, output_map in enumerate(psbt.o):
        has_script = (
            PSBT_OUT_SCRIPT in output_map and len(output_map[PSBT_OUT_SCRIPT]) > 0
        )
        has_sp_info = PSBT_OUT_SP_V0_INFO in output_map
        has_sp_label = PSBT_OUT_SP_V0_LABEL in output_map

        # Output must have script or SP info
        if not has_script and not has_sp_info:
            return (
                False,
                f"Output {i} must have either PSBT_OUT_SCRIPT or PSBT_OUT_SP_V0_INFO",
            )

        # SP label requires SP info
        if has_sp_label and not has_sp_info:
            return (
                False,
                f"Output {i} has PSBT_OUT_SP_V0_LABEL but missing PSBT_OUT_SP_V0_INFO",
            )

        # Validate SP_V0_INFO field length
        if has_sp_info:
            sp_info = output_map[PSBT_OUT_SP_V0_INFO]
            if len(sp_info) != 66:
                return (
                    False,
                    f"Output {i} SP_V0_INFO has wrong length ({len(sp_info)} bytes, expected 66)",
                )

    # Validate ECDH share lengths (global and per-input)
    global_ecdh_shares = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_ECDH_SHARE)
    for _, ecdh_share in global_ecdh_shares:
        if len(ecdh_share) != 33:
            return (
                False,
                f"Global ECDH share has wrong length ({len(ecdh_share)} bytes, expected 33)",
            )

    for i, input_map in enumerate(psbt.i):
        input_ecdh_shares = input_map.get_all_by_type(PSBT_IN_SP_ECDH_SHARE)
        for _, ecdh_share in input_ecdh_shares:
            if len(ecdh_share) != 33:
                return (
                    False,
                    f"Input {i} ECDH share has wrong length ({len(ecdh_share)} bytes, expected 33)",
                )

    # Validate DLEQ proof lengths (global and per-input)
    global_dleq_proofs = psbt.g.get_all_by_type(PSBT_GLOBAL_SP_DLEQ)
    for _, dleq_proof in global_dleq_proofs:
        if len(dleq_proof) != 64:
            return (
                False,
                f"Global DLEQ proof has wrong length ({len(dleq_proof)} bytes, expected 64)",
            )

    for i, input_map in enumerate(psbt.i):
        input_dleq_proofs = input_map.get_all_by_type(PSBT_IN_SP_DLEQ)
        for _, dleq_proof in input_dleq_proofs:
            if len(dleq_proof) != 64:
                return (
                    False,
                    f"Input {i} DLEQ proof has wrong length ({len(dleq_proof)} bytes, expected 64)",
                )

    # Check TX_MODIFIABLE flag when PSBT_OUT_SCRIPT is set
    for output_map in psbt.o:
        if PSBT_OUT_SP_V0_INFO in output_map and PSBT_OUT_SCRIPT in output_map:
            if len(output_map.get(PSBT_OUT_SCRIPT, b"")) > 0:
                if psbt.g.get(PSBT_GLOBAL_TX_MODIFIABLE) != b"\x00":
                    return (
                        False,
                        "PSBT_OUT_SCRIPT set for silent payments output but PSBT_GLOBAL_TX_MODIFIABLE not zeroed",
                    )
    return True, None


def validate_ecdh_coverage(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate ECDH share coverage and DLEQ proof correctness

    Checks:
    - Verify ECDH share coverage for each scan key associated with SP outputs
    - Every ECDH share must have a corresponding DLEQ proof
    - If PSBT_OUT_SCRIPT is set, all eligible inputs must have ECDH coverage
    - DLEQ proofs must verify correctly
    """
    # Collect unique scan keys from SP outputs
    scan_keys = set()
    for output_map in psbt.o:
        if PSBT_OUT_SP_V0_INFO in output_map:
            sp_info = output_map[PSBT_OUT_SP_V0_INFO]
            scan_keys.add(sp_info[:33])

    if not scan_keys:
        return True, None  # No SP outputs, nothing to check

    # For each scan key, verify ECDH share coverage and DLEQ proofs
    for scan_key in scan_keys:
        has_global_ecdh = psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key)
        has_input_ecdh = any(
            input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
            for input_map in psbt.i
        )

        scan_key_has_computed_output = any(
            PSBT_OUT_SP_V0_INFO in om
            and om[PSBT_OUT_SP_V0_INFO][:33] == scan_key
            and PSBT_OUT_SCRIPT in om
            for om in psbt.o
        )
        if scan_key_has_computed_output and not has_global_ecdh and not has_input_ecdh:
            return False, "Silent payment output present but no ECDH share for scan key"

        # Verify global DLEQ proof if global ECDH present
        if has_global_ecdh:
            ecdh_share = psbt.g.get_by_key(PSBT_GLOBAL_SP_ECDH_SHARE, scan_key)
            dleq_proof = psbt.g.get_by_key(PSBT_GLOBAL_SP_DLEQ, scan_key)
            if not dleq_proof:
                return False, "Global ECDH share missing DLEQ proof"

            # Compute A_sum "input public keys" for global verification
            A_sum = None
            for input_map in psbt.i:
                pubkey = pubkey_from_eligible_input(input_map)
                if pubkey is not None:
                    A_sum = pubkey if A_sum is None else A_sum + pubkey
            assert A_sum is not None, "No public keys found for inputs"

            valid, msg = validate_dleq_proof(A_sum, scan_key, ecdh_share, dleq_proof)
            if not valid:
                return False, f"Global DLEQ proof invalid: {msg}"

        # Verify per-input coverage for eligible inputs
        if scan_key_has_computed_output and not has_global_ecdh:
            for i, input_map in enumerate(psbt.i):
                is_eligible, _ = is_input_eligible(input_map)
                ecdh_share = input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
                if not is_eligible and ecdh_share:
                    return (
                        False,
                        f"Input {i} has ECDH share but is ineligible for silent payments",
                    )
                if is_eligible and not ecdh_share:
                    return (
                        False,
                        f"Output script set but eligible input {i} missing ECDH share",
                    )
                if ecdh_share:
                    # Verify per-input DLEQ proofs
                    dleq_proof = input_map.get_by_key(PSBT_IN_SP_DLEQ, scan_key)
                    if not dleq_proof:
                        return False, f"Input {i} ECDH share missing DLEQ proof"

                    # Get input public key A
                    A = pubkey_from_eligible_input(input_map)
                    if A is None:
                        return (
                            False,
                            f"Input {i} missing public key for DLEQ verification",
                        )

                    valid, msg = validate_dleq_proof(
                        A, scan_key, ecdh_share, dleq_proof
                    )
                    if not valid:
                        return False, f"Input {i} DLEQ proof invalid: {msg}"
    return True, None


def validate_dleq_proof(
    A: GE,
    scan_key: bytes,
    ecdh_share: bytes,
    dleq_proof: bytes,
) -> Tuple[bool, str]:
    """
    Verify a DLEQ proof for silent payments
    
    Checks:
    - ECDH share and DLEQ proof lengths
    - Verify DLEQ proof correctness
    """
    if len(ecdh_share) != 33:
        return (
            False,
            f"Invalid ECDH share length: {len(ecdh_share)} bytes (expected 33)",
        )

    if len(dleq_proof) != 64:
        return (
            False,
            f"Invalid DLEQ proof length: {len(dleq_proof)} bytes (expected 64)",
        )

    B_scan = GE.from_bytes(scan_key)
    C_ecdh = GE.from_bytes(ecdh_share)

    # Verify DLEQ proof using BIP-374 reference
    result = dleq_verify_proof(A, B_scan, C_ecdh, dleq_proof)
    if not result:
        return False, "DLEQ proof verification failed"
    return True, None


def validate_input_eligibility(psbt: PSBT) -> Tuple[bool, str]:
    return False, "Input eligibility check not implemented yet"


def validate_output_scripts(psbt: PSBT) -> Tuple[bool, str]:
    return False, "Output scripts check not implemented yet"
