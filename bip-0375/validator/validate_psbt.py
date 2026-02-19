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
    return False, "ECDH coverage check not implemented yet"


def validate_input_eligibility(psbt: PSBT) -> Tuple[bool, str]:
    return False, "Input eligibility check not implemented yet"


def validate_output_scripts(psbt: PSBT) -> Tuple[bool, str]:
    return False, "Output scripts check not implemented yet"
