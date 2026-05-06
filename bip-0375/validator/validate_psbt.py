#!/usr/bin/env python3
"""
Validates PSBTs according to BIP-375 rules

Provides independent checks for PSBT structure, ECDH share coverage,
input eligibility, and output script correctness.
"""

import struct
from typing import Tuple

from deps.bitcoin_test.messages import COutPoint
from deps.bitcoin_test.psbt import (
    PSBT,
    PSBT_GLOBAL_TX_MODIFIABLE,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_WITNESS_UTXO,
    PSBT_OUT_SCRIPT,
)
from deps.dleq import dleq_verify_proof
from secp256k1lab.secp256k1 import GE

from .bip352_crypto import compute_silent_payment_output_script
from .inputs import (
    collect_input_ecdh_and_pubkey,
    is_input_eligible,
    parse_witness_utxo,
    pubkey_from_eligible_input,
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

            _, summed_pubkey_bytes = collect_input_ecdh_and_pubkey(psbt, scan_key)
            assert summed_pubkey_bytes is not None, "No public keys found for inputs"
            A_sum = GE.from_bytes(summed_pubkey_bytes)

            valid, msg = validate_dleq_proof(A_sum, scan_key, ecdh_share, dleq_proof)
            if not valid:
                return False, f"Global DLEQ proof invalid: {msg}"

        # Verify per-input coverage for eligible inputs
        if scan_key_has_computed_output and not has_global_ecdh:
            for i, input_map in enumerate(psbt.i):
                if not is_input_eligible(input_map):
                    continue
                ecdh_share = input_map.get_by_key(PSBT_IN_SP_ECDH_SHARE, scan_key)
                if not ecdh_share:
                    return (
                        False,
                        f"Output script set but eligible input {i} missing ECDH share",
                    )
                else:
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
    """
    Validate input eligibility constraints for silent payments

    Checks:
    - No segwit v>1 inputs when SP outputs present
    - SIGHASH_ALL required when SP outputs present
    """
    # Check if SP outputs exist
    has_sp_outputs = any(PSBT_OUT_SP_V0_INFO in om for om in psbt.o)
    if not has_sp_outputs:
        return True, None

    # Check segwit version restrictions
    for i, input_map in enumerate(psbt.i):
        if PSBT_IN_WITNESS_UTXO in input_map:
            witness_utxo = input_map[PSBT_IN_WITNESS_UTXO]
            script = parse_witness_utxo(witness_utxo)
            if script and 0x51 < script[0] <= 0x60:  # OP_2 or higher (segwit v2+)
                return False, f"Input {i} uses segwit version > 1 with silent payments"

    # Check SIGHASH_ALL requirement - PSBT_IN_SIGHASH_TYPE is optional, but if set it must be SIGHASH_ALL when SP outputs are present
    for i, input_map in enumerate(psbt.i):
        if PSBT_IN_SIGHASH_TYPE in input_map:
            sighash = input_map[PSBT_IN_SIGHASH_TYPE]
            if len(sighash) >= 4:
                sighash_type = struct.unpack("<I", sighash[:4])[0]
                if sighash_type != 1:  # SIGHASH_ALL
                    return (
                        False,
                        f"Input {i} uses non-SIGHASH_ALL ({sighash_type}) with silent payments",
                    )
    return True, None


def validate_output_scripts(psbt: PSBT) -> Tuple[bool, str]:
    """
    Validate computed output scripts match silent payment derivation

    Checks:
    - For each SP output with PSBT_OUT_SCRIPT set, recomputes the expected P2TR
      script from the ECDH share and input public keys and verifies it matches
    - k values are tracked per scan key and incremented for each SP output sharing
      the same scan key (outputs with different scan keys use independent k counters)
    """
    # Build outpoints list
    outpoints = []
    for input_map in psbt.i:
        if PSBT_IN_PREVIOUS_TXID in input_map and PSBT_IN_OUTPUT_INDEX in input_map:
            output_index_bytes = input_map.get(PSBT_IN_OUTPUT_INDEX)
            txid_int = int.from_bytes(input_map[PSBT_IN_PREVIOUS_TXID], "little")
            output_index = struct.unpack("<I", output_index_bytes)[0]
            outpoints.append(COutPoint(txid_int, output_index))

    # Track k values per scan key
    scan_key_k_values = {}

    # Validate each SP output
    for output_idx, output_map in enumerate(psbt.o):
        if PSBT_OUT_SP_V0_INFO not in output_map:
            continue  # Skip non-SP outputs

        sp_info = output_map[PSBT_OUT_SP_V0_INFO]
        scan_pubkey_bytes = sp_info[:33]
        spend_pubkey_bytes = sp_info[33:]

        k = scan_key_k_values.get(scan_pubkey_bytes, 0)

        # Get ECDH share and summed pubkey
        ecdh_share_bytes, summed_pubkey_bytes = collect_input_ecdh_and_pubkey(
            psbt, scan_pubkey_bytes
        )

        if ecdh_share_bytes and summed_pubkey_bytes and outpoints:
            computed_script = compute_silent_payment_output_script(
                outpoints, summed_pubkey_bytes, ecdh_share_bytes, spend_pubkey_bytes, k
            )

            if PSBT_OUT_SCRIPT in output_map:
                actual_script = output_map[PSBT_OUT_SCRIPT]
                if actual_script != computed_script:
                    return (
                        False,
                        f"Output {output_idx} script doesn't match silent payments derivation",
                    )

            scan_key_k_values[scan_pubkey_bytes] = k + 1
        elif PSBT_OUT_SCRIPT in output_map:
            return (
                False,
                f"Output {output_idx} has PSBT_OUT_SCRIPT but missing ECDH share or input pubkeys",
            )
    return True, None
