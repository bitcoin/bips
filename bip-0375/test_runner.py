#!/usr/bin/env python3
"""
BIP 375: Test Runner

Validates BIP 375 PSBT test vectors.
"""

import argparse
import base64
import json
import os
import sys

from parser import parse_psbt_structure
from inputs import validate_input_eligibility, check_invalid_segwit_version
from constants import PSBTFieldType

# Add sibling directory bip-374 to path before to make secp256k1 and dleq reference available
current_dir = os.path.dirname(os.path.abspath(__file__))
sibling_dir_path = os.path.join(current_dir, '..', 'bip-0374')
if sibling_dir_path not in sys.path:
    sys.path.append(sibling_dir_path)
from dleq import validate_global_dleq_proof, validate_input_dleq_proof


def load_test_vectors(filename: str) -> dict:
    """Load test vectors from JSON file"""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Test vector file '{filename}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in test vector file: {e}")
        sys.exit(1)


def validate_structure_inputs_and_dleq(psbt_b64: str) -> tuple[bool, str]:
    """Validate PSBT structure, input eligibility, and DLEQ proofs"""
    try:
        # Decode PSBT
        psbt_data = base64.b64decode(psbt_b64)

        # Check magic bytes
        if len(psbt_data) < 5 or psbt_data[:5] != b"psbt\xff":
            return False, "Invalid PSBT magic"

        # Parse structure
        global_fields, input_maps, output_maps = parse_psbt_structure(psbt_data)

        # Check if this PSBT has silent payment outputs
        has_silent_outputs = any(
            PSBTFieldType.PSBT_OUT_SP_V0_INFO in output_fields
            or PSBTFieldType.PSBT_OUT_SP_V0_LABEL in output_fields
            for output_fields in output_maps
        )

        if not has_silent_outputs:
            return True, f"Valid PSBT v2 (no silent payments): {len(input_maps)} inputs, {len(output_maps)} outputs"

        # Validate input eligibility for silent payments
        for i, input_fields in enumerate(input_maps):
            is_valid, error_msg = validate_input_eligibility(input_fields, i)
            if not is_valid:
                return False, error_msg

            # Check segwit version restrictions
            if PSBTFieldType.PSBT_IN_WITNESS_UTXO in input_fields:
                witness_utxo = input_fields[PSBTFieldType.PSBT_IN_WITNESS_UTXO]
                if check_invalid_segwit_version(witness_utxo):
                    return False, f"Input {i} uses segwit version > 1 with silent payments"

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
                        return False, "Cannot have both global and per-input ECDH shares for same scan key"

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

        return True, f"Valid PSBT with DLEQ proofs: {len(input_maps)} inputs, {len(output_maps)} outputs"

    except Exception as e:
        return False, f"Validation error: {str(e)}"


def run_tests(test_data: dict, verbose: bool = False) -> None:
    """Run structure, input, and DLEQ validation on all test cases"""

    print("BIP 375 Reference Implementation - Test Runner (Structure + Input + DLEQ)")
    print("=" * 78)
    print(f"Description: {test_data['description']}")
    print(f"Version: {test_data['version']}")
    print(f"Invalid test cases: {len(test_data['invalid'])}")
    print(f"Valid test cases: {len(test_data['valid'])}")

    test_num = 1
    passed = 0
    failed = 0

    # Run invalid test cases
    print("\n=== Running Invalid Test Cases ===")
    for test_case in test_data["invalid"]:
        description = test_case["description"]
        psbt_b64 = test_case["psbt"]

        print(f"Test {test_num}: {description}")

        is_valid, msg = validate_structure_inputs_and_dleq(psbt_b64)

        if verbose:
            print(f"     Result: {msg}")

        # For invalid cases, we expect validation to reject them
        if not is_valid:
            passed += 1
        else:
            failed += 1
            print(f"     FAILED: Expected invalid but got: {msg}")

        test_num += 1

    # Run valid test cases
    print()
    print("=== Running Valid Test Cases ===")
    for test_case in test_data["valid"]:
        description = test_case["description"]
        psbt_b64 = test_case["psbt"]

        print(f"Test {test_num}: {description}")

        is_valid, msg = validate_structure_inputs_and_dleq(psbt_b64)

        if verbose:
            print(f"     Result: {msg}")

        if is_valid:
            passed += 1
        else:
            failed += 1
            print(f"     FAILED: {msg}")

        test_num += 1

    print(f"\n✓ Validation complete: {passed} passed, {failed} failed")
    print("Note: Full output script validation will be added in subsequent commits")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="BIP 375 Reference Implementation - Test Runner",
    )
    parser.add_argument(
        "--test-file",
        "-f",
        default="test_vectors.json",
        help="Test vector file to run (default: test_vectors.json)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output for each test",
    )

    args = parser.parse_args()

    # Load test vectors
    test_data = load_test_vectors(args.test_file)

    # Run tests
    run_tests(test_data, args.verbose)
