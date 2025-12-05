#!/usr/bin/env python3
"""
BIP 375: Test Runner

Validates BIP 375 PSBT test vectors.
"""

import argparse
import base64
import json
import sys

from parser import parse_psbt_structure


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


def validate_basic_structure(psbt_b64: str) -> tuple[bool, str]:
    """Validate basic PSBT structure (magic bytes and parseability)"""
    try:
        # Decode PSBT
        psbt_data = base64.b64decode(psbt_b64)

        # Check magic bytes
        if len(psbt_data) < 5 or psbt_data[:5] != b"psbt\xff":
            return False, "Invalid PSBT magic"

        # Parse structure
        global_fields, input_maps, output_maps = parse_psbt_structure(psbt_data)

        return True, f"Valid structure: {len(input_maps)} inputs, {len(output_maps)} outputs"

    except Exception as e:
        return False, f"Parse error: {str(e)}"


def run_tests(test_data: dict, verbose: bool = False) -> None:
    """Run basic structure validation on all test cases"""

    print("BIP 375 Reference Implementation - Test Runner (Basic Validation)")
    print("=" * 70)
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

        is_valid, msg = validate_basic_structure(psbt_b64)

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

        is_valid, msg = validate_basic_structure(psbt_b64)

        if verbose:
            print(f"     Result: {msg}")

        if is_valid:
            passed += 1
        else:
            failed += 1
            print(f"     FAILED: {msg}")

        test_num += 1

    print(f"\n✓ Basic structure validation complete: {passed} passed, {failed} failed")
    print("Note: Full BIP 375 validation will be added in subsequent commits")


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
