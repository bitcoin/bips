#!/usr/bin/env python3
"""Process test vectors JSON file and run validation checks"""

import argparse
import json
from pathlib import Path
import sys
from typing import Tuple

project_root = Path(__file__).parent
deps_dir = project_root / "deps"
secp256k1lab_dir = deps_dir / "secp256k1lab" / "src"
for path in [str(deps_dir), str(secp256k1lab_dir)]:
    if path not in sys.path:
        sys.path.insert(0, path)

from validator.psbt_bip375 import BIP375PSBT
from validator.validate_psbt import (
    validate_psbt_structure,
    validate_ecdh_coverage,
    validate_input_eligibility,
    validate_output_scripts,
)

CHECK_FUNCTIONS = {
    "psbt_structure": validate_psbt_structure,
    "ecdh_coverage": validate_ecdh_coverage,
    "input_eligibility": validate_input_eligibility,
    "output_scripts": validate_output_scripts,
}


def validate_bip375_psbt(
    psbt_data: str, checks: list[str], debug: bool = False
) -> Tuple[bool, str]:
    """Performs sequential validation of a PSBT against BIP-375 rules"""
    psbt = BIP375PSBT.from_base64(psbt_data)

    if checks is None:
        checks = [
            "psbt_structure",
            "ecdh_coverage",
            "input_eligibility",
            "output_scripts",
        ]

    for check_name in checks:
        if check_name not in CHECK_FUNCTIONS:
            return False, f"Unknown check: {check_name}"

        check_fn = CHECK_FUNCTIONS[check_name]

        is_valid, msg = check_fn(psbt)
        if debug:
            msg = f"{check_name.upper()}: {msg}" if msg else msg

        if not is_valid:
            return False, msg

    return True, "All checks passed"


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


def run_validation_tests(test_data: dict, verbosity: int = 0) -> tuple[int, int]:
    """Run validation checks for each test vector"""
    passed = 0
    failed = 0

    # Process invalid PSBTs (should fail validation)
    invalid_tests = test_data.get("invalid", [])
    print(f"Invalid PSBTs: {len(invalid_tests)}")
    for test_vector in invalid_tests:
        is_valid, result = validate_bip375_psbt(
            test_vector["psbt"], test_vector.get("checks"), debug=verbosity >= 2
        )
        print(f"{test_vector['description']}")
        if not is_valid:
            passed += 1
            if verbosity >= 1:
                print(f"  {result}")
        else:
            failed += 1
            if result:
                print(f"  ERROR: {result}")

    # Process valid PSBTs (should pass validation)
    valid_tests = test_data.get("valid", [])
    print("")
    print(f"Valid PSBTs: {len(valid_tests)}")
    for test_vector in valid_tests:
        is_valid, result = validate_bip375_psbt(
            test_vector["psbt"], test_vector.get("checks"), debug=verbosity >= 2
        )

        print(f"{test_vector['description']}")
        if is_valid:
            passed += 1
            if verbosity >= 1:
                print(f"  {result}")
        else:
            failed += 1
            if result:
                print(f"  ERROR: {result}")

    return passed, failed


def main():
    parser = argparse.ArgumentParser(
        description="Silent Payments PSBT Validator",
    )
    parser.add_argument(
        "--test-file",
        "-f",
        default=str(project_root / "bip375_test_vectors.json"),
        help="Test vector file to run (default: bip375_test_vectors.json)",
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        action="count",
        default=0,
        help="Verbosity level: -v shows pass/fail details, -vv enables debug output",
    )

    args = parser.parse_args()

    test_data = load_test_vectors(args.test_file)

    print(f"Description: {test_data.get('description', 'N/A')}")
    print(f"Version: {test_data.get('version', 'N/A')}")
    print()

    passed, failed = run_validation_tests(test_data, args.verbosity)

    print()
    print(f"Summary: {passed} passed, {failed} failed")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
