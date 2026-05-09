#!/usr/bin/env python3
"""BIP-0376 reference implementation and test vector runner.

Run:
    ./bip-0376/reference.py bip-0376/test-vectors.json
"""

import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
DEPS_DIR = PROJECT_DIR / "deps"
SECP256K1LAB_DIR = DEPS_DIR / "secp256k1lab/src"
for dependency_path in (PROJECT_DIR, DEPS_DIR, SECP256K1LAB_DIR):
    sys.path.insert(0, str(dependency_path))

from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.secp256k1 import G, Scalar

from deps.bitcoin_test.messages import ser_string_vector
from deps.bitcoin_test.psbt import (
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_TAP_KEY_SIG,
)
from psbt_bip376 import (
    BIP376PSBT,
    PSBT_IN_SP_SPEND_BIP32_DERIVATION,
    PSBT_IN_SP_TWEAK,
    get_p2tr_witness_utxo_output_key,
    get_sp_tweak,
    remove_sp_finalized_fields,
    set_tap_key_sig,
)


def parse_hex(data: str, expected_len: int, field_name: str) -> bytes:
    raw = bytes.fromhex(data)
    if len(raw) != expected_len:
        raise ValueError(f"{field_name} must be {expected_len} bytes.")
    return raw


def load_psbt(psbt_data: dict) -> BIP376PSBT:
    if "hex" in psbt_data:
        return BIP376PSBT.from_hex(psbt_data["hex"])
    if "base64" in psbt_data:
        return BIP376PSBT.from_base64(psbt_data["base64"])
    raise ValueError("psbt must contain hex or base64")


def encode_psbt(psbt: BIP376PSBT) -> dict:
    return {
        "hex": psbt.to_hex(),
        "base64": psbt.to_base64(),
    }


def derive_signing_key(
    spend_seckey: bytes, tweak: bytes, output_pubkey: bytes
) -> tuple[Scalar, Scalar, bool]:
    try:
        b_spend = Scalar.from_bytes_checked(spend_seckey)
    except ValueError as exc:
        raise ValueError("spend key out of range") from exc
    if b_spend == 0:
        raise ValueError("spend key out of range")

    d_raw = b_spend + Scalar.from_bytes_wrapping(tweak)
    if d_raw == 0:
        raise ValueError("tweaked private key is zero")

    Q = d_raw * G
    assert not Q.infinity
    negated = not Q.has_even_y()
    d = d_raw if not negated else -d_raw

    Q_even = d * G
    assert not Q_even.infinity
    if Q_even.to_bytes_xonly() != output_pubkey:
        raise ValueError("tweaked key does not match output key")

    return d_raw, d, negated


def update_psbt(psbt_data: dict, supplementary: dict) -> dict:
    psbt = load_psbt(psbt_data)
    input_index = supplementary.get("input_index", 0)
    input_map = psbt.i[input_index]
    tweak = parse_hex(supplementary["tweak"], 32, "tweak")

    if "spend_pubkey" in supplementary:
        spend_pubkey = parse_hex(supplementary["spend_pubkey"], 33, "spend_pubkey")
        derivation = bytes.fromhex(
            supplementary.get("spend_bip32_derivation", "00000000")
        )
        if len(derivation) < 4 or len(derivation) % 4 != 0:
            raise ValueError(
                "spend_bip32_derivation must be fingerprint plus path elements"
            )
        input_map.set_by_key(
            PSBT_IN_SP_SPEND_BIP32_DERIVATION, derivation, spend_pubkey
        )
    input_map.set_by_key(PSBT_IN_SP_TWEAK, tweak)

    return encode_psbt(psbt)


def sign_psbt(psbt_data: dict, spend_seckey: bytes, message: bytes, aux_rand: bytes) -> dict:
    psbt = load_psbt(psbt_data)
    for input_map in psbt.i:
        if input_map.get(PSBT_IN_SP_TWEAK) is None:
            continue
        tweak = get_sp_tweak(input_map)
        output_pubkey = get_p2tr_witness_utxo_output_key(input_map)
        _, d, _ = derive_signing_key(spend_seckey, tweak, output_pubkey)
        set_tap_key_sig(input_map, schnorr_sign(message, d.to_bytes(), aux_rand))
    return encode_psbt(psbt)


def finalize_psbt(psbt_data: dict, message: bytes) -> dict:
    psbt = load_psbt(psbt_data)
    for input_map in psbt.i:
        if input_map.get(PSBT_IN_SP_TWEAK) is None:
            continue
        signature = input_map.get(PSBT_IN_TAP_KEY_SIG)
        if signature is None:
            raise ValueError("missing PSBT_IN_TAP_KEY_SIG")

        output_pubkey = get_p2tr_witness_utxo_output_key(input_map)
        if not schnorr_verify(message, output_pubkey, signature[:64]):
            raise ValueError("invalid PSBT_IN_TAP_KEY_SIG")

        if input_map.get(PSBT_IN_FINAL_SCRIPTWITNESS) is None:
            input_map.set_by_key(
                PSBT_IN_FINAL_SCRIPTWITNESS, ser_string_vector([signature])
            )
        remove_sp_finalized_fields(input_map)
    return encode_psbt(psbt)


def run_case(case: dict) -> dict:
    supplementary = case.get("supplementary", {})
    task = supplementary["task"]
    psbt_data = case["psbt"]

    if task == "update":
        return update_psbt(psbt_data, supplementary)

    if task in ("sign", "fail_sign"):
        spend_seckey = parse_hex(supplementary["spend_seckey"], 32, "spend_seckey")
        message = parse_hex(supplementary["message"], 32, "message")
        aux_rand = parse_hex(supplementary["aux_rand"], 32, "aux_rand")
        return sign_psbt(psbt_data, spend_seckey, message, aux_rand)

    if task in ("finalize", "fail"):
        message = parse_hex(supplementary["message"], 32, "message")
        return finalize_psbt(psbt_data, message)

    raise ValueError(f"unknown task: {task}")


def run_test_vectors(path: Path) -> bool:
    vectors = json.loads(path.read_text(encoding="utf-8"))
    all_passed = True

    cases = vectors.get("cases", [])
    print(f"Description: {vectors.get('description', 'N/A')}")
    print(f"Version: {vectors.get('version', 'N/A')}")
    print(f"Running {len(cases)} cases")
    for index, case in enumerate(cases):
        description = case["description"]
        task = case.get("supplementary", {})["task"]
        print(f"- cases[{index}] {description}")
        try:
            result = run_case(case)
            if task in ("fail", "fail_sign"):
                all_passed = False
                print("  FAILED: expected an exception")
                continue
            expected = case["expected"]["psbt"]
            if result != expected:
                all_passed = False
                print("  FAILED: PSBT mismatch")
        except Exception as exc:
            if task in ("fail", "fail_sign"):
                continue
            all_passed = False
            print(f"  FAILED: {exc}")

    print("All test vectors passed." if all_passed else "Some test vectors failed.")
    return all_passed


def main() -> int:
    if len(sys.argv) > 2:
        print(f"Usage: {sys.argv[0]} [test-vectors.json]")
        return 1

    if len(sys.argv) == 2:
        vector_path = Path(sys.argv[1])
    else:
        vector_path = Path(__file__).with_name("test-vectors.json")

    if not vector_path.is_file():
        print(f"Vector file not found: {vector_path}")
        return 1

    return 0 if run_test_vectors(vector_path) else 1


if __name__ == "__main__":
    raise SystemExit(main())
