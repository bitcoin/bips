#!/usr/bin/env python3
"""BIP-0376 reference implementation and test vector runner.

Run:
    ./bip-0376/reference.py bip-0376/test-vectors.json
"""

import json
import sys
from pathlib import Path

BIP375_DIR = Path(__file__).resolve().parents[1] / "bip-0375"
DEPS_DIR = BIP375_DIR / "deps"
SECP256K1LAB_DIR = DEPS_DIR / "secp256k1lab/src"
for dependency_path in (BIP375_DIR, DEPS_DIR, SECP256K1LAB_DIR):
    sys.path.insert(0, str(dependency_path))

from secp256k1lab.bip340 import schnorr_sign
from secp256k1lab.secp256k1 import G, Scalar

from psbt_bip376 import (
    BIP376PSBT,
    PSBT_IN_SP_TWEAK,
    get_p2tr_witness_utxo_output_key,
    get_sp_tweak,
    set_tap_key_sig,
)


def parse_hex(data: str, expected_len: int, field_name: str) -> bytes:
    raw = bytes.fromhex(data)
    if len(raw) != expected_len:
        raise ValueError(f"{field_name} must be {expected_len} bytes.")
    return raw


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


def sign_psbt(psbt_data: str, spend_seckey: bytes, message: bytes, aux_rand: bytes) -> str:
    psbt = BIP376PSBT.from_base64(psbt_data)
    for input_map in psbt.i:
        if input_map.get(PSBT_IN_SP_TWEAK) is None:
            continue
        tweak = get_sp_tweak(input_map)
        output_pubkey = get_p2tr_witness_utxo_output_key(input_map)
        _, d, _ = derive_signing_key(spend_seckey, tweak, output_pubkey)
        set_tap_key_sig(input_map, schnorr_sign(message, d.to_bytes(), aux_rand))
    return psbt.to_base64()


def run_test_vectors(path: Path) -> bool:
    vectors = json.loads(path.read_text(encoding="utf-8"))
    all_passed = True

    valid_vectors = vectors.get("valid", [])
    invalid_vectors = vectors.get("invalid", [])

    print(f"Running {len(valid_vectors)} valid vectors")
    for index, vector in enumerate(valid_vectors):
        description = vector["description"]
        given = vector["given"]
        expected = vector["expected"]
        print(f"- valid[{index}] {description}")
        try:
            spend_seckey = parse_hex(given["spend_seckey"], 32, "spend_seckey")
            message = parse_hex(given["message"], 32, "message")
            aux_rand = parse_hex(given["aux_rand"], 32, "aux_rand")

            if "psbt" in given:
                signed_psbt = sign_psbt(given["psbt"], spend_seckey, message, aux_rand)
                assert signed_psbt == expected["psbt"]
            else:
                tweak = parse_hex(given["tweak"], 32, "tweak")
                output_pubkey = parse_hex(given["output_pubkey"], 32, "output_pubkey")
                _, d, _ = derive_signing_key(spend_seckey, tweak, output_pubkey)
                signature = schnorr_sign(message, d.to_bytes(), aux_rand)
                assert signature.hex() == expected["signature"]
        except Exception as exc:
            all_passed = False
            print(f"  FAILED: {exc}")

    print(f"Running {len(invalid_vectors)} invalid vectors")
    for index, vector in enumerate(invalid_vectors):
        description = vector["description"]
        given = vector["given"]
        print(f"- invalid[{index}] {description}")
        try:
            spend_seckey = parse_hex(given["spend_seckey"], 32, "spend_seckey")
            tweak = parse_hex(given["tweak"], 32, "tweak")
            output_pubkey = parse_hex(given["output_pubkey"], 32, "output_pubkey")
            derive_signing_key(spend_seckey, tweak, output_pubkey)
            all_passed = False
            print("  FAILED: expected an exception")
        except Exception:
            pass

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
