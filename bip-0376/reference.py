#!/usr/bin/env python3
"""BIP-0376 reference implementation and test vector runner.

Run:
    ./bip-0376/reference.py bip-0376/test-vectors.json
"""

import json
import sys
import hashlib
from pathlib import Path
from typing import Optional, Tuple

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = Tuple[int, int]


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def int_from_bytes(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")


def has_even_y(P: Point) -> bool:
    return (P[1] % 2) == 0


def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(P[0])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(a, b))


def lift_x(x_coord: int) -> Optional[Point]:
    if x_coord >= p:
        return None
    y_sq = (pow(x_coord, 3, p) + 7) % p
    y_coord = pow(y_sq, (p + 1) // 4, p)
    if pow(y_coord, 2, p) != y_sq:
        return None
    return (x_coord, y_coord if (y_coord % 2) == 0 else p - y_coord)


def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (P1[0] == P2[0]) and (P1[1] != P2[1]):
        return None
    if P1 == P2:
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    x3 = (lam * lam - P1[0] - P2[0]) % p
    y3 = (lam * (P1[0] - x3) - P1[1]) % p
    return (x3, y3)


def point_mul(P: Optional[Point], scalar: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (scalar >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    P = lift_x(int_from_bytes(pubkey))
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if P is None or r >= p or s >= n:
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if R is None:
        return False
    return has_even_y(R) and (R[0] == r)


def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError("The secret key must be in the range 1..n-1.")
    if len(aux_rand) != 32:
        raise ValueError("aux_rand must be 32 bytes.")
    P = point_mul(G, d0)
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n
    if k0 == 0:
        raise RuntimeError("Failure. This happens only with negligible probability.")
    R = point_mul(G, k0)
    assert R is not None
    k = k0 if has_even_y(R) else n - k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError("The created signature does not pass verification.")
    return sig


def parse_hex(data: str, expected_len: int, field_name: str) -> bytes:
    raw = bytes.fromhex(data)
    if len(raw) != expected_len:
        raise ValueError(f"{field_name} must be {expected_len} bytes.")
    return raw


def derive_signing_key(spend_seckey: bytes, tweak: bytes, output_pubkey: bytes) -> Tuple[int, int, bool]:
    b_spend = int_from_bytes(spend_seckey)
    if not (1 <= b_spend <= n - 1):
        raise ValueError("spend key out of range")

    tweak_int = int_from_bytes(tweak)
    d_raw = (b_spend + tweak_int) % n
    if d_raw == 0:
        raise ValueError("tweaked private key is zero")

    Q = point_mul(G, d_raw)
    assert Q is not None
    negated = not has_even_y(Q)
    d = d_raw if not negated else n - d_raw

    Q_even = point_mul(G, d)
    assert Q_even is not None
    if bytes_from_point(Q_even) != output_pubkey:
        raise ValueError("tweaked key does not match output key")

    return d_raw, d, negated


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
            tweak = parse_hex(given["tweak"], 32, "tweak")
            output_pubkey = parse_hex(given["output_pubkey"], 32, "output_pubkey")
            message = parse_hex(given["message"], 32, "message")
            aux_rand = parse_hex(given["aux_rand"], 32, "aux_rand")

            d_raw, d, negated = derive_signing_key(spend_seckey, tweak, output_pubkey)
            signature = schnorr_sign(message, bytes_from_int(d), aux_rand)

            assert bytes_from_int(d_raw).hex() == expected["raw_tweaked_seckey"]
            assert negated == expected["negated"]
            assert bytes_from_int(d).hex() == expected["final_seckey"]
            assert signature.hex() == expected["signature"]
        except Exception as exc:
            all_passed = False
            print(f"  FAILED: {exc}")

    print(f"Running {len(invalid_vectors)} invalid vectors")
    for index, vector in enumerate(invalid_vectors):
        description = vector["description"]
        given = vector["given"]
        error_substr = vector["error_substr"]
        print(f"- invalid[{index}] {description}")
        try:
            spend_seckey = parse_hex(given["spend_seckey"], 32, "spend_seckey")
            tweak = parse_hex(given["tweak"], 32, "tweak")
            output_pubkey = parse_hex(given["output_pubkey"], 32, "output_pubkey")
            derive_signing_key(spend_seckey, tweak, output_pubkey)
            all_passed = False
            print("  FAILED: expected an exception")
        except Exception as exc:
            if error_substr not in str(exc):
                all_passed = False
                print(f"  FAILED: wrong error, got: {exc}")

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
