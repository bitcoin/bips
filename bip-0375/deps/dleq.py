#!/usr/bin/env python3
"""
Handle DLEQ proof generation and verification

Adapted from bip-0374 reference.py
"""

from secp256k1lab.secp256k1 import G, GE
from secp256k1lab.util import tagged_hash, xor_bytes


DLEQ_TAG_AUX = "BIP0374/aux"
DLEQ_TAG_NONCE = "BIP0374/nonce"
DLEQ_TAG_CHALLENGE = "BIP0374/challenge"


def dleq_challenge(
    A: GE, B: GE, C: GE, R1: GE, R2: GE, m: bytes | None, G: GE,
) -> int:
    if m is not None:
        assert len(m) == 32
    m = bytes([]) if m is None else m
    return int.from_bytes(
        tagged_hash(
            DLEQ_TAG_CHALLENGE,
            A.to_bytes_compressed()
            + B.to_bytes_compressed()
            + C.to_bytes_compressed()
            + G.to_bytes_compressed()
            + R1.to_bytes_compressed()
            + R2.to_bytes_compressed()
            + m,
        ),
        "big",
    )


def dleq_generate_proof(
    a: int, B: GE, r: bytes, G: GE = G, m: bytes | None = None
) -> bytes | None:
    assert len(r) == 32
    if not (0 < a < GE.ORDER):
        return None
    if B.infinity:
        return None
    if m is not None:
        assert len(m) == 32
    A = a * G
    C = a * B
    t = xor_bytes(a.to_bytes(32, "big"), tagged_hash(DLEQ_TAG_AUX, r))
    m_prime = bytes([]) if m is None else m
    rand = tagged_hash(
        DLEQ_TAG_NONCE, t + A.to_bytes_compressed() + C.to_bytes_compressed() + m_prime
    )
    k = int.from_bytes(rand, "big") % GE.ORDER
    if k == 0:
        return None
    R1 = k * G
    R2 = k * B
    e = dleq_challenge(A, B, C, R1, R2, m, G)
    s = (k + e * a) % GE.ORDER
    proof = e.to_bytes(32, "big") + s.to_bytes(32, "big")
    if not dleq_verify_proof(A, B, C, proof, G=G, m=m):
        return None
    return proof


def dleq_verify_proof(
    A: GE, B: GE, C: GE, proof: bytes, G: GE = G, m: bytes | None = None
) -> bool:
    if A.infinity or B.infinity or C.infinity or G.infinity:
        return False
    assert len(proof) == 64
    e = int.from_bytes(proof[:32], "big")
    s = int.from_bytes(proof[32:], "big")
    if s >= GE.ORDER:
        return False
    R1 = s * G - e * A
    if R1.infinity:
        return False
    R2 = s * B - e * C
    if R2.infinity:
        return False
    if e != dleq_challenge(A, B, C, R1, R2, m, G):
        return False
    return True
