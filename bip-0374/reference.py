#!/usr/bin/env python3

"""Reference implementation of DLEQ BIP for secp256k1 with unit tests."""

from hashlib import sha256
import random
from secp256k1 import G, GE
import sys
import unittest


DLEQ_TAG_AUX = "BIP0374/aux"
DLEQ_TAG_NONCE = "BIP0374/nonce"
DLEQ_TAG_CHALLENGE = "BIP0374/challenge"


def TaggedHash(tag: str, data: bytes) -> bytes:
    ss = sha256(tag.encode()).digest()
    ss += ss
    ss += data
    return sha256(ss).digest()


def xor_bytes(lhs: bytes, rhs: bytes) -> bytes:
    assert len(lhs) == len(rhs)
    return bytes([lhs[i] ^ rhs[i] for i in range(len(lhs))])


def dleq_challenge(
    A: GE, B: GE, C: GE, R1: GE, R2: GE, m: bytes | None, G: GE,
) -> int:
    if m is not None:
        assert len(m) == 32
    m = bytes([]) if m is None else m
    return int.from_bytes(
        TaggedHash(
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
    A = a * G
    C = a * B
    t = xor_bytes(a.to_bytes(32, "big"), TaggedHash(DLEQ_TAG_AUX, r))
    rand = TaggedHash(
        DLEQ_TAG_NONCE, t + A.to_bytes_compressed() + C.to_bytes_compressed()
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
    # TODO: implement subtraction operator (__sub__) for GE class to simplify these terms
    R1 = s * G + (-e * A)
    if R1.infinity:
        return False
    R2 = s * B + (-e * C)
    if R2.infinity:
        return False
    if e != dleq_challenge(A, B, C, R1, R2, m, G):
        return False
    return True


class DLEQTests(unittest.TestCase):
    def test_dleq(self):
        seed = random.randrange(sys.maxsize)
        random.seed(seed)
        print(f"PRNG seed is: {seed}")
        for _ in range(10):
            # generate random keypairs for both parties
            a = random.randrange(1, GE.ORDER)
            A = a * G
            b = random.randrange(1, GE.ORDER)
            B = b * G

            # create shared secret
            C = a * B

            # create dleq proof
            rand_aux = random.randbytes(32)
            proof = dleq_generate_proof(a, B, rand_aux)
            self.assertTrue(proof is not None)
            # verify dleq proof
            success = dleq_verify_proof(A, B, C, proof)
            self.assertTrue(success)

            # flip a random bit in the dleq proof and check that verification fails
            for _ in range(5):
                proof_damaged = list(proof)
                proof_damaged[random.randrange(len(proof))] ^= 1 << (
                    random.randrange(8)
                )
                success = dleq_verify_proof(A, B, C, bytes(proof_damaged))
                self.assertFalse(success)

            # create the same dleq proof with a message
            message = random.randbytes(32)
            proof = dleq_generate_proof(a, B, rand_aux, m=message)
            self.assertTrue(proof is not None)
            # verify dleq proof with a message
            success = dleq_verify_proof(A, B, C, proof, m=message)
            self.assertTrue(success)

            # flip a random bit in the dleq proof and check that verification fails
            for _ in range(5):
                proof_damaged = list(proof)
                proof_damaged[random.randrange(len(proof))] ^= 1 << (
                    random.randrange(8)
                )
                success = dleq_verify_proof(A, B, C, bytes(proof_damaged))
                self.assertFalse(success)
