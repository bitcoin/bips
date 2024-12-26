#!/usr/bin/env python3
"""Generate the BIP-DLEQ test vectors (limited to secp256k1 generator right now)."""
import csv
import os
import sys
from reference import (
    TaggedHash,
    dleq_generate_proof,
    dleq_verify_proof,
)
from secp256k1 import G as GENERATOR, GE


NUM_SUCCESS_TEST_VECTORS = 5
DLEQ_TAG_TESTVECTORS_RNG = "BIP0374/testvectors_rng"

FILENAME_GENERATE_PROOF_TEST = os.path.join(sys.path[0], 'test_vectors_generate_proof.csv')
FILENAME_VERIFY_PROOF_TEST = os.path.join(sys.path[0], 'test_vectors_verify_proof.csv')


def random_scalar_int(vector_i, purpose):
    rng_out = TaggedHash(DLEQ_TAG_TESTVECTORS_RNG, purpose.encode() + vector_i.to_bytes(4, 'little'))
    return int.from_bytes(rng_out, 'big') % GE.ORDER


def random_bytes(vector_i, purpose):
    rng_out = TaggedHash(DLEQ_TAG_TESTVECTORS_RNG, purpose.encode() + vector_i.to_bytes(4, 'little'))
    return rng_out


def create_test_vector_data(vector_i):
    g = random_scalar_int(vector_i, "scalar_g")
    assert g < GE.ORDER
    assert g > 0
    G = g * GENERATOR
    assert not G.infinity
    a = random_scalar_int(vector_i, "scalar_a")
    A = a * G
    b = random_scalar_int(vector_i, "scalar_b")
    B = b * G
    C = a * B  # shared secret
    assert C.to_bytes_compressed() == (b * A).to_bytes_compressed()
    auxrand = random_bytes(vector_i, "auxrand")
    msg = random_bytes(vector_i, "message")
    proof = dleq_generate_proof(a, B, auxrand, G=G, m=msg)
    return (G, a, A, b, B, C, auxrand, msg, proof)

TEST_VECTOR_DATA = [create_test_vector_data(i) for i in range(NUM_SUCCESS_TEST_VECTORS)]


def gen_all_generate_proof_vectors(f):
    writer = csv.writer(f)
    writer.writerow(("index", "point_G", "scalar_a", "point_B", "auxrand_r", "message", "result_proof", "comment"))

    # success cases with random values
    idx = 0
    for i in range(NUM_SUCCESS_TEST_VECTORS):
        G, a, A, b, B, C, auxrand, msg, proof = TEST_VECTOR_DATA[i]
        assert proof is not None and len(proof) == 64
        writer.writerow((idx, G.to_bytes_compressed().hex(), f"{a:064x}", B.to_bytes_compressed().hex(), auxrand.hex(), msg.hex(), proof.hex(), f"Success case {i+1}"))
        idx += 1

    # failure cases: a is not within group order (a=0, a=N)
    a_invalid = 0
    assert dleq_generate_proof(a_invalid, B, auxrand, G=G, m=msg) is None
    writer.writerow((idx, G.to_bytes_compressed().hex(), f"{a_invalid:064x}", B.to_bytes_compressed().hex(), auxrand.hex(), msg.hex(), "INVALID", f"Failure case (a=0)"))
    idx += 1
    a_invalid = GE.ORDER
    assert dleq_generate_proof(a_invalid, B, auxrand, G=G, m=msg) is None
    writer.writerow((idx, G.to_bytes_compressed().hex(), f"{a_invalid:064x}", B.to_bytes_compressed().hex(), auxrand.hex(), msg.hex(), "INVALID", f"Failure case (a=N [group order])"))
    idx += 1

    # failure case: B is point at infinity
    B_infinity = GE()
    B_infinity_str = "INFINITY"
    assert dleq_generate_proof(a, B_infinity, auxrand, m=msg) is None
    writer.writerow((idx, G.to_bytes_compressed().hex(), f"{a:064x}", B_infinity_str, auxrand.hex(), msg.hex(), "INVALID", f"Failure case (B is point at infinity)"))
    idx += 1


def gen_all_verify_proof_vectors(f):
    writer = csv.writer(f)
    writer.writerow(("index", "point_G", "point_A", "point_B", "point_C", "proof", "message", "result_success", "comment"))

    # success cases (same as above)
    idx = 0
    for i in range(NUM_SUCCESS_TEST_VECTORS):
        G, _, A, _, B, C, _, msg, proof = TEST_VECTOR_DATA[i]
        assert dleq_verify_proof(A, B, C, proof, G=G, m=msg)
        writer.writerow((idx, G.to_bytes_compressed().hex(), A.to_bytes_compressed().hex(), B.to_bytes_compressed().hex(),
                         C.to_bytes_compressed().hex(), proof.hex(), msg.hex(), "TRUE", f"Success case {i+1}"))
        idx += 1

    # other permutations of A, B, C should always fail
    for i, points in enumerate(([A, C, B], [B, A, C], [B, C, A], [C, A, B], [C, B, A])):
        assert not dleq_verify_proof(points[0], points[1], points[2], proof, m=msg)
        writer.writerow((idx, G.to_bytes_compressed().hex(), points[0].to_bytes_compressed().hex(), points[1].to_bytes_compressed().hex(),
                         points[2].to_bytes_compressed().hex(), proof.hex(), msg.hex(), "FALSE", f"Swapped points case {i+1}"))
        idx += 1

    # modifying proof should fail (flip one bit)
    proof_damage_pos = random_scalar_int(idx, "damage_pos") % 256
    proof_damaged = list(proof)
    proof_damaged[proof_damage_pos // 8] ^= (1 << (proof_damage_pos % 8))
    proof_damaged = bytes(proof_damaged)
    writer.writerow((idx, G.to_bytes_compressed().hex(), A.to_bytes_compressed().hex(), B.to_bytes_compressed().hex(),
                     C.to_bytes_compressed().hex(), proof_damaged.hex(), msg.hex(), "FALSE", f"Tampered proof (random bit-flip)"))
    idx += 1

    # modifying message should fail (flip one bit)
    msg_damage_pos = random_scalar_int(idx, "damage_pos") % 256
    msg_damaged = list(msg)
    msg_damaged[proof_damage_pos // 8] ^= (1 << (msg_damage_pos % 8))
    msg_damaged = bytes(msg_damaged)
    writer.writerow((idx, G.to_bytes_compressed().hex(), A.to_bytes_compressed().hex(), B.to_bytes_compressed().hex(),
                     C.to_bytes_compressed().hex(), proof.hex(), msg_damaged.hex(), "FALSE", f"Tampered message (random bit-flip)"))
    idx += 1


if __name__ == "__main__":
    print(f"Generating {FILENAME_GENERATE_PROOF_TEST}...")
    with open(FILENAME_GENERATE_PROOF_TEST, "w", encoding="utf-8") as fil_generate_proof:
        gen_all_generate_proof_vectors(fil_generate_proof)
    print(f"Generating {FILENAME_VERIFY_PROOF_TEST}...")
    with open(FILENAME_VERIFY_PROOF_TEST, "w", encoding="utf-8") as fil_verify_proof:
        gen_all_verify_proof_vectors(fil_verify_proof)
