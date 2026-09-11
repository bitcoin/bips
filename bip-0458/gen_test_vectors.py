#!/usr/bin/env python3
"""
Generate test vectors for Schnorr signature half-aggregation.

Usage:
    python gen_test_vectors.py

Outputs:
    - vectors/test_vectors_aggregate.csv
    - vectors/test_vectors_incaggregate.csv
    - vectors/test_vectors_verify.csv
"""

import csv
import os
from pathlib import Path
from typing import List, Tuple

from halfagg import Aggregate, IncAggregate, hashHalfAgg_randomizer
from secp256k1lab.secp256k1 import GE, FE, Scalar
from secp256k1lab.util import bytes_from_int
from secp256k1lab.bip340 import pubkey_gen, schnorr_sign, schnorr_verify


ROOT = Path(__file__).resolve().parent
VECTORS_DIR = ROOT / "vectors"
AGGREGATE_VECTORS = VECTORS_DIR / 'test_vectors_aggregate.csv'
INCAGGREGATE_VECTORS = VECTORS_DIR / 'test_vectors_incaggregate.csv'
VERIFY_VECTORS = VECTORS_DIR / 'test_vectors_verify.csv'

n = GE.ORDER
p = FE.SIZE


def create_signature(index: int) -> Tuple[bytes, bytes, bytes]:
    """Create a deterministic (pubkey, message, signature) triple."""
    sk = bytes([index + 1] * 32)
    pk = pubkey_gen(sk)
    msg = bytes([index + 2] * 32)
    aux = bytes([index + 3] * 32)
    sig = schnorr_sign(msg, sk, aux)
    return pk, msg, sig


def format_list(items: List[bytes], sep: str = ";") -> str:
    """Format a list of bytes as semicolon-separated hex strings."""
    if not items:
        return ""
    return sep.join(item.hex().upper() for item in items)


def gen_aggregate_vectors(f):
    """Generate test vectors for Aggregate function."""
    writer = csv.writer(f)
    writer.writerow((
        "index",
        "pubkeys",
        "messages",
        "signatures",
        "expected_result",
        "expected_aggsig",
        "comment"
    ))

    idx = 0
    sigs = [create_signature(i) for i in range(5)]

    # Success: Empty aggregation
    aggsig_empty = Aggregate([])
    writer.writerow((
        idx, "", "", "",
        "TRUE",
        aggsig_empty.hex().upper(),
        "Empty signature list"
    ))
    idx += 1

    # Success: Single signature
    pk0, msg0, sig0 = sigs[0]
    aggsig_1 = Aggregate([(pk0, msg0, sig0)])
    writer.writerow((
        idx,
        pk0.hex().upper(),
        msg0.hex().upper(),
        sig0.hex().upper(),
        "TRUE",
        aggsig_1.hex().upper(),
        "Single signature"
    ))
    idx += 1

    # Success: Two signatures
    pk1, msg1, sig1 = sigs[1]
    pms_2 = [(pk0, msg0, sig0), (pk1, msg1, sig1)]
    aggsig_2 = Aggregate(pms_2)
    writer.writerow((
        idx,
        format_list([pk0, pk1]),
        format_list([msg0, msg1]),
        format_list([sig0, sig1]),
        "TRUE",
        aggsig_2.hex().upper(),
        "Two signatures"
    ))
    idx += 1

    # Success: Three signatures
    pk2, msg2, sig2 = sigs[2]
    pms_3 = [(pk0, msg0, sig0), (pk1, msg1, sig1), (pk2, msg2, sig2)]
    aggsig_3 = Aggregate(pms_3)
    writer.writerow((
        idx,
        format_list([pk0, pk1, pk2]),
        format_list([msg0, msg1, msg2]),
        format_list([sig0, sig1, sig2]),
        "TRUE",
        aggsig_3.hex().upper(),
        "Three signatures"
    ))
    idx += 1

    # Success: Five signatures
    pms_5 = [sigs[i] for i in range(5)]
    aggsig_5 = Aggregate(pms_5)
    writer.writerow((
        idx,
        format_list([s[0] for s in pms_5]),
        format_list([s[1] for s in pms_5]),
        format_list([s[2] for s in pms_5]),
        "TRUE",
        aggsig_5.hex().upper(),
        "Five signatures"
    ))
    idx += 1

    # Success: Strange aggregation - individual invalid sigs that are valid
    # in aggregate
    pk_a, msg_a, sig_a = sigs[0]
    pk_b, msg_b, sig_b = sigs[1]
    pms_valid = [(pk_a, msg_a, sig_a), (pk_b, msg_b, sig_b)]
    aggsig_valid = Aggregate(pms_valid)

    pmr = []
    z = []
    for i in range(2):
        pk, msg, sig = pms_valid[i]
        pmr.append((pk, msg, sig[:32]))
        z.append(hashHalfAgg_randomizer(pmr, i))

    sagg = Scalar.from_bytes_wrapping(aggsig_valid[64:96])
    s1_new = Scalar.from_int_wrapping(0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0)
    s0_new = (sagg - z[1] * s1_new) / z[0]

    sig_a_invalid = sig_a[:32] + s0_new.to_bytes()
    assert not schnorr_verify(msg_a, pk_a, sig_a_invalid), "sig_a_invalid should not verify"
    sig_b_invalid = sig_b[:32] + s1_new.to_bytes()
    assert not schnorr_verify(msg_b, pk_b, sig_b_invalid), "sig_b_invalid should not verify"

    pms_strange = [(pk_a, msg_a, sig_a_invalid), (pk_b, msg_b, sig_b_invalid)]
    aggsig_strange = Aggregate(pms_strange)

    writer.writerow((
        idx,
        format_list([pk_a, pk_b]),
        format_list([msg_a, msg_b]),
        format_list([sig_a_invalid, sig_b_invalid]),
        "TRUE",
        aggsig_strange.hex().upper(),
        "Strange aggregation - invalid individual sigs, valid aggregate"
    ))
    idx += 1

    # Failure: Signature with s = n
    invalid_sig_n = sig0[0:32] + bytes_from_int(n)
    writer.writerow((
        idx,
        pk0.hex().upper(),
        msg0.hex().upper(),
        invalid_sig_n.hex().upper(),
        "FALSE",
        "",
        "Signature s = n (at boundary)"
    ))
    idx += 1

    # Failure: Signature with s > n
    invalid_sig_gt_n = sig0[0:32] + bytes_from_int(n + 1000)
    writer.writerow((
        idx,
        pk0.hex().upper(),
        msg0.hex().upper(),
        invalid_sig_gt_n.hex().upper(),
        "FALSE",
        "",
        "Signature s > n"
    ))
    idx += 1

    # Failure: Signature with s = 2^256 - 1
    invalid_sig_max = sig0[0:32] + bytes([0xff] * 32)
    writer.writerow((
        idx,
        pk0.hex().upper(),
        msg0.hex().upper(),
        invalid_sig_max.hex().upper(),
        "FALSE",
        "",
        "Signature s = 2^256 - 1"
    ))
    idx += 1


def gen_incaggregate_vectors(f):
    """Generate test vectors for IncAggregate function."""
    writer = csv.writer(f)
    writer.writerow((
        "index",
        "aggsig",
        "pm_aggd_pubkeys",
        "pm_aggd_messages",
        "pms_pubkeys",
        "pms_messages",
        "pms_signatures",
        "expected_result",
        "expected_aggsig",
        "comment"
    ))

    idx = 0
    sigs = [create_signature(i) for i in range(4)]
    pk0, msg0, sig0 = sigs[0]
    pk1, msg1, sig1 = sigs[1]
    pk2, msg2, sig2 = sigs[2]

    # Success: Increment empty aggregate with single signature
    empty_aggsig = bytes([0] * 32)
    result_0 = IncAggregate(empty_aggsig, [], [(pk0, msg0, sig0)])
    writer.writerow((
        idx,
        empty_aggsig.hex().upper(),
        "", "",
        pk0.hex().upper(),
        msg0.hex().upper(),
        sig0.hex().upper(),
        "TRUE",
        result_0.hex().upper(),
        "Add single signature to empty aggregate"
    ))
    idx += 1

    # Success: Increment single-sig aggregate with another signature
    aggsig_1 = Aggregate([(pk0, msg0, sig0)])
    result_1 = IncAggregate(aggsig_1, [(pk0, msg0)], [(pk1, msg1, sig1)])
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        pk1.hex().upper(),
        msg1.hex().upper(),
        sig1.hex().upper(),
        "TRUE",
        result_1.hex().upper(),
        "Add second signature to single-sig aggregate"
    ))
    idx += 1

    # Success: Add two signatures at once
    result_2 = IncAggregate(aggsig_1, [(pk0, msg0)], [(pk1, msg1, sig1), (pk2, msg2, sig2)])
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        format_list([pk1, pk2]),
        format_list([msg1, msg2]),
        format_list([sig1, sig2]),
        "TRUE",
        result_2.hex().upper(),
        "Add two signatures at once"
    ))
    idx += 1

    # Success: Increment with empty new signatures (no change)
    result_3 = IncAggregate(aggsig_1, [(pk0, msg0)], [])
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "", "", "",
        "TRUE",
        result_3.hex().upper(),
        "Add no new signatures (unchanged)"
    ))
    idx += 1

    # Failure: Wrong aggsig length (too long)
    wrong_len_aggsig = bytes([0] * 64)
    writer.writerow((
        idx,
        wrong_len_aggsig.hex().upper(),
        "", "",
        "", "", "",
        "FALSE",
        "",
        "Aggregate signature wrong length"
    ))
    idx += 1

    # Failure: Empty aggsig
    writer.writerow((
        idx,
        "",
        "", "",
        "", "", "",
        "FALSE",
        "",
        "Aggregate signature empty"
    ))
    idx += 1

    # Failure: Existing aggsig with s = n
    invalid_aggsig_s = bytes_from_int(n)
    writer.writerow((
        idx,
        invalid_aggsig_s.hex().upper(),
        "", "",
        "", "", "",
        "FALSE",
        "",
        "Existing aggregate has s = n"
    ))
    idx += 1

    # Failure: New signature with s = n
    invalid_new_sig = sig0[0:32] + bytes_from_int(n)
    writer.writerow((
        idx,
        empty_aggsig.hex().upper(),
        "", "",
        pk0.hex().upper(),
        msg0.hex().upper(),
        invalid_new_sig.hex().upper(),
        "FALSE",
        "",
        "New signature has s = n"
    ))
    idx += 1


def gen_verify_vectors(f):
    """Generate test vectors for VerifyAggregate function."""
    writer = csv.writer(f)
    writer.writerow((
        "index",
        "aggsig",
        "pubkeys",
        "messages",
        "expected_result",
        "comment"
    ))

    idx = 0
    sigs = [create_signature(i) for i in range(5)]
    pk0, msg0, sig0 = sigs[0]
    pk1, msg1, sig1 = sigs[1]
    pk2, msg2, sig2 = sigs[2]

    # Success: Empty signature list
    writer.writerow((
        idx,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "", "",
        "TRUE",
        "Empty signature list"
    ))
    idx += 1

    # Success: Single signature
    writer.writerow((
        idx,
        "B070AAFCEA439A4F6F1BBFC2EB66D29D24B0CAB74D6B745C3CFB009CC8FE4AA80E066C34819936549FF49B6FD4D41EDFC401A367B87DDD59FEE38177961C225F",
        "1B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "TRUE",
        "Single signature"
    ))
    idx += 1

    # Success: Two signatures
    writer.writerow((
        idx,
        "B070AAFCEA439A4F6F1BBFC2EB66D29D24B0CAB74D6B745C3CFB009CC8FE4AA8A3AFBDB45A6A34BF7C8C00F1B6D7E7D375B54540F13716C87B62E51E2F4F22FFBF8913EC53226A34892D60252A7052614CA79AE939986828D81D2311957371AD",
        "1B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F;462779AD4AAD39514614751A71085F2F10E1C7A593E4E030EFB5B8721CE55B0B",
        "0202020202020202020202020202020202020202020202020202020202020202;0505050505050505050505050505050505050505050505050505050505050505",
        "TRUE",
        "Two signatures"
    ))
    idx += 1

    # Success: Three signatures
    aggsig_3 = Aggregate([(pk0, msg0, sig0), (pk1, msg1, sig1), (pk2, msg2, sig2)])
    writer.writerow((
        idx,
        aggsig_3.hex().upper(),
        format_list([pk0, pk1, pk2]),
        format_list([msg0, msg1, msg2]),
        "TRUE",
        "Three signatures"
    ))
    idx += 1

    # Success: Five signatures
    pms_5 = [sigs[i] for i in range(5)]
    aggsig_5 = Aggregate(pms_5)
    writer.writerow((
        idx,
        aggsig_5.hex().upper(),
        format_list([s[0] for s in pms_5]),
        format_list([s[1] for s in pms_5]),
        "TRUE",
        "Five signatures"
    ))
    idx += 1

    # Failure: Public key not on curve
    aggsig_1 = Aggregate([(pk0, msg0, sig0)])
    invalid_x = 0x4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D  # From BIP340
    invalid_pk = bytes_from_int(invalid_x)
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        invalid_pk.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Public key not on curve"
    ))
    idx += 1

    # Failure: Public key is zero
    zero_pk = bytes([0] * 32)
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        zero_pk.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Public key is zero"
    ))
    idx += 1

    # Failure: Public key >= field size
    pk_too_large = bytes_from_int(p)
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        pk_too_large.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Public key >= field size"
    ))
    idx += 1

    # Failure: R value not on curve
    invalid_r = bytes_from_int(invalid_x)
    invalid_r_aggsig = invalid_r + sig0[32:64]
    writer.writerow((
        idx,
        invalid_r_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "R value not on curve"
    ))
    idx += 1

    # Failure: R value is zero
    zero_r_aggsig = bytes([0] * 32) + sig0[32:64]
    writer.writerow((
        idx,
        zero_r_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "R value is zero"
    ))
    idx += 1

    # Failure: R value >= field size
    r_too_large_aggsig = bytes_from_int(p + 100) + sig0[32:64]
    writer.writerow((
        idx,
        r_too_large_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "R value >= field size"
    ))
    idx += 1

    # Failure: Aggregate s = n
    s_n_aggsig = sig0[0:32] + bytes_from_int(n)
    writer.writerow((
        idx,
        s_n_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Aggregate s = n"
    ))
    idx += 1

    # Failure: Aggregate s > n
    s_gt_n_aggsig = sig0[0:32] + bytes_from_int(n + 1000)
    writer.writerow((
        idx,
        s_gt_n_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Aggregate s > n"
    ))
    idx += 1

    # Failure: Aggregate s = 2^256 - 1
    max_s_aggsig = sig0[0:32] + bytes([0xff] * 32)
    writer.writerow((
        idx,
        max_s_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Aggregate s = 2^256 - 1"
    ))
    idx += 1

    # Failure: Wrong message
    wrong_msg = bytes([0xff] * 32)
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        pk0.hex().upper(),
        wrong_msg.hex().upper(),
        "FALSE",
        "Wrong message"
    ))
    idx += 1

    # Failure: Wrong public key
    writer.writerow((
        idx,
        aggsig_1.hex().upper(),
        pk1.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Wrong public key"
    ))
    idx += 1

    # Failure: Tampered signature
    tampered_aggsig = aggsig_1[:-1] + bytes([(aggsig_1[-1] + 1) % 256])
    writer.writerow((
        idx,
        tampered_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Tampered signature (bit flip)"
    ))
    idx += 1

    # Failure: Swapped order
    aggsig_2 = Aggregate([(pk0, msg0, sig0), (pk1, msg1, sig1)])
    writer.writerow((
        idx,
        aggsig_2.hex().upper(),
        format_list([pk1, pk0]),
        format_list([msg1, msg0]),
        "FALSE",
        "Swapped order"
    ))
    idx += 1

    # Failure: s = n - 1 (valid range, wrong signature)
    s_n_minus_1_aggsig = sig0[0:32] + bytes_from_int(n - 1)
    writer.writerow((
        idx,
        s_n_minus_1_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "s = n-1 (valid range, wrong sig)"
    ))
    idx += 1

    # Failure: s = 0 (valid range, wrong signature)
    s_zero_aggsig = sig0[0:32] + bytes([0] * 32)
    writer.writerow((
        idx,
        s_zero_aggsig.hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "s = 0 (valid range, wrong sig)"
    ))
    idx += 1

    # Failure: Aggsig too short
    writer.writerow((
        idx,
        sig0[0:31].hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Aggregate signature too short"
    ))
    idx += 1

    # Failure: Aggsig too long
    writer.writerow((
        idx,
        (aggsig_1 + bytes([0] * 32)).hex().upper(),
        pk0.hex().upper(),
        msg0.hex().upper(),
        "FALSE",
        "Aggregate signature too long"
    ))
    idx += 1


if __name__ == "__main__":
    os.makedirs(VECTORS_DIR, exist_ok=True)

    print(f"Generating {AGGREGATE_VECTORS}")
    with open(AGGREGATE_VECTORS, "w", newline='', encoding="utf-8") as f:
        gen_aggregate_vectors(f)

    print(f"Generating {INCAGGREGATE_VECTORS}")
    with open(INCAGGREGATE_VECTORS, "w", newline='', encoding="utf-8") as f:
        gen_incaggregate_vectors(f)

    print(f"Generating {VERIFY_VECTORS}")
    with open(VERIFY_VECTORS, "w", newline='', encoding="utf-8") as f:
        gen_verify_vectors(f)

    print("Done.")
