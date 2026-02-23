"""
Silent payment output script derivation
"""

from typing import List

from deps.bitcoin_test.messages import COutPoint
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.ecdh import ecdh_compressed_in_raw_out
from secp256k1lab.util import tagged_hash


def compute_silent_payment_output_script(
    outpoints: List[COutPoint],
    summed_pubkey_bytes: bytes,
    ecdh_share_bytes: bytes,
    spend_pubkey_bytes: bytes,
    k: int,
) -> bytes:
    """Compute silent payment output script per BIP-352"""
    input_hash_bytes = get_input_hash(outpoints, GE.from_bytes(summed_pubkey_bytes))

    # Compute shared_secret = input_hash * ecdh_share
    shared_secret_bytes = ecdh_compressed_in_raw_out(
        input_hash_bytes, ecdh_share_bytes
    ).to_bytes_compressed()

    # Compute t_k = hash_BIP0352/SharedSecret(shared_secret || k)
    t_k = Scalar.from_bytes_checked(
        tagged_hash("BIP0352/SharedSecret", shared_secret_bytes + ser_uint32(k))
    )

    # Compute P_k = B_spend + t_k * G
    B_spend = GE.from_bytes(spend_pubkey_bytes)
    P_k = B_spend + t_k * G

    # Return P2TR script (x-only pubkey)
    return bytes([0x51, 0x20]) + P_k.to_bytes_xonly()


def get_input_hash(outpoints: List[COutPoint], sum_input_pubkeys: GE) -> bytes:
    """Compute input hash per BIP-352"""
    lowest_outpoint = sorted(outpoints, key=lambda outpoint: outpoint.serialize())[0]
    return tagged_hash(
        "BIP0352/Inputs",
        lowest_outpoint.serialize() + sum_input_pubkeys.to_bytes_compressed(),
    )


def ser_uint32(u: int) -> bytes:
    return u.to_bytes(4, "big")
