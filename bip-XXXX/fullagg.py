#!/usr/bin/env python3
"""
Reference implementation of Full Aggregation of BIP 340 Signatures
per the DahLIAS interactive signing protocol.

WARNING: This implementation is for demonstration purposes only and is not
optimized for production use.
"""

from pathlib import Path
from typing import List, Tuple, Optional
import secrets
import sys

sys.path.insert(0, str(Path(__file__).parent / "secp256k1lab/src"))
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash, xor_bytes

n = GE.ORDER

FULLAGG_TAG_AUX = "FullAgg/aux"
FULLAGG_TAG_NONCE = "FullAgg/nonce"
FULLAGG_TAG_NONCECOEF = "FullAgg/noncecoef"
FULLAGG_TAG_SIG = "FullAgg/sig"


#
# Helpers
#

def has_even_y(P: GE) -> bool:
    return P.has_even_y()


def cbytes(P: GE) -> bytes:
    return P.to_bytes_compressed()


def xbytes(P: GE) -> bytes:
    return P.to_bytes_xonly()


#
# Key Tweaking
#

def TweakSK(sk: Scalar, t: Scalar, is_xonly: bool) -> Scalar:
    d = sk if (not is_xonly or has_even_y(sk * G)) else -sk
    return d + t


def TweakPK(pk: GE, t: Scalar, is_xonly: bool) -> GE:
    P = pk if (not is_xonly or has_even_y(pk)) else -pk
    Q = P + t * G
    assert not Q.infinity
    return Q


#
# Nonce Generation and Aggregation
#

def NonceGen(sk: Optional[Scalar] = None,
             extra_in: bytes = b'') -> Tuple[Tuple[Scalar, Scalar], Tuple[GE, GE]]:
    rand_prime = secrets.token_bytes(32)
    if sk is not None:
        rand = xor_bytes(sk.to_bytes(), tagged_hash(FULLAGG_TAG_AUX, rand_prime))
    else:
        rand = rand_prime
    r1 = Scalar.from_bytes_wrapping(tagged_hash(FULLAGG_TAG_NONCE, rand + extra_in + b'\x00'))
    r2 = Scalar.from_bytes_wrapping(tagged_hash(FULLAGG_TAG_NONCE, rand + extra_in + b'\x01'))
    assert r1 != 0 and r2 != 0
    R1, R2 = r1 * G, r2 * G
    return (r1, r2), (R1, R2)


def NonceAgg(pubnonces: List[Tuple[GE, GE]]) -> Tuple[GE, GE]:
    u = len(pubnonces)
    R1, R2 = pubnonces[0]
    for i in range(1, u):
        R1 = R1 + pubnonces[i][0]
        R2 = R2 + pubnonces[i][1]
    if R1.infinity or R2.infinity:
        raise ValueError("aggregate nonce is the point at infinity")
    return R1, R2


#
# Session Values
#

def GetSessionValues(aggnonce: Tuple[GE, GE], pks: List[GE], msgs: List[bytes],
                     pubnonces: List[Tuple[GE, GE]]) -> Tuple[GE, Scalar]:
    R1, R2 = aggnonce
    u = len(pks)
    nonce_data = cbytes(R1) + cbytes(R2)
    for i in range(u):
        nonce_data += xbytes(pks[i]) + msgs[i] + cbytes(pubnonces[i][1])
    b = Scalar.from_bytes_wrapping(tagged_hash(FULLAGG_TAG_NONCECOEF, nonce_data))
    R = R1 + b * R2
    assert not R.infinity
    return R, b


#
# Signing
#

def Sign(secnonce: Tuple[Scalar, Scalar], sk: Scalar, m: bytes,
         aggnonce: Tuple[GE, GE], pks: List[GE], msgs: List[bytes],
         pubnonces: List[Tuple[GE, GE]]) -> Scalar:
    assert len(pks) == len(msgs) == len(pubnonces) >= 1
    assert len(m) == 32 and all(len(mi) == 32 for mi in msgs)
    r1, r2 = secnonce
    assert r1 != 0 and r2 != 0
    assert sk != 0
    P = sk * G
    R2_local = r2 * G

    # Index lookup and uniqueness check
    matches = [j for j in range(len(pubnonces)) if pubnonces[j][1] == R2_local]
    assert len(matches) == 1
    j = matches[0]
    assert xbytes(pks[j]) == xbytes(P) and msgs[j] == m

    R, b = GetSessionValues(aggnonce, pks, msgs, pubnonces)
    e = Scalar(1) if has_even_y(R) else -Scalar(1)
    d_prime = sk if has_even_y(P) else -sk

    L = b''
    for i in range(len(pks)):
        L += xbytes(pks[i]) + msgs[i]
    c_j = Scalar.from_bytes_wrapping(tagged_hash(FULLAGG_TAG_SIG, L + xbytes(R) + xbytes(pks[j]) + msgs[j]))
    s_j = e * (r1 + b * r2) + c_j * d_prime
    return s_j


#
# Aggregation
#

def SigAgg(aggnonce: Tuple[GE, GE], pks: List[GE], msgs: List[bytes],
           pubnonces: List[Tuple[GE, GE]], psigs: List[Scalar]) -> Tuple[GE, Scalar]:
    assert len(pks) == len(msgs) == len(pubnonces) == len(psigs) >= 1
    assert all(len(mi) == 32 for mi in msgs)
    R, _ = GetSessionValues(aggnonce, pks, msgs, pubnonces)
    s = Scalar.sum(*psigs)
    return R, s


#
# Partial Signature Verification
#

def PartialSigVerify(psig: Scalar, pks: List[GE], msgs: List[bytes],
                     pubnonces: List[Tuple[GE, GE]], signer_index: int) -> bool:
    if not (len(pks) == len(msgs) == len(pubnonces) >= 1) or any(len(mi) != 32 for mi in msgs):
        return False
    if not (0 <= signer_index < len(pks)):
        return False
    i = signer_index
    R1_i, R2_i = pubnonces[i]
    P_i = GE.from_bytes_xonly(xbytes(pks[i]))
    R, b = GetSessionValues(NonceAgg(pubnonces), pks, msgs, pubnonces)
    e = Scalar(1) if has_even_y(R) else -Scalar(1)

    L = b''
    for k in range(len(pks)):
        L += xbytes(pks[k]) + msgs[k]
    c_i = Scalar.from_bytes_wrapping(tagged_hash(FULLAGG_TAG_SIG, L + xbytes(R) + xbytes(pks[i]) + msgs[i]))
    R_eff_i = R1_i + b * R2_i
    return psig * G == e * R_eff_i + c_i * P_i


#
# Aggregate Signature Verification
#

def Verify(pks: List[GE], msgs: List[bytes], sig: Tuple[GE, Scalar]) -> bool:
    R_point, s = sig
    if not (len(pks) == len(msgs) >= 1) or any(len(mi) != 32 for mi in msgs):
        return False
    u = len(pks)
    R = GE.from_bytes_xonly(xbytes(R_point))
    Ps = [GE.from_bytes_xonly(xbytes(pks[i])) for i in range(u)]

    L = b''
    for i in range(u):
        L += xbytes(pks[i]) + msgs[i]
    rhs = R
    for i in range(u):
        c_i = Scalar.from_bytes_wrapping(tagged_hash(FULLAGG_TAG_SIG, L + xbytes(R) + xbytes(pks[i]) + msgs[i]))
        rhs = rhs + c_i * Ps[i]
    return s * G == rhs
