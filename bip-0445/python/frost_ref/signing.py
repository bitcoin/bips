# BIP FROST Signing reference implementation
#
# It's worth noting that many functions, types, and exceptions were directly
# copied or modified from the MuSig2 (BIP 327) reference code, found at:
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import List, Optional, Tuple, NewType, NamedTuple, Sequence, Literal
import secrets

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import int_from_bytes, tagged_hash, xor_bytes

PlainPk = NewType("PlainPk", bytes)
XonlyPk = NewType("XonlyPk", bytes)
ContribKind = Literal[
    "aggothernonce", "aggnonce", "psig", "pubkey", "pubnonce", "pubshare"
]

# There are two types of exceptions that can be raised by this implementation:
#   - ValueError for indicating that an input doesn't conform to some function
#     precondition (e.g. an input array is the wrong length, a serialized
#     representation doesn't have the correct format).
#   - InvalidContributionError for indicating that a signer (or the
#     coordinator) is misbehaving in the protocol.
#
# Assertions are used to (1) satisfy the type-checking system, and (2) check for
# inconvenient events that can't happen except with negligible probability (e.g.
# output of a hash function is 0) and can't be manually triggered by any
# signer.


# This exception is raised if a party (signer or nonce coordinator) sends invalid
# values. Actual implementations should not crash when receiving invalid
# contributions. Instead, they should hold the offending party accountable.
class InvalidContributionError(Exception):
    def __init__(self, signer_id: Optional[int], contrib: ContribKind) -> None:
        # participant identifier of the signer who sent the invalid value
        self.id = signer_id
        # contrib is one of "pubkey", "pubnonce", "aggnonce", or "psig".
        self.contrib = contrib


def derive_interpolating_value(ids: List[int], my_id: int) -> Scalar:
    assert my_id in ids
    assert 0 <= my_id < 2**32
    assert len(set(ids)) == len(ids)
    num = Scalar(1)
    deno = Scalar(1)
    for curr_id in ids:
        if curr_id == my_id:
            continue
        num *= Scalar(curr_id + 1)
        deno *= Scalar(curr_id - my_id)
    return num / deno


def derive_thresh_pubkey(ids: List[int], pubshares: List[PlainPk]) -> PlainPk:
    Q = GE()
    for my_id, pubshare in zip(ids, pubshares):
        try:
            X_i = GE.from_bytes_compressed(pubshare)
        except ValueError:
            raise InvalidContributionError(my_id, "pubshare")
        lam_i = derive_interpolating_value(ids, my_id)
        Q = Q + lam_i * X_i
    # Q is not the point at infinity except with negligible probability.
    assert not Q.infinity
    return PlainPk(Q.to_bytes_compressed())


# REVIEW: should we remove n and t from this struct?
class SignersContext(NamedTuple):
    n: int
    t: int
    ids: List[int]
    pubshares: List[PlainPk]
    thresh_pk: PlainPk


def validate_signers_ctx(signers_ctx: SignersContext) -> None:
    n, t, ids, pubshares, thresh_pk = signers_ctx
    assert t <= n
    if not t <= len(ids) <= n:
        raise ValueError("The number of signers must be between t and n.")
    if len(pubshares) != len(ids):
        raise ValueError("The pubshares and ids arrays must have the same length.")
    for i, pubshare in zip(ids, pubshares):
        if not 0 <= i <= n - 1:
            raise ValueError(f"The participant identifier {i} is out of range.")
        try:
            _ = GE.from_bytes_compressed(pubshare)
        except ValueError:
            raise InvalidContributionError(i, "pubshare")
    if len(set(ids)) != len(ids):
        raise ValueError("The participant identifier list contains duplicate elements.")
    if derive_thresh_pubkey(ids, pubshares) != thresh_pk:
        raise ValueError("The provided key material is incorrect.")


class TweakContext(NamedTuple):
    Q: GE
    gacc: Scalar
    tacc: Scalar


def get_xonly_pk(tweak_ctx: TweakContext) -> XonlyPk:
    Q, _, _ = tweak_ctx
    return XonlyPk(Q.to_bytes_xonly())


def get_plain_pk(tweak_ctx: TweakContext) -> PlainPk:
    Q, _, _ = tweak_ctx
    return PlainPk(Q.to_bytes_compressed())


def tweak_ctx_init(thresh_pk: PlainPk) -> TweakContext:
    Q = GE.from_bytes_compressed(thresh_pk)
    gacc = Scalar(1)
    tacc = Scalar(0)
    return TweakContext(Q, gacc, tacc)


def apply_tweak(tweak_ctx: TweakContext, tweak: bytes, is_xonly: bool) -> TweakContext:
    if len(tweak) != 32:
        raise ValueError("The tweak must be a 32-byte array.")
    Q, gacc, tacc = tweak_ctx
    if is_xonly and not Q.has_even_y():
        g = Scalar(-1)
    else:
        g = Scalar(1)
    try:
        twk = Scalar.from_bytes_checked(tweak)
    except ValueError:
        raise ValueError("The tweak must be less than n.")
    Q_ = g * Q + twk * G
    if Q_.infinity:
        raise ValueError("The result of tweaking cannot be infinity.")
    gacc_ = g * gacc
    tacc_ = twk + g * tacc
    return TweakContext(Q_, gacc_, tacc_)


def nonce_hash(
    rand: bytes,
    pubshare: PlainPk,
    thresh_pk: XonlyPk,
    i: int,
    msg_prefixed: bytes,
    extra_in: bytes,
) -> bytes:
    buf = b""
    buf += rand
    buf += len(pubshare).to_bytes(1, "big")
    buf += pubshare
    buf += len(thresh_pk).to_bytes(1, "big")
    buf += thresh_pk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, "big")
    buf += extra_in
    buf += i.to_bytes(1, "big")
    return tagged_hash("FROST/nonce", buf)


def nonce_gen_internal(
    rand_: bytes,
    secshare: Optional[bytes],
    pubshare: Optional[PlainPk],
    thresh_pk: Optional[XonlyPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None:
        rand = xor_bytes(secshare, tagged_hash("FROST/aux", rand_))
    else:
        rand = rand_
    if pubshare is None:
        pubshare = PlainPk(b"")
    if thresh_pk is None:
        thresh_pk = XonlyPk(b"")
    if msg is None:
        msg_prefixed = b"\x00"
    else:
        msg_prefixed = b"\x01"
        msg_prefixed += len(msg).to_bytes(8, "big")
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b""
    k_1 = Scalar.from_bytes_wrapping(
        nonce_hash(rand, pubshare, thresh_pk, 0, msg_prefixed, extra_in)
    )
    k_2 = Scalar.from_bytes_wrapping(
        nonce_hash(rand, pubshare, thresh_pk, 1, msg_prefixed, extra_in)
    )
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R1_partial = k_1 * G
    R2_partial = k_2 * G
    assert not R1_partial.infinity
    assert not R2_partial.infinity
    pubnonce = R1_partial.to_bytes_compressed() + R2_partial.to_bytes_compressed()
    # use mutable `bytearray` since secnonce need to be replaced with zeros during signing.
    secnonce = bytearray(k_1.to_bytes() + k_2.to_bytes())
    return secnonce, pubnonce


# think: can msg & extra_in be of any length here?
# think: why doesn't musig2 ref code check for `pk` length here?
# REVIEW: Why should thresh_pk be XOnlyPk here? Shouldn't it be PlainPk?
def nonce_gen(
    secshare: Optional[bytes],
    pubshare: Optional[PlainPk],
    thresh_pk: Optional[XonlyPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None and len(secshare) != 32:
        raise ValueError("The optional byte array secshare must have length 32.")
    if pubshare is not None and len(pubshare) != 33:
        raise ValueError("The optional byte array pubshare must have length 33.")
    if thresh_pk is not None and len(thresh_pk) != 32:
        raise ValueError("The optional byte array thresh_pk must have length 32.")
    # bench: will adding individual_pk(secshare) == pubshare check, increase the execution time significantly?
    rand_ = secrets.token_bytes(32)
    return nonce_gen_internal(rand_, secshare, pubshare, thresh_pk, msg, extra_in)


# REVIEW should we raise value errors for:
#     (1) duplicate ids
#     (2) 0 <= id < max_participants < 2^32
# in each function that takes `ids` as argument?


# `ids` is typed as Sequence[Optional[int]] so that callers can pass either
# List[int] or List[Optional[int]] without triggering mypy invariance errors.
# Sequence is read-only and covariant.
def nonce_agg(pubnonces: List[bytes], ids: Sequence[Optional[int]]) -> bytes:
    if len(pubnonces) != len(ids):
        raise ValueError("The pubnonces and ids arrays must have the same length.")
    aggnonce = b""
    for j in (1, 2):
        R_j = GE()
        for my_id, pubnonce in zip(ids, pubnonces):
            try:
                R_ij = GE.from_bytes_compressed(pubnonce[(j - 1) * 33 : j * 33])
            except ValueError:
                raise InvalidContributionError(my_id, "pubnonce")
            R_j = R_j + R_ij
        aggnonce += R_j.to_bytes_compressed_with_infinity()
    return aggnonce


class SessionContext(NamedTuple):
    aggnonce: bytes
    signers_ctx: SignersContext
    tweaks: List[bytes]
    is_xonly: List[bool]
    msg: bytes


def thresh_pubkey_and_tweak(
    thresh_pk: PlainPk, tweaks: List[bytes], is_xonly: List[bool]
) -> TweakContext:
    if len(tweaks) != len(is_xonly):
        raise ValueError("The tweaks and is_xonly arrays must have the same length.")
    tweak_ctx = tweak_ctx_init(thresh_pk)
    v = len(tweaks)
    for i in range(v):
        tweak_ctx = apply_tweak(tweak_ctx, tweaks[i], is_xonly[i])
    return tweak_ctx


def get_session_values(
    session_ctx: SessionContext,
) -> Tuple[GE, Scalar, Scalar, List[int], List[PlainPk], Scalar, GE, Scalar]:
    (aggnonce, signers_ctx, tweaks, is_xonly, msg) = session_ctx
    validate_signers_ctx(signers_ctx)
    _, _, ids, pubshares, thresh_pk = signers_ctx
    Q, gacc, tacc = thresh_pubkey_and_tweak(thresh_pk, tweaks, is_xonly)
    # sort the ids before serializing because ROAST paper considers them as a set
    ser_ids = serialize_ids(ids)
    b = Scalar.from_bytes_wrapping(
        tagged_hash("FROST/noncecoef", ser_ids + aggnonce + Q.to_bytes_xonly() + msg)
    )
    assert b != 0
    try:
        R1 = GE.from_bytes_compressed_with_infinity(aggnonce[0:33])
        R2 = GE.from_bytes_compressed_with_infinity(aggnonce[33:66])
    except ValueError:
        # coordinator sent invalid aggnonce
        raise InvalidContributionError(None, "aggnonce")
    R_ = R1 + b * R2
    R = R_ if not R_.infinity else G
    assert not R.infinity
    e = Scalar.from_bytes_wrapping(
        tagged_hash("BIP0340/challenge", R.to_bytes_xonly() + Q.to_bytes_xonly() + msg)
    )
    assert e != 0
    return (Q, gacc, tacc, ids, pubshares, b, R, e)


def serialize_ids(ids: List[int]) -> bytes:
    # REVIEW assert for ids not being unsigned values?
    sorted_ids = sorted(ids)
    ser_ids = b"".join(i.to_bytes(4, byteorder="big", signed=False) for i in sorted_ids)
    return ser_ids


def sign(
    secnonce: bytearray, secshare: bytes, my_id: int, session_ctx: SessionContext
) -> bytes:
    (Q, gacc, _, ids, pubshares, b, R, e) = get_session_values(session_ctx)
    try:
        k_1_ = Scalar.from_bytes_nonzero_checked(bytes(secnonce[0:32]))
    except ValueError:
        raise ValueError("first secnonce value is out of range.")
    try:
        k_2_ = Scalar.from_bytes_nonzero_checked(bytes(secnonce[32:64]))
    except ValueError:
        raise ValueError("second secnonce value is out of range.")
    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:] = bytearray(b"\x00" * 64)
    k_1 = k_1_ if R.has_even_y() else -k_1_
    k_2 = k_2_ if R.has_even_y() else -k_2_
    d_ = int_from_bytes(secshare)
    if not 0 < d_ < GE.ORDER:
        raise ValueError("The signer's secret share value is out of range.")
    P = d_ * G
    assert not P.infinity
    my_pubshare = P.to_bytes_compressed()
    # REVIEW: do we actually need this check? Musig2 embeds pk in secnonce to prevent
    # the wagner's attack related to tweaked pubkeys, but here we don't have that issue.
    # If we don't need to worry about that attack, we remove pubshare from get_session_values
    # return values
    if my_pubshare not in pubshares:
        raise ValueError(
            "The signer's pubshare must be included in the list of pubshares."
        )
    # REVIEW: do we actually need this check?
    if my_id not in ids:
        raise ValueError(
            "The signer's id must be present in the participant identifier list."
        )
    a = derive_interpolating_value(ids, my_id)
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    d = g * gacc * d_
    s = k_1 + b * k_2 + e * a * d
    psig = s.to_bytes()
    R1_partial = k_1_ * G
    R2_partial = k_2_ * G
    assert not R1_partial.infinity
    assert not R2_partial.infinity
    pubnonce = R1_partial.to_bytes_compressed() + R2_partial.to_bytes_compressed()
    # Optional correctness check. The result of signing should pass signature verification.
    assert partial_sig_verify_internal(psig, my_id, pubnonce, my_pubshare, session_ctx)
    return psig


# REVIEW should we hash the signer set (or pubshares) too? Otherwise same nonce will be generate even if the signer set changes
def det_nonce_hash(
    secshare_: bytes, aggothernonce: bytes, tweaked_tpk: bytes, msg: bytes, i: int
) -> bytes:
    buf = b""
    buf += secshare_
    buf += aggothernonce
    buf += tweaked_tpk
    buf += len(msg).to_bytes(8, "big")
    buf += msg
    buf += i.to_bytes(1, "big")
    return tagged_hash("FROST/deterministic/nonce", buf)


COORDINATOR_ID = None


def deterministic_sign(
    secshare: bytes,
    my_id: int,
    aggothernonce: bytes,
    signers_ctx: SignersContext,
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
    rand: Optional[bytes],
) -> Tuple[bytes, bytes]:
    if rand is not None:
        secshare_ = xor_bytes(secshare, tagged_hash("FROST/aux", rand))
    else:
        secshare_ = secshare
    # REVIEW: do we need to add any check for ids & pubshares (in signers_ctx context) here?
    validate_signers_ctx(signers_ctx)
    _, _, _, _, thresh_pk = signers_ctx
    tweaked_tpk = get_xonly_pk(thresh_pubkey_and_tweak(thresh_pk, tweaks, is_xonly))

    k_1 = Scalar.from_bytes_wrapping(
        det_nonce_hash(secshare_, aggothernonce, tweaked_tpk, msg, 0)
    )
    k_2 = Scalar.from_bytes_wrapping(
        det_nonce_hash(secshare_, aggothernonce, tweaked_tpk, msg, 1)
    )
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0

    R1_partial = k_1 * G
    R2_partial = k_2 * G
    assert not R1_partial.infinity
    assert not R2_partial.infinity
    pubnonce = R1_partial.to_bytes_compressed() + R2_partial.to_bytes_compressed()
    secnonce = bytearray(k_1.to_bytes() + k_2.to_bytes())
    try:
        aggnonce = nonce_agg([pubnonce, aggothernonce], [my_id, COORDINATOR_ID])
    except Exception:
        # Since `pubnonce` can never be invalid, blame coordinator's pubnonce.
        # REVIEW: should we introduce an unknown participant or coordinator error?
        raise InvalidContributionError(COORDINATOR_ID, "aggothernonce")
    session_ctx = SessionContext(aggnonce, signers_ctx, tweaks, is_xonly, msg)
    psig = sign(secnonce, secshare, my_id, session_ctx)
    return (pubnonce, psig)


def partial_sig_verify(
    psig: bytes,
    pubnonces: List[bytes],
    signers_ctx: SignersContext,
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
    i: int,
) -> bool:
    validate_signers_ctx(signers_ctx)
    _, _, ids, pubshares, _ = signers_ctx
    if len(pubnonces) != len(ids):
        raise ValueError("The pubnonces and ids arrays must have the same length.")
    if len(tweaks) != len(is_xonly):
        raise ValueError("The tweaks and is_xonly arrays must have the same length.")
    aggnonce = nonce_agg(pubnonces, ids)
    session_ctx = SessionContext(aggnonce, signers_ctx, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(
        psig, ids[i], pubnonces[i], pubshares[i], session_ctx
    )


# REVIEW: catch `cpoint` ValueError and return false
def partial_sig_verify_internal(
    psig: bytes,
    my_id: int,
    pubnonce: bytes,
    pubshare: bytes,
    session_ctx: SessionContext,
) -> bool:
    (Q, gacc, _, ids, pubshares, b, R, e) = get_session_values(session_ctx)
    try:
        s = Scalar.from_bytes_nonzero_checked(psig)
    except ValueError:
        return False
    if pubshare not in pubshares:
        return False
    if my_id not in ids:
        return False
    try:
        R1_partial = GE.from_bytes_compressed(pubnonce[0:33])
        R2_partial = GE.from_bytes_compressed(pubnonce[33:66])
    except ValueError:
        return False
    Re_s_ = R1_partial + b * R2_partial
    Re_s = Re_s_ if R.has_even_y() else -Re_s_
    try:
        P = GE.from_bytes_compressed(pubshare)
    except ValueError:
        return False
    a = derive_interpolating_value(ids, my_id)
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    g_ = g * gacc
    return s * G == Re_s + (e * a * g_) * P


def partial_sig_agg(
    psigs: List[bytes], ids: List[int], session_ctx: SessionContext
) -> bytes:
    assert COORDINATOR_ID not in ids
    if len(psigs) != len(ids):
        raise ValueError("The psigs and ids arrays must have the same length.")
    (Q, _, tacc, _, _, _, R, e) = get_session_values(session_ctx)
    s = Scalar(0)
    for my_id, psig in zip(ids, psigs):
        try:
            s_i = Scalar.from_bytes_checked(psig)
        except ValueError:
            raise InvalidContributionError(my_id, "psig")
        s = s + s_i
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    s = s + e * g * tacc
    return R.to_bytes_xonly() + s.to_bytes()
