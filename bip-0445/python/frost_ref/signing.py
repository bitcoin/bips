# BIP FROST Signing reference implementation
#
# It's worth noting that many functions, types, and exceptions were directly
# copied or modified from the MuSig2 (BIP 327) reference code, found at:
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import List, Optional, Tuple, NewType, NamedTuple, Literal
import secrets

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash, xor_bytes

PlainPk = NewType("PlainPk", bytes)
XonlyPk = NewType("XonlyPk", bytes)
ContribKind = Literal["aggothernonce", "aggnonce", "psig", "pubnonce"]

# Tagged hash domain-separation tags. The challenge tag is inherited from
# BIP340 for signature compatibility; the rest are specific to this BIP.
FROST_TAG_AUX = "BIP0445/aux"
FROST_TAG_NONCE = "BIP0445/nonce"
FROST_TAG_NONCECOEF = "BIP0445/noncecoef"
FROST_TAG_DETERMINISTIC_NONCE = "BIP0445/deterministic/nonce"
BIP340_TAG_CHALLENGE = "BIP0340/challenge"

# Upper bound on the total number of participants n. See the footnote on this
# bound in the BIP text for the security rationale.
MAX_PARTICIPANTS = 128

# There are two types of exceptions that can be raised by this implementation:
#   - ValueError for indicating that an input doesn't conform to some function
#     precondition (e.g. an input array is the wrong length, a serialized
#     representation doesn't have the correct format).
#   - InvalidContributionError for indicating that a signer (or the
#     coordinator) is misbehaving in the protocol.
#
# Byte arrays received from other parties (pubnonces, aggnonce, aggothernonce,
# psigs) are always length-checked. The signer's own inputs are assumed to have
# the lengths the BIP specifies (only nonce_gen and apply_tweak check them).
#
# Assertions are used to (1) satisfy the type-checking system, and (2) check for
# inconvenient events that can't happen except with negligible probability (e.g.
# output of a hash function is 0) and can't be manually triggered by any
# signer.


# This exception is raised if a party (signer or nonce coordinator) sends invalid
# values. Actual implementations should not crash when receiving invalid
# contributions. Instead, they should hold the offending party accountable.
class InvalidContributionError(Exception):
    def __init__(self, signer_index: Optional[int], contrib: ContribKind) -> None:
        # position in ids of the signer who sent the invalid value, or None for coordinator
        self.signer_index = signer_index
        self.contrib = contrib


def has_duplicates(lst: List[int]) -> bool:
    return len(set(lst)) != len(lst)


def derive_interpolating_value(ids: List[int], id_i: int) -> Scalar:
    assert id_i in ids
    assert 0 <= id_i < 2**32
    assert not has_duplicates(ids)
    num = Scalar(1)
    deno = Scalar(1)
    for id_k in ids:
        if id_k == id_i:
            continue
        num *= Scalar(id_k + 1)
        deno *= Scalar(id_k - id_i)
    return num / deno


def derive_pubshare_at(ids: List[int], pubshares: List[GE], x: int) -> GE:
    assert len(ids) == len(pubshares)
    assert not has_duplicates(ids)
    Q = GE()
    for id_i, X_i in zip(ids, pubshares):
        assert 0 <= id_i < 2**32
        num = Scalar(1)
        deno = Scalar(1)
        for id_k in ids:
            if id_k == id_i:
                continue
            num *= Scalar(x - id_k)
            deno *= Scalar(id_i - id_k)
        Q += (num / deno) * X_i
    return Q  # can be infinity


def derive_thresh_pubkey(ids: List[int], pubshares: List[GE]) -> PlainPk:
    # derive_pubshare_at evaluates in identifier space. Identifiers are 0-based,
    # so participant id sits at polynomial x-coordinate id + 1, and the secret,
    # the constant term at x-coordinate 0, is equal to the identifier -1.
    Q = derive_pubshare_at(ids, pubshares, -1)
    if Q.infinity:
        raise ValueError("The threshold public key must not be the point at infinity.")
    return PlainPk(Q.to_bytes_compressed())


class ThresholdInfo(NamedTuple):
    t: int
    thresh_pk: PlainPk
    # List of length n, where the i-th entry belongs to the participant
    # with id = i. A `None` entry means the participant's public share
    # is unavailable.
    pubshares: List[Optional[PlainPk]]


def validate_threshold_info(info: ThresholdInfo) -> None:
    t, thresh_pk, pubshares = info
    n = len(pubshares)

    if not (1 <= t <= n):
        raise ValueError("The threshold must be 1 <= t <= n.")
    if n > MAX_PARTICIPANTS:
        raise ValueError(f"The number of participants must be n <= {MAX_PARTICIPANTS}.")

    # 1. Validate the threshold public key
    # deserializing before interpolating ensures serialization failures
    # are caught before cryptographic inconsistencies.
    try:
        GE.from_bytes_compressed(thresh_pk)
    except ValueError:
        raise ValueError("The thresh_pk is not a valid point.")

    # 2. Extract and parse present public shares
    parsed_shares = []
    for i, pubshare_bytes in enumerate(pubshares):
        if pubshare_bytes is None:
            continue
        try:
            point = GE.from_bytes_compressed(pubshare_bytes)
            parsed_shares.append((i, point))
        except ValueError:
            raise ValueError(f"The pubshare at index {i} is not a valid point.")

    if len(parsed_shares) < t:
        raise ValueError("At least t pubshares must be present.")

    # 3. Establish the base set for polynomial interpolation
    base_ids = [i for i, _ in parsed_shares[:t]]
    base_points = [point for _, point in parsed_shares[:t]]

    # 3.1 Ensure all pubshares shares lie on the same polynomial
    for i, point in parsed_shares[t:]:
        if derive_pubshare_at(base_ids, base_points, i) != point:
            raise ValueError(
                "The provided key material is incorrect: the public shares do not lie on a single polynomial."
            )
    # 3.2 Ensure the derived threshold key matches the provided one
    if derive_thresh_pubkey(base_ids, base_points) != thresh_pk:
        raise ValueError(
            "The provided key material is incorrect: the public shares do not match the threshold public key."
        )


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
    try:
        Q = GE.from_bytes_compressed(thresh_pk)
    except ValueError:
        raise ValueError("The thresh_pk is not a valid point.")
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
        raise ValueError("The tweak value is out of range.")
    Q_ = g * Q + twk * G
    if Q_.infinity:
        raise ValueError(
            "The tweaked threshold public key must not be the point at infinity."
        )
    gacc_ = g * gacc
    tacc_ = twk + g * tacc
    return TweakContext(Q_, gacc_, tacc_)


def nonce_hash(
    rand_: bytes,
    signer_id_: bytes,
    pubshare: PlainPk,
    thresh_pk_xonly: XonlyPk,
    i: int,
    msg_prefixed: bytes,
    extra_in: bytes,
) -> bytes:
    buf = b""
    buf += rand_
    buf += len(signer_id_).to_bytes(1, "big")
    buf += signer_id_
    buf += len(pubshare).to_bytes(1, "big")
    buf += pubshare
    buf += len(thresh_pk_xonly).to_bytes(1, "big")
    buf += thresh_pk_xonly
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, "big")
    buf += extra_in
    buf += i.to_bytes(1, "big")
    return tagged_hash(FROST_TAG_NONCE, buf)


def nonce_gen_internal(
    rand: bytes,
    secshare: Optional[bytes],
    signer_id: Optional[int],
    pubshare: Optional[PlainPk],
    thresh_pk_xonly: Optional[XonlyPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None:
        rand_ = xor_bytes(secshare, tagged_hash(FROST_TAG_AUX, rand))
    else:
        rand_ = rand
    if signer_id is None:
        signer_id_ = b""
    else:
        signer_id_ = signer_id.to_bytes(4, "big")
    if pubshare is None:
        pubshare = PlainPk(b"")
    if thresh_pk_xonly is None:
        thresh_pk_xonly = XonlyPk(b"")
    if msg is None:
        msg_prefixed = b"\x00"
    else:
        msg_prefixed = b"\x01"
        msg_prefixed += len(msg).to_bytes(8, "big")
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b""
    k_1 = Scalar.from_bytes_wrapping(
        nonce_hash(
            rand_, signer_id_, pubshare, thresh_pk_xonly, 0, msg_prefixed, extra_in
        )
    )
    k_2 = Scalar.from_bytes_wrapping(
        nonce_hash(
            rand_, signer_id_, pubshare, thresh_pk_xonly, 1, msg_prefixed, extra_in
        )
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


def nonce_gen(
    secshare: Optional[bytes],
    signer_id: Optional[int],
    pubshare: Optional[PlainPk],
    thresh_pk_xonly: Optional[XonlyPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None and len(secshare) != 32:
        raise ValueError("The optional secshare must be a 32-byte array.")
    if signer_id is not None and not 0 <= signer_id <= 2**32 - 1:
        raise ValueError("The optional signer_id must be a 4-byte integer.")
    if pubshare is not None and len(pubshare) != 33:
        raise ValueError("The optional pubshare must be a 33-byte array.")
    if thresh_pk_xonly is not None and len(thresh_pk_xonly) != 32:
        raise ValueError("The optional thresh_pk_xonly must be a 32-byte array.")
    rand = secrets.token_bytes(32)
    return nonce_gen_internal(
        rand, secshare, signer_id, pubshare, thresh_pk_xonly, msg, extra_in
    )


def nonce_agg(pubnonces: List[bytes]) -> bytes:
    for idx, pubnonce in enumerate(pubnonces):
        if len(pubnonce) != 66:
            raise ValueError(f"The pubnonce at index {idx} must be a 66-byte array.")
    aggnonce = b""
    for j in (1, 2):
        R_j = GE()
        for idx, pubnonce in enumerate(pubnonces):
            try:
                R_ij = GE.from_bytes_compressed(pubnonce[(j - 1) * 33 : j * 33])
            except ValueError:
                raise InvalidContributionError(idx, "pubnonce")
            R_j += R_ij
        aggnonce += R_j.to_bytes_compressed_with_infinity()
    return aggnonce


class SessionContext(NamedTuple):
    n: int
    t: int
    ids: List[int]  # u signer ids
    pubshares: Optional[List[PlainPk]]  # u signer pubshares, or None if unknown
    thresh_pk: PlainPk
    aggnonce: bytes
    tweaks: List[bytes]
    is_xonly: List[bool]
    msg: bytes


def thresh_pubkey_and_tweak(
    thresh_pk: PlainPk, tweaks: List[bytes], is_xonly: List[bool]
) -> TweakContext:
    if len(tweaks) != len(is_xonly):
        raise ValueError("The tweaks and is_xonly lists must have the same length.")
    tweak_ctx = tweak_ctx_init(thresh_pk)
    v = len(tweaks)
    for i in range(v):
        tweak_ctx = apply_tweak(tweak_ctx, tweaks[i], is_xonly[i])
    return tweak_ctx


def validate_session_params(
    n: int,
    t: int,
    ids: List[int],
    pubshares: Optional[List[PlainPk]],
    thresh_pk: PlainPk,
) -> None:
    if not (1 <= t <= n):
        raise ValueError("The threshold must be 1 <= t <= n.")
    if n > MAX_PARTICIPANTS:
        raise ValueError(f"The number of participants must be n <= {MAX_PARTICIPANTS}.")
    if not (t <= len(ids) <= n):
        raise ValueError("The number of signers must satisfy t <= u <= n.")
    if pubshares is not None and len(pubshares) != len(ids):
        raise ValueError("The pubshares and ids lists must have the same length.")
    # ensure all pubshares and ids are within the valid range
    pubshare_points = []
    for idx, id_i in enumerate(ids):
        if not 0 <= id_i <= n - 1:
            raise ValueError(f"The id at index {idx} must satisfy 0 <= id <= n - 1.")
        if pubshares is not None:
            try:
                pubshare_points.append(GE.from_bytes_compressed(pubshares[idx]))
            except ValueError:
                raise ValueError(f"The pubshare at index {idx} is not a valid point.")
    if has_duplicates(ids):
        raise ValueError("The ids list contains duplicate elements.")
    # ensure that the derived threshold public key matches the provided one
    if (
        pubshares is not None
        and derive_thresh_pubkey(ids, pubshare_points) != thresh_pk
    ):
        raise ValueError(
            "The provided key material is incorrect: the public shares do not match the threshold public key."
        )


def get_session_values(
    session_ctx: SessionContext,
) -> Tuple[GE, Scalar, Scalar, List[int], Optional[List[PlainPk]], Scalar, GE, Scalar]:
    (n, t, ids, pubshares, thresh_pk, aggnonce, tweaks, is_xonly, msg) = session_ctx
    validate_session_params(n, t, ids, pubshares, thresh_pk)
    Q, gacc, tacc = thresh_pubkey_and_tweak(thresh_pk, tweaks, is_xonly)
    if len(aggnonce) != 66:
        raise ValueError("The aggnonce must be a 66-byte array.")
    # the signers are a set, so serialize_ids sorts to keep b independent of ids order
    ser_ids = serialize_ids(ids)
    b = Scalar.from_bytes_wrapping(
        tagged_hash(
            FROST_TAG_NONCECOEF,
            len(ids).to_bytes(4, "big") + ser_ids + aggnonce + Q.to_bytes_xonly() + msg,
        )
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
        tagged_hash(BIP340_TAG_CHALLENGE, R.to_bytes_xonly() + Q.to_bytes_xonly() + msg)
    )
    assert e != 0
    return (Q, gacc, tacc, ids, pubshares, b, R, e)


def serialize_ids(ids: List[int]) -> bytes:
    sorted_ids = sorted(ids)
    ser_ids = b"".join(i.to_bytes(4, byteorder="big", signed=False) for i in sorted_ids)
    return ser_ids


def sign(
    secnonce: bytearray, secshare: bytes, signer_id: int, session_ctx: SessionContext
) -> bytes:
    (Q, gacc, _, ids, pubshares, b, R, e) = get_session_values(session_ctx)
    try:
        k_1_ = Scalar.from_bytes_nonzero_checked(bytes(secnonce[0:32]))
    except ValueError:
        raise ValueError("The first half of secnonce is out of range.")
    try:
        k_2_ = Scalar.from_bytes_nonzero_checked(bytes(secnonce[32:64]))
    except ValueError:
        raise ValueError("The second half of secnonce is out of range.")
    # Overwrite the secnonce argument with zeros, so the subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:] = bytearray(b"\x00" * 64)
    k_1 = k_1_ if R.has_even_y() else -k_1_
    k_2 = k_2_ if R.has_even_y() else -k_2_
    try:
        d_ = Scalar.from_bytes_nonzero_checked(secshare)
    except ValueError:
        raise ValueError("The secshare is out of range.")
    P = d_ * G
    assert not P.infinity
    signer_pubshare = P.to_bytes_compressed()
    if signer_id not in ids:
        raise ValueError("The signer's id is missing from the ids list.")
    if pubshares is not None and pubshares[ids.index(signer_id)] != signer_pubshare:
        raise ValueError(
            "The signer's pubshare does not match its entry in the pubshares list."
        )
    a = derive_interpolating_value(ids, signer_id)
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
    assert partial_sig_verify_internal(
        psig, signer_id, pubnonce, signer_pubshare, session_ctx
    )
    return psig


def det_nonce_hash(
    masked_secshare: bytes,
    signer_id: int,
    ids: List[int],
    aggothernonce: bytes,
    tweaked_thresh_pk_xonly: bytes,
    msg: bytes,
    i: int,
) -> bytes:
    buf = b""
    buf += masked_secshare
    buf += signer_id.to_bytes(4, "big")
    buf += len(ids).to_bytes(4, "big")
    buf += serialize_ids(ids)
    buf += len(aggothernonce).to_bytes(1, "big")
    buf += aggothernonce
    buf += tweaked_thresh_pk_xonly
    buf += len(msg).to_bytes(8, "big")
    buf += msg
    buf += i.to_bytes(1, "big")
    return tagged_hash(FROST_TAG_DETERMINISTIC_NONCE, buf)


def deterministic_sign(
    secshare: bytes,
    signer_id: int,
    aggothernonce: Optional[bytes],
    n: int,
    t: int,
    ids: List[int],
    pubshares: Optional[List[PlainPk]],
    thresh_pk: PlainPk,
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
    aux_rand: Optional[bytes],
) -> Tuple[bytes, bytes]:
    validate_session_params(n, t, ids, pubshares, thresh_pk)
    # aggothernonce is omitted if and only if there is a sole signer (u = 1). A sole
    # signer hashes the empty byte string and uses its own pubnonce as the aggnonce.
    if len(ids) == 1 and aggothernonce is not None:
        raise ValueError("The aggothernonce must be omitted when u = 1.")
    if len(ids) > 1 and (aggothernonce is None or len(aggothernonce) != 66):
        raise ValueError(
            "The aggothernonce must be present and a 66-byte array when u > 1."
        )
    tweak_ctx = thresh_pubkey_and_tweak(thresh_pk, tweaks, is_xonly)
    Q, gacc, _ = tweak_ctx
    tweaked_thresh_pk_xonly = get_xonly_pk(tweak_ctx)
    try:
        d_ = Scalar.from_bytes_nonzero_checked(secshare)
    except ValueError:
        raise ValueError("The secshare is out of range.")
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    # hash the possibly negated secshare, so the nonce binds to g * gacc
    d = g * gacc * d_
    if aux_rand is not None:
        masked_secshare = xor_bytes(d.to_bytes(), tagged_hash(FROST_TAG_AUX, aux_rand))
    else:
        masked_secshare = d.to_bytes()

    if aggothernonce is None:
        aggothernonce_ = b""
    else:
        aggothernonce_ = aggothernonce

    k_1 = Scalar.from_bytes_wrapping(
        det_nonce_hash(
            masked_secshare,
            signer_id,
            ids,
            aggothernonce_,
            tweaked_thresh_pk_xonly,
            msg,
            0,
        )
    )
    k_2 = Scalar.from_bytes_wrapping(
        det_nonce_hash(
            masked_secshare,
            signer_id,
            ids,
            aggothernonce_,
            tweaked_thresh_pk_xonly,
            msg,
            1,
        )
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
    if aggothernonce is None:
        aggnonce = pubnonce
    else:
        try:
            aggnonce = nonce_agg([pubnonce, aggothernonce])
        except InvalidContributionError:
            # pubnonce is always valid, so any failure is due to aggothernonce.
            raise InvalidContributionError(None, "aggothernonce")
    session_ctx = SessionContext(
        n, t, ids, pubshares, thresh_pk, aggnonce, tweaks, is_xonly, msg
    )
    psig = sign(secnonce, secshare, signer_id, session_ctx)
    return (pubnonce, psig)


def partial_sig_verify(
    psig: bytes,
    pubnonces: List[bytes],
    n: int,
    t: int,
    ids: List[int],
    pubshares: List[PlainPk],
    thresh_pk: PlainPk,
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
    i: int,
) -> bool:
    if len(pubnonces) != len(ids) or len(pubshares) != len(ids):
        raise ValueError(
            "The pubnonces, pubshares and ids lists must have the same length."
        )
    if not 0 <= i < len(ids):
        raise ValueError("The signer index must satisfy 0 <= i <= u - 1.")
    if len(tweaks) != len(is_xonly):
        raise ValueError("The tweaks and is_xonly lists must have the same length.")
    validate_session_params(n, t, ids, pubshares, thresh_pk)
    aggnonce = nonce_agg(pubnonces)
    session_ctx = SessionContext(
        n, t, ids, pubshares, thresh_pk, aggnonce, tweaks, is_xonly, msg
    )
    return partial_sig_verify_internal(
        psig, ids[i], pubnonces[i], pubshares[i], session_ctx
    )


def partial_sig_verify_internal(
    psig: bytes,
    signer_id: int,
    pubnonce: bytes,
    pubshare: bytes,
    session_ctx: SessionContext,
) -> bool:
    (Q, gacc, _, ids, _, b, R, e) = get_session_values(session_ctx)
    if len(psig) != 32:
        return False
    try:
        s = Scalar.from_bytes_checked(psig)
    except ValueError:
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
    a = derive_interpolating_value(ids, signer_id)
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    g_ = g * gacc
    return s * G == Re_s + (e * a * g_) * P


def partial_sig_agg(psigs: List[bytes], session_ctx: SessionContext) -> bytes:
    (Q, _, tacc, ids, _, _, R, e) = get_session_values(session_ctx)
    if len(psigs) != len(ids):
        raise ValueError("The psigs and ids lists must have the same length.")
    for idx, psig in enumerate(psigs):
        if len(psig) != 32:
            raise ValueError(f"The psig at index {idx} must be a 32-byte array.")
    s = Scalar(0)
    for idx, psig in enumerate(psigs):
        try:
            s_i = Scalar.from_bytes_checked(psig)
        except ValueError:
            raise InvalidContributionError(idx, "psig")
        s += s_i
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    s += e * g * tacc
    return R.to_bytes_xonly() + s.to_bytes()
