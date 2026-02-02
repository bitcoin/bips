# BIPXXX reference implementation
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import Dict, Mapping, Optional, Sequence, Tuple, NewType, NamedTuple, List, Callable, Any, cast
import hashlib
import json
import os
import secrets
import sys

from bip32 import (
    CURVE_N,
    ExtendedPublicKey,
    apply_tweak_to_public,
    apply_tweak_to_secret,
    int_to_bytes,
    parse_extended_public_key,
    compress_point,
    decode_path,
)
from descriptor import SortedMultiDescriptorTemplate 

from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import G, GE, Scalar

HashFunc = Callable[[bytes], Any]

PlainPk = NewType('PlainPk', bytes)
XonlyPk = NewType('XonlyPk', bytes)

def xbytes(P: GE) -> bytes:
    return P.to_bytes_xonly()

def cbytes(P: GE) -> bytes:
    return P.to_bytes_compressed()

def cpoint(x: bytes) -> GE:
    return GE.from_bytes_compressed(x)

TweakContext = NamedTuple('TweakContext', [('Q', GE),
                                           ('gacc', Scalar),
                                           ('tacc', Scalar)])

def tweak_ctx_init(pk: PlainPk) -> TweakContext:
    Q = cpoint(pk)
    if Q.infinity:
        raise ValueError('The public key cannot be infinity.')
    gacc = Scalar(1)
    tacc = Scalar(0)
    return TweakContext(Q, gacc, tacc)

def apply_tweak(tweak_ctx: TweakContext, tweak: bytes, is_xonly: bool) -> TweakContext:
    if len(tweak) != 32:
        raise ValueError('The tweak must be a 32-byte array.')
    Q, gacc, tacc = tweak_ctx
    if is_xonly and not Q.has_even_y():
        g = Scalar(-1)
    else:
        g = Scalar(1)
    try:
        t = Scalar.from_bytes_checked(tweak)
    except ValueError:
        raise ValueError('The tweak must be less than n.')
    Q_ = g * Q + t * G
    if Q_.infinity:
        raise ValueError('The result of tweaking cannot be infinity.')
    gacc_ = g * gacc
    tacc_ = t + g * tacc
    return TweakContext(Q_, gacc_, tacc_)

# Return the plain public key corresponding to a given secret key
def individual_pk(seckey: bytes) -> PlainPk:
    return PlainPk(pubkey_gen_plain(seckey))

def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def tagged_hash(tag: str, msg: bytes, hash_func: HashFunc = hashlib.sha256) -> bytes:
    tag_hash = hash_func(tag.encode()).digest()
    return hash_func(tag_hash + tag_hash + msg).digest()

def nonce_hash(rand: bytes, pk: PlainPk, extra_in: bytes) -> bytes:
    buf = b''
    buf += rand
    buf += len(pk).to_bytes(1, 'big')
    buf += pk
    buf += len(extra_in).to_bytes(4, 'big')
    buf += extra_in
    return tagged_hash('CCD/blindnonce', buf)

def blind_nonce_gen_internal(rand_: bytes, sk: Optional[bytes], pk: Optional[PlainPk], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None:
        rand = bytes_xor(sk, tagged_hash('CCD/aux', rand_))
    else:
        rand = rand_
    if pk is None:
        pk = PlainPk(b'')
    if extra_in is None:
        extra_in = b''
    k = Scalar.from_bytes_wrapping(nonce_hash(rand, pk, extra_in))
    # k == 0 cannot occur except with negligible probability.
    assert k != 0
    R = k * G
    assert R is not None
    blindpubnonce = cbytes(R)
    blindsecnonce = bytearray(k.to_bytes() + pk)
    return blindsecnonce, blindpubnonce

def blind_nonce_gen(sk: Optional[bytes], pk: Optional[PlainPk], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None and len(sk) != 32:
        raise ValueError('The optional byte array sk must have length 32.')
    rand_ = secrets.token_bytes(32)
    return blind_nonce_gen_internal(rand_, sk, pk, extra_in)

SessionContext = NamedTuple('SessionContext', [('pk', PlainPk),
                                               ('blindfactor', bytes),
                                               ('challenge', bytes),
                                               ('pubnonce', bytes),
                                               ('tweaks', List[bytes]),
                                               ('is_xonly', List[bool])])

def blind_factor_hash(rand: bytes, cpk: PlainPk, blindpubnonce: bytes, msg: bytes, extra_in: bytes) -> bytes:
    buf = b''
    buf += rand
    buf += len(cpk).to_bytes(1, 'big')
    buf += cpk
    buf += len(blindpubnonce).to_bytes(1, 'big')
    buf += blindpubnonce
    buf += len(msg).to_bytes(8, 'big')
    buf += msg
    buf += len(extra_in).to_bytes(4, 'big')
    buf += extra_in
    return tagged_hash('CCD/blindfactor', buf, hashlib.sha512)

def blind_challenge_gen_internal(rand: bytes, msg: bytes, blindpubnonce: bytes, pk: PlainPk, tweaks: List[bytes], is_xonly: List[bool], extra_in: Optional[bytes]) -> Tuple[SessionContext, bytes, bool, bool]:
    if extra_in is None:
        extra_in = b''
    Q, gacc, tacc = pubkey_and_tweak(pk, tweaks, is_xonly)
    cpk = PlainPk(cbytes(Q))
    k = blind_factor_hash(rand, cpk, blindpubnonce, msg, extra_in)
    a_ = Scalar.from_bytes_wrapping(k[0:32])
    assert a_ != 0
    b_ = Scalar.from_bytes_wrapping(k[32:64])
    assert b_ != 0

    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    pk_parity = g * gacc == 1
    X_ = cpoint(pk)
    X = X_ if pk_parity else -X_

    R_ = cpoint(blindpubnonce)
    R = R_ + (a_ * G) + (b_ * X)
    if R is None:
        raise ValueError('The result of nonce blinding cannot be infinity.')
    nonce_parity = R.has_even_y()
    if not nonce_parity:
        a = -a_
        b = -b_
    else:
        a = a_
        b = b_

    e = Scalar.from_bytes_wrapping(tagged_hash("BIP0340/challenge", xbytes(R) + xbytes(Q) + msg))
    e_ = e + b

    session_ctx = SessionContext(pk, a.to_bytes(), e.to_bytes(), cbytes(R), tweaks, is_xonly)
    return session_ctx, e_.to_bytes(), pk_parity, nonce_parity

def blind_challenge_gen(msg: bytes, blindpubnonce: bytes, pk: PlainPk, tweaks: List[bytes], is_xonly: List[bool], extra_in: Optional[bytes]) -> Tuple[SessionContext, bytes, bool, bool]:
    rand = secrets.token_bytes(32)
    return blind_challenge_gen_internal(rand, msg, blindpubnonce, pk, tweaks, is_xonly, extra_in)

def blind_sign(sk: bytes, blindchallenge: bytes, blindsecnonce: bytearray, pk_parity: bool, nonce_parity: bool) -> bytes:
    try:
        d_ = Scalar.from_bytes_checked(sk)
        if d_ == 0:
            raise ValueError('The secret key cannot be zero.')
    except ValueError:
        raise ValueError('The secret key is out of range.')
    P = d_ * G
    if P.infinity:
        raise ValueError('The public key cannot be infinity.')
    d = d_ if pk_parity else -d_
    e_ = Scalar.from_bytes_checked(blindchallenge)
    k_ = Scalar.from_bytes_checked(bytes(blindsecnonce[0:32]))
    k = k_ if nonce_parity else -k_
    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    blindsecnonce[:64] = bytearray(b'\x00'*64)
    R_ = k_ * G
    if R_.infinity:
        raise ValueError('The blindpubnonce cannot be infinity.')
    s_ = k + (e_ * d)
    pk = PlainPk(cbytes(P))
    blindsignature = s_.to_bytes()
    assert verify_blind_signature(pk, cbytes(R_), blindchallenge, blindsignature, pk_parity, nonce_parity)
    return blindsignature

def verify_blind_signature(pk: PlainPk, blindpubnonce: bytes, blindchallenge: bytes, blindsignature: bytes, pk_parity: bool, nonce_parity: bool) -> bool:
    P_ = cpoint(pk)
    P = P_ if pk_parity else -P_
    if P.infinity:
        raise ValueError('The public key cannot be infinity.')
    R_ = cpoint(blindpubnonce)
    R = R_ if nonce_parity else -R_
    e_ = Scalar.from_bytes_checked(blindchallenge)
    s_ = Scalar.from_bytes_checked(blindsignature)
    R_calc = (s_ * G) + (-e_ * P)
    if R_calc.infinity:
        return False
    return R == R_calc

def pubkey_and_tweak(pk: PlainPk, tweaks: List[bytes], is_xonly: List[bool]) -> TweakContext:
    if len(tweaks) != len(is_xonly):
        raise ValueError('The tweaks and is_xonly arrays must have the same length.')
    tweak_ctx = tweak_ctx_init(pk)
    v = len(tweaks)
    for i in range(v):
        tweak_ctx = apply_tweak(tweak_ctx, tweaks[i], is_xonly[i])
    return tweak_ctx

def get_session_values(session_ctx: SessionContext) -> Tuple[GE, Scalar, Scalar, GE, Scalar, Scalar]:
    (pk, blindfactor, challenge, pubnonce, tweaks, is_xonly) = session_ctx
    Q, gacc, tacc = pubkey_and_tweak(pk, tweaks, is_xonly)
    a = Scalar.from_bytes_checked(blindfactor)
    e = Scalar.from_bytes_checked(challenge)
    R = cpoint(pubnonce)
    return Q, a, e, R, gacc, tacc

def unblind_signature(session_ctx: SessionContext, blindsignature: bytes) -> bytes:
    Q, a, e, R, gacc, tacc = get_session_values(session_ctx)
    s_ = Scalar.from_bytes_checked(blindsignature)
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    s = s_ + a + (e * g * tacc)
    return xbytes(R) + s.to_bytes()

#
# The following code is only used for testing.
#

def hx(s: str) -> bytes:
    return bytes.fromhex(s)

def fromhex_all(l):  # noqa: E741
    return [hx(l_i) for l_i in l]


def get_error_details(tc):
    et = tc["error"]["type"]
    # Resolve to real class from name
    exc_cls = getattr(__builtins__, et, None) or getattr(__import__("builtins"), et)
    # Optional message predicate
    msg = tc["error"].get("message")
    if msg is None:
        return exc_cls, (lambda e: True)
    return exc_cls, (lambda e: msg in str(e))

def assert_raises(exc_cls, fn, pred):
    try:
        fn()
    except Exception as e:
        assert isinstance(e, exc_cls), f"Raised {type(e).__name__}, expected {exc_cls.__name__}"
        assert pred(e), f"Exception message predicate failed: {e}"
        return
    assert False, f"Expected {exc_cls.__name__} but no exception was raised"

def build_session_ctx(obj):
    pk = PlainPk(bytes.fromhex(obj["pk"]))
    a = bytes.fromhex(obj["blindfactor"])
    e = bytes.fromhex(obj["challenge"])
    R = bytes.fromhex(obj["pubnonce"])
    tweaks = fromhex_all(obj["tweaks"])
    is_xonly = obj["is_xonly"]
    return (pk, a, e, R, tweaks, is_xonly)

def test_blind_nonce_gen_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'blind_nonce_gen_vectors.json')) as f:
        tv = json.load(f)

    for tc in tv["test_cases"]:
        def get_bytes(key) -> bytes:
            return bytes.fromhex(tc[key])

        def get_bytes_maybe(key) -> Optional[bytes]:
            v = tc.get(key)
            return None if v is None else bytes.fromhex(v)

        rand_ = get_bytes("rand_")
        sk = get_bytes_maybe("sk")
        pk = get_bytes_maybe("pk")
        if pk is not None:
            pk = PlainPk(pk)
        extra_in = get_bytes_maybe("extra_in")

        expected_blindsecnonce = get_bytes("expected_blindsecnonce")
        expected_blindpubnonce = get_bytes("expected_blindpubnonce")

        blindsecnonce, blindpubnonce = blind_nonce_gen_internal(rand_, sk, pk, extra_in)

        assert bytes(blindsecnonce) == expected_blindsecnonce
        assert blindpubnonce == expected_blindpubnonce

        pk_len = 0 if tc["pk"] is None else 33
        assert len(expected_blindsecnonce) == 32 + pk_len
        assert len(expected_blindpubnonce) == 33

def test_blind_challenge_gen_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'blind_challenge_gen_vectors.json')) as f:
        tv = json.load(f)

    # ---------- Valid cases ----------
    for tc in tv["test_cases"]:
        rand = bytes.fromhex(tc["rand"])
        msg = bytes.fromhex(tc["msg"]) if tc["msg"] != "" else b""
        blindpubnonce = bytes.fromhex(tc["blindpubnonce"])
        pk = PlainPk(bytes.fromhex(tc["pk"]))
        tweaks = fromhex_all(tc["tweaks"])
        is_xonly = tc["is_xonly"]
        extra_in = None if tc["extra_in"] is None else bytes.fromhex(tc["extra_in"])

        expected_a = bytes.fromhex(tc["expected_blindfactor"])
        expected_e = bytes.fromhex(tc["expected_challenge"])
        expected_R = bytes.fromhex(tc["expected_pubnonce"])
        expected_e_prime = bytes.fromhex(tc["expected_blindchallenge"])
        expected_pk_parity = bool(tc["expected_pk_parity"])
        expected_nonce_parity = bool(tc["expected_nonce_parity"])

        session_ctx, blindchallenge, pk_parity, nonce_parity = blind_challenge_gen_internal(
            rand, msg, blindpubnonce, pk, tweaks, is_xonly, extra_in
        )

        # Check tuple outputs
        assert blindchallenge == expected_e_prime
        assert pk_parity == expected_pk_parity
        assert nonce_parity == expected_nonce_parity

        # Check session_ctx fields
        pk_sc, blindfactor_sc, challenge_sc, pubnonce_sc, tweaks_sc, is_xonly_sc = session_ctx
        assert pk_sc == pk
        assert blindfactor_sc == expected_a
        assert challenge_sc == expected_e
        assert pubnonce_sc == expected_R
        assert tweaks_sc == tweaks
        assert is_xonly_sc == is_xonly

        # Extra sanity: recompute Q and e and compare
        Q, gacc, tacc = pubkey_and_tweak(pk, tweaks, is_xonly)
        R = cpoint(expected_R)
        e_check = tagged_hash("BIP0340/challenge", xbytes(R) + xbytes(Q) + msg)
        assert e_check == expected_e

        # Length sanity
        assert len(expected_a) == 32
        assert len(expected_e) == 32
        assert len(expected_R) == 33
        assert len(expected_e_prime) == 32

    # ---------- Error cases ----------
    for tc in tv.get("error_test_cases", []):
        rand = bytes.fromhex(tc["rand"])
        msg = bytes.fromhex(tc["msg"]) if tc["msg"] != "" else b""
        blindpubnonce = bytes.fromhex(tc["blindpubnonce"])
        pk = PlainPk(bytes.fromhex(tc["pk"]))
        tweaks = fromhex_all(tc["tweaks"])
        is_xonly = tc["is_xonly"]
        extra_in = None if tc["extra_in"] is None else bytes.fromhex(tc["extra_in"])

        err = tc["error"]
        err_type = err["type"]
        err_message = err.get("message")

        raised = False
        try:
            _ = blind_challenge_gen_internal(rand, msg, blindpubnonce, pk, tweaks, is_xonly, extra_in)
        except Exception as e:
            raised = True
            # Type check
            assert e.__class__.__name__ == err_type
            # Optional substring match on message, if provided
            if err_message is not None:
                assert err_message in str(e)
        assert raised, "Expected an exception but none was raised"

def test_blind_sign_and_verify_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'blind_sign_and_verify_vectors.json')) as f:
        tv = json.load(f)

    # ------------------ Valid ------------------
    for test_case in tv["valid_test_cases"]:
        sk = hx(test_case["sk"])
        pk = PlainPk(hx(test_case["pk"]))
        blindsecnonce_all = hx(test_case["blindsecnonce"])
        blindpubnonce = hx(test_case["blindpubnonce"])
        blindchallenge = hx(test_case["blindchallenge"])
        pk_parity = bool(test_case["pk_parity"])
        nonce_parity = bool(test_case["nonce_parity"])

        # R' consistency check: cbytes(k'*G) == blindpubnonce
        k_ = Scalar.from_bytes_checked(blindsecnonce_all[0:32])
        R_prime = k_ * G
        assert cbytes(R_prime) == blindpubnonce

        expected_sprime = hx(test_case["expected"]["blindsignature"])

        # Copy because blind_sign zeroizes the first 64 bytes of the buffer
        secnonce_buf = bytearray(blindsecnonce_all)
        s_prime = blind_sign(sk, blindchallenge, secnonce_buf, pk_parity, nonce_parity)
        assert s_prime == expected_sprime

        checks = test_case.get("checks", {})
        if checks.get("secnonce_prefix_zeroed_after_sign", False):
            assert all(b == 0 for b in secnonce_buf[:64])

        if checks.get("verify_returns_true", True):
            ok = verify_blind_signature(pk, blindpubnonce, blindchallenge, s_prime, pk_parity, nonce_parity)
            assert ok is True

        if checks.get("second_call_raises_valueerror", False):
            # Reuse the same (now zeroized) buffer; must raise
            def try_again():
                blind_sign(sk, blindchallenge, secnonce_buf, pk_parity, nonce_parity)
            raised = False
            try:
                try_again()
            except ValueError:
                raised = True
            assert raised, "Expected ValueError on nonce reuse"

    # ------------------ Sign errors (exceptions) ------------------
    for test_case in tv.get("sign_error_test_cases", []):
        exception, except_fn = get_error_details(test_case)

        sk = hx(test_case["sk"])
        blindsecnonce_all = hx(test_case["blindsecnonce"])
        blindchallenge = hx(test_case["blindchallenge"])
        pk_parity = bool(test_case["pk_parity"])
        nonce_parity = bool(test_case["nonce_parity"])
        repeat = int(test_case.get("repeat", 1))

        if repeat == 1:
            # Single-call error (e.g., out-of-range e')
            assert_raises(exception, lambda: blind_sign(sk, blindchallenge, bytearray(blindsecnonce_all), pk_parity, nonce_parity), except_fn)
        else:
            # Two-call error (nonce reuse)
            buf = bytearray(blindsecnonce_all)
            # First call should succeed
            _ = blind_sign(sk, blindchallenge, buf, pk_parity, nonce_parity)
            # Second call must raise
            assert_raises(exception, lambda: blind_sign(sk, blindchallenge, buf, pk_parity, nonce_parity), except_fn)

    # ------------------ Verify returns False (no exception) ------------------
    for test_case in tv.get("verify_fail_test_cases", []):
        pk = PlainPk(hx(test_case["pk"]))
        blindpubnonce = hx(test_case["blindpubnonce"])
        blindchallenge = hx(test_case["blindchallenge"])
        blindsignature = hx(test_case["blindsignature"])
        pk_parity = bool(test_case["pk_parity"])
        nonce_parity = bool(test_case["nonce_parity"])

        assert verify_blind_signature(pk, blindpubnonce, blindchallenge, blindsignature, pk_parity, nonce_parity) is False

    # ------------------ Verify errors (exceptions) ------------------
    for test_case in tv.get("verify_error_test_cases", []):
        exception, except_fn = get_error_details(test_case)

        pk = PlainPk(hx(test_case["pk"]))
        blindpubnonce = hx(test_case["blindpubnonce"])
        blindchallenge = hx(test_case["blindchallenge"])
        blindsignature = hx(test_case["blindsignature"])
        pk_parity = bool(test_case["pk_parity"])
        nonce_parity = bool(test_case["nonce_parity"])

        assert_raises(exception, lambda: verify_blind_signature(pk, blindpubnonce, blindchallenge, blindsignature, pk_parity, nonce_parity), except_fn)

def test_unblind_signature_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'unblind_signature_vectors.json')) as f:
        tv = json.load(f)

    # ---------- Valid ----------
    for tc in tv["valid_test_cases"]:
        session_ctx = build_session_ctx(tc["session_ctx"])
        msg = bytes.fromhex(tc["msg"]) if tc["msg"] != "" else b""
        blindsignature = bytes.fromhex(tc["blindsignature"])
        expected_sig = bytes.fromhex(tc["expected_bip340_sig"])

        sig = unblind_signature(session_ctx, blindsignature)
        assert sig == expected_sig

        # Verify BIP340 with tweaked Q
        pk, _, _, _, tweaks, is_xonly = session_ctx
        Q, _, _ = pubkey_and_tweak(pk, tweaks, is_xonly)
        assert schnorr_verify(msg, xbytes(Q), sig)

    # ---------- Errors ----------
    for tc in tv.get("error_test_cases", []):
        session_ctx = build_session_ctx(tc["session_ctx"])
        msg = bytes.fromhex(tc["msg"]) if tc["msg"] != "" else b""
        blindsignature = bytes.fromhex(tc["blindsignature"])

        err = tc["error"]
        err_type = err["type"]
        err_msg = err.get("message")

        raised = False
        try:
            _ = unblind_signature(session_ctx, blindsignature)
        except Exception as e:
            raised = True
            assert e.__class__.__name__ == err_type
            if err_msg is not None:
                assert err_msg in str(e)
        assert raised, "Expected an exception but none was raised"

def test_sign_and_verify_random(iters: int) -> None:
    for _ in range(iters):
        sk = Scalar.from_bytes_wrapping(secrets.token_bytes(32))
        pk = individual_pk(sk.to_bytes())
        msg = Scalar.from_bytes_wrapping(secrets.token_bytes(32))
        v = secrets.randbelow(4)
        tweaks = [secrets.token_bytes(32) for _ in range(v)]
        tweak_modes = [secrets.choice([False, True]) for _ in range(v)]
        Q, _, _ = pubkey_and_tweak(pk, tweaks, tweak_modes)
        assert not Q.infinity

        # Round 1
        # Signer
        extra_in_1 = secrets.token_bytes(32)
        blindsecnonce, blindpubnonce = blind_nonce_gen(sk.to_bytes(), pk, extra_in_1)
        # User
        extra_in_2 = secrets.token_bytes(32)
        session_ctx, blindchallenge, pk_parity, nonce_parity = blind_challenge_gen(msg.to_bytes(), blindpubnonce, pk, tweaks, tweak_modes, extra_in_2)

        # Round 2
        # Signer
        blindsignature = blind_sign(sk.to_bytes(), blindchallenge, blindsecnonce, pk_parity, nonce_parity)
        # User
        sig = unblind_signature(session_ctx, blindsignature)
        assert schnorr_verify(msg.to_bytes(), xbytes(Q), sig)

def compute_bip32_tweak(xpub: ExtendedPublicKey, path: Sequence[int]) -> Tuple[int, ExtendedPublicKey]:
    """Compute the CCD tweak scalar for a non-hardened derivation path."""

    aggregate = 0
    current = xpub
    for index in path:
        tweak, child = current.derive_child(index)
        aggregate = (aggregate + tweak) % CURVE_N
        current = child
    return aggregate, current

def input_verification(
    descriptor_template: SortedMultiDescriptorTemplate,
    witness_script: Optional[bytes],
    tweaks: Mapping[bytes, int],
) -> bool:
    """Check that an input script matches the tweaked policy from CCD data."""

    return _verify_tweaked_descriptor(
        descriptor_template,
        witness_script,
        tweaks,
    )


def change_output_verification(
    descriptor_template: SortedMultiDescriptorTemplate,
    witness_script: Optional[bytes],
    tweaks: Mapping[bytes, int],
) -> bool:
    """Validate a change output script using delegated CCD tweak data."""

    return _verify_tweaked_descriptor(
        descriptor_template,
        witness_script,
        tweaks,
    )


def _verify_tweaked_descriptor(
    descriptor_template: SortedMultiDescriptorTemplate,
    witness_script: Optional[bytes],
    tweaks: Mapping[bytes, int],
) -> bool:
    if witness_script is None or not tweaks:
        return False

    if descriptor_template.threshold > len(tweaks):
        return False

    tweaked_keys: List[bytes] = []
    for base_key, tweak in sorted(tweaks.items(), key=lambda item: item[0]):
        if len(base_key) != 33:
            return False
        tweaked_key = apply_tweak_to_public(base_key, tweak % CURVE_N)
        tweaked_keys.append(tweaked_key)

    try:
        expected_witness_script = descriptor_template.witness_script(tweaked_keys)
    except ValueError:
        return False

    return witness_script == expected_witness_script

def delegator_sign(
    tweak: int,
    base_secret: int,
    message: bytes,
) -> bytes:
    """Derive the delegated key, sign ``message``, and return signature."""
    child_secret = int_to_bytes(apply_tweak_to_secret(base_secret, tweak), 32)
    message_digest = hashlib.sha256(message).digest()
    signature = schnorr_sign(message_digest, child_secret, bytes(32))
    return signature

def test_compute_tweak_vectors() -> None:
    with open(os.path.join(sys.path[0], 'vectors', 'compute_bip32_tweak_vectors.json')) as f:
        data = json.load(f)

    default_xpub_data = data.get("xpub")
    if default_xpub_data is None:
        raise AssertionError("compute_bip32_tweak_vectors.json missing top-level 'xpub'")

    for case in data.get("valid_test_cases", []):
        xpub_data = case.get("xpub", default_xpub_data)
        xpub = parse_extended_public_key(xpub_data)
        path = decode_path(case.get("path", []))
        expected = case.get("expected")
        if not isinstance(expected, Mapping):
            raise AssertionError("valid compute_tweak case missing 'expected'")

        tweak_hex = expected.get("tweak")
        if not isinstance(tweak_hex, str):
            raise AssertionError("expected 'tweak' must be a string")
        
        derived = expected.get("derived_xpub", {})
        derived_compressed = derived.get("compressed")
        if not isinstance(derived_compressed, str):
            raise AssertionError("expected 'derived_xpub.compressed' must be a string")
        
        derived_chain_code = derived.get("chain_code")
        if not isinstance(derived_chain_code, str):
            raise AssertionError("expected 'derived_xpub.chain_code' must be a string")

        tweak, child = compute_bip32_tweak(xpub, path)
        actual_tweak_hex = f"{tweak:064x}"
        if actual_tweak_hex != tweak_hex.lower():
            raise AssertionError(f"tweak mismatch: expected {tweak_hex}, got {actual_tweak_hex}")

        actual_compressed = compress_point(child.point).hex()
        actual_chain_code = child.chain_code.hex()
        if actual_compressed != derived_compressed.lower():
            raise AssertionError("derived public key mismatch")
        if actual_chain_code != derived_chain_code.lower():
            raise AssertionError("derived chain code mismatch")

    for case in data.get("error_test_cases", []):
        xpub_data = case.get("xpub", default_xpub_data)
        xpub = parse_extended_public_key(xpub_data)
        path = decode_path(case.get("path", []))
        error_spec = case.get("error", {})
        exc_type, message = resolve_error_spec(error_spec)

        try:
            compute_bip32_tweak(xpub, path)
        except exc_type as exc:
            if message and message.lower() not in str(exc).lower():
                raise AssertionError(f"expected error containing '{message}' but got '{exc}'")
        else:
            raise AssertionError("expected failure but case succeeded")

def test_delegator_sign_vectors() -> None:
    with open(os.path.join(sys.path[0], 'vectors', 'delegator_sign_vectors.json')) as f:
        data = json.load(f)

    for case in data.get("test_cases", []):
        base_secret_hex = case.get("base_secret")
        tweak_hex = case.get("tweak")
        message_hex = case.get("message")

        base_secret = int(base_secret_hex, 16)
        tweak = int(tweak_hex, 16)
        message = message_hex.encode('utf-8')

        expected = case.get("expected")
        if not isinstance(expected, Mapping):
            raise AssertionError("delegator_sign case missing 'expected'")
        expected_signature_hex = expected.get("signature")
        if not isinstance(expected_signature_hex, str):
            raise AssertionError("expected 'signature' must be a string")
        expected_signature = bytes.fromhex(expected_signature_hex)

        signature = delegator_sign(
            tweak,
            base_secret,
            message,
        )

        if signature != expected_signature:
            raise AssertionError("signature mismatch")


def test_input_verification_vectors() -> None:
    with open(os.path.join(sys.path[0], 'vectors', 'input_verification_vectors.json')) as f:
        data = json.load(f)


    for case in data.get("test_cases", []):
        descriptor = SortedMultiDescriptorTemplate(threshold=2)
        witness_hex = case.get("witness_script")
        # Get the tweak map of the bare public keys to the BIP 32 tweak
        tweaks_raw = case.get("tweak_map", {})
        tweaks = parse_tweak_map(tweaks_raw)
        expected_bool = bool(case.get("expected", False))

        result = input_verification(
            descriptor,
            bytes.fromhex(witness_hex),
            tweaks,
        )
        if result != expected_bool:
            raise AssertionError(
                f"input_verification result {result} did not match expected {expected_bool}"
            )

def test_change_output_verification_vectors() -> None:
    with open(os.path.join(sys.path[0], 'vectors', 'change_output_verification_vectors.json')) as f:
        data = json.load(f)

    for case in data.get("test_cases", []):
        descriptor = SortedMultiDescriptorTemplate(threshold=2)
        witness_hex = case.get("witness_script")
        # Get the tweak map of the bare public keys to the BIP 32 tweak
        tweaks_raw = case.get("tweak_map", {})
        tweaks = parse_tweak_map(tweaks_raw)
        expected_bool = bool(case.get("expected", False))

        result = change_output_verification(
            descriptor,
            bytes.fromhex(witness_hex),
            tweaks,
        )
        if result != expected_bool:
            raise AssertionError(
                f"change_output_verification result {result} did not match expected {expected_bool}"
            )

def parse_tweak_map(raw: Mapping[str, object]) -> Dict[bytes, int]:
    tweaks: Dict[bytes, int] = {}
    for key_hex, tweak_hex in raw.items():
        base_key = bytes.fromhex(key_hex)
        if not isinstance(tweak_hex, str):
            raise ValueError(f"tweak value for key {key_hex} must be a string")
        tweak_value = int(tweak_hex, 16)
        tweaks[base_key] = tweak_value % CURVE_N
    return tweaks

def resolve_error_spec(raw: object) -> Tuple[type[Exception], Optional[str]]:
    mapping: Dict[str, type[Exception]] = {"value": ValueError, "assertion": AssertionError, "runtime": RuntimeError}
    if not isinstance(raw, dict):
        return ValueError, None

    raw_dict = cast(Dict[str, Any], raw)
    name = str(raw_dict.get("type", "value")).lower()
    message = raw_dict.get("message")
    exc_type = mapping.get(name, ValueError)
    return exc_type, None if message is None else str(message)

if __name__ == '__main__':
    test_blind_nonce_gen_vectors()
    test_blind_challenge_gen_vectors()
    test_blind_sign_and_verify_vectors()
    test_unblind_signature_vectors()
    test_sign_and_verify_random(6)
    test_compute_tweak_vectors()
    test_delegator_sign_vectors()
    test_input_verification_vectors()
    test_change_output_verification_vectors()
    print("All tests passed")