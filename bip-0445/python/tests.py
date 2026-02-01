#!/usr/bin/env python3

import json
import os
import secrets
import sys
import time
from typing import List, Optional, Tuple

from frost_ref.signing import (
    COORDINATOR_ID,
    InvalidContributionError,
    PlainPk,
    SessionContext,
    SignersContext,
    XonlyPk,
    deterministic_sign,
    get_xonly_pk,
    thresh_pubkey_and_tweak,
    nonce_agg,
    nonce_gen,
    nonce_gen_internal,
    partial_sig_agg,
    partial_sig_verify,
    partial_sig_verify_internal,
    sign,
)
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import G, Scalar
from secp256k1lab.bip340 import schnorr_verify
from secp256k1lab.util import int_from_bytes
from trusted_dealer import trusted_dealer_keygen


def fromhex_all(hex_values):
    return [bytes.fromhex(value) for value in hex_values]


# Check that calling `try_fn` raises a `exception`. If `exception` is raised,
# examine it with `except_fn`.
def assert_raises(exception, try_fn, except_fn):
    raised = False
    try:
        try_fn()
    except exception as e:
        raised = True
        assert except_fn(e)
    except BaseException:
        raise AssertionError("Wrong exception raised in a test.")
    if not raised:
        raise AssertionError(
            "Exception was _not_ raised in a test where it was required."
        )


def get_error_details(test_case):
    error = test_case["error"]
    if error["type"] == "InvalidContributionError":
        exception = InvalidContributionError
        if "contrib" in error:

            def except_fn(e):
                return e.id == error["id"] and e.contrib == error["contrib"]
        else:

            def except_fn(e):
                return e.id == error["id"]
    elif error["type"] == "ValueError":
        exception = ValueError

        def except_fn(e):
            return str(e) == error["message"]
    else:
        raise RuntimeError(f"Invalid error type: {error['type']}")
    return exception, except_fn


def generate_frost_keys(
    n: int, t: int
) -> Tuple[PlainPk, List[int], List[bytes], List[PlainPk]]:
    if not (2 <= t <= n):
        raise ValueError("values must satisfy: 2 <= t <= n")

    thresh_pk, secshares, pubshares = trusted_dealer_keygen(
        secrets.token_bytes(32), n, t
    )

    # IDs are 0-indexed: the index in the list IS the participant ID
    assert len(secshares) == n
    identifiers = list(range(len(secshares)))

    return (thresh_pk, identifiers, secshares, pubshares)


def test_nonce_gen_vectors():
    with open(os.path.join(sys.path[0], "vectors", "nonce_gen_vectors.json")) as f:
        test_data = json.load(f)

    for test_case in test_data["test_cases"]:

        def get_value(key) -> bytes:
            return bytes.fromhex(test_case[key])

        def get_value_maybe(key) -> Optional[bytes]:
            if test_case[key] is not None:
                return get_value(key)
            else:
                return None

        rand_ = get_value("rand_")
        secshare = get_value_maybe("secshare")
        pubshare = get_value_maybe("pubshare")
        if pubshare is not None:
            pubshare = PlainPk(pubshare)
        thresh_pk = get_value_maybe("threshold_pubkey")
        if thresh_pk is not None:
            thresh_pk = XonlyPk(thresh_pk)
        msg = get_value_maybe("msg")
        extra_in = get_value_maybe("extra_in")
        expected_secnonce = get_value("expected_secnonce")
        expected_pubnonce = get_value("expected_pubnonce")

        assert nonce_gen_internal(
            rand_, secshare, pubshare, thresh_pk, msg, extra_in
        ) == (expected_secnonce, expected_pubnonce)


def test_nonce_agg_vectors():
    with open(os.path.join(sys.path[0], "vectors", "nonce_agg_vectors.json")) as f:
        test_data = json.load(f)

    pubnonces_list = fromhex_all(test_data["pubnonces"])
    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        # todo: assert the t <= len(pubnonces, ids) <= n
        # todo: assert the values of ids too? 1 <= id <= n?
        pubnonces = [pubnonces_list[i] for i in test_case["pubnonce_indices"]]
        ids = test_case["participant_identifiers"]
        expected_aggnonce = bytes.fromhex(test_case["expected_aggnonce"])
        assert nonce_agg(pubnonces, ids) == expected_aggnonce

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)
        pubnonces = [pubnonces_list[i] for i in test_case["pubnonce_indices"]]
        ids = test_case["participant_identifiers"]
        assert_raises(exception, lambda: nonce_agg(pubnonces, ids), except_fn)


# todo: include vectors from the frost draft too
# todo: add a test where thresh_pk is even (might need to modify json file)
def test_sign_verify_vectors():
    with open(os.path.join(sys.path[0], "vectors", "sign_verify_vectors.json")) as f:
        test_data = json.load(f)

    n = test_data["n"]
    t = test_data["t"]
    secshare_p0 = bytes.fromhex(test_data["secshare_p0"])
    ids = test_data["identifiers"]
    pubshares = fromhex_all(test_data["pubshares"])
    thresh_pk = bytes.fromhex(test_data["threshold_pubkey"])
    # The public key corresponding to the first participant (secshare_p0) is at index 0
    assert pubshares[0] == PlainPk(pubkey_gen_plain(secshare_p0))

    secnonces_p0 = fromhex_all(test_data["secnonces_p0"])
    pubnonces = fromhex_all(test_data["pubnonces"])
    # The public nonce corresponding to first participant (secnonce_p0[0]) is at index 0
    k_1 = int_from_bytes(secnonces_p0[0][0:32])
    k_2 = int_from_bytes(secnonces_p0[0][32:64])
    R_s1 = k_1 * G
    R_s2 = k_2 * G
    assert not R_s1.infinity and not R_s2.infinity
    assert pubnonces[0] == R_s1.to_bytes_compressed() + R_s2.to_bytes_compressed()

    aggnonces = fromhex_all(test_data["aggnonces"])
    msgs = fromhex_all(test_data["msgs"])

    valid_test_cases = test_data["valid_test_cases"]
    sign_error_test_cases = test_data["sign_error_test_cases"]
    verify_fail_test_cases = test_data["verify_fail_test_cases"]
    verify_error_test_cases = test_data["verify_error_test_cases"]

    for test_case in valid_test_cases:
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        # Make sure that pubnonces and aggnonce in the test vector are consistent
        assert nonce_agg(pubnonces_tmp, ids_tmp) == aggnonce_tmp
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        my_id = ids_tmp[signer_index]
        expected = bytes.fromhex(test_case["expected"])

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        session_ctx = SessionContext(aggnonce_tmp, signers_tmp, [], [], msg)
        # WARNING: An actual implementation should _not_ copy the secnonce.
        # Reusing the secnonce, as we do here for testing purposes, can leak the
        # secret key.
        secnonce_tmp = bytearray(secnonces_p0[0])
        assert sign(secnonce_tmp, secshare_p0, my_id, session_ctx) == expected
        assert partial_sig_verify(
            expected, pubnonces_tmp, signers_tmp, [], [], msg, signer_index
        )

    for test_case in sign_error_test_cases:
        exception, except_fn = get_error_details(test_case)
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        my_id = (
            test_case["signer_id"] if signer_index is None else ids_tmp[signer_index]
        )
        secnonce_tmp = bytearray(secnonces_p0[test_case["secnonce_index"]])

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        session_ctx = SessionContext(aggnonce_tmp, signers_tmp, [], [], msg)
        assert_raises(
            exception,
            lambda: sign(secnonce_tmp, secshare_p0, my_id, session_ctx),
            except_fn,
        )

    for test_case in verify_fail_test_cases:
        psig = bytes.fromhex(test_case["psig"])
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        assert not partial_sig_verify_internal(
            psig,
            ids_tmp[signer_index],
            pubnonces_tmp[signer_index],
            pubshares_tmp[signer_index],
            session_ctx,
        )

    for test_case in verify_error_test_cases:
        exception, except_fn = get_error_details(test_case)

        psig = bytes.fromhex(test_case["psig"])
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        assert_raises(
            exception,
            lambda: partial_sig_verify(
                psig, pubnonces_tmp, signers_tmp, [], [], msg, signer_index
            ),
            except_fn,
        )


def test_tweak_vectors():
    with open(os.path.join(sys.path[0], "vectors", "tweak_vectors.json")) as f:
        test_data = json.load(f)

    n = test_data["n"]
    t = test_data["t"]
    secshare_p0 = bytes.fromhex(test_data["secshare_p0"])
    ids = test_data["identifiers"]
    pubshares = fromhex_all(test_data["pubshares"])
    # The public key corresponding to the first participant (secshare_p0) is at index 0
    assert pubshares[0] == PlainPk(pubkey_gen_plain(secshare_p0))
    thresh_pk = bytes.fromhex(test_data["threshold_pubkey"])

    secnonce_p0 = bytearray(bytes.fromhex(test_data["secnonce_p0"]))
    pubnonces = fromhex_all(test_data["pubnonces"])
    # The public nonce corresponding to first participant (secnonce_p0[0]) is at index 0
    k_1 = Scalar.from_bytes_checked(secnonce_p0[0:32])
    k_2 = Scalar.from_bytes_checked(secnonce_p0[32:64])
    R_s1 = k_1 * G
    R_s2 = k_2 * G
    assert not R_s1.infinity and not R_s2.infinity
    assert pubnonces[0] == R_s1.to_bytes_compressed() + R_s2.to_bytes_compressed()

    aggnonces = fromhex_all(test_data["aggnonces"])
    tweaks = fromhex_all(test_data["tweaks"])

    msg = bytes.fromhex(test_data["msg"])

    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for i, test_case in enumerate(valid_test_cases):
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        # Make sure that pubnonces and aggnonce in the test vector are consistent
        assert nonce_agg(pubnonces_tmp, ids_tmp) == aggnonce_tmp
        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        signer_index = test_case["signer_index"]
        my_id = ids_tmp[signer_index]
        expected = bytes.fromhex(test_case["expected"])

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        session_ctx = SessionContext(
            aggnonce_tmp, signers_tmp, tweaks_tmp, tweak_modes_tmp, msg
        )
        # WARNING: An actual implementation should _not_ copy the secnonce.
        # Reusing the secnonce, as we do here for testing purposes, can leak the
        # secret key.
        secnonce_tmp = bytearray(secnonce_p0)
        assert sign(secnonce_tmp, secshare_p0, my_id, session_ctx) == expected
        assert partial_sig_verify(
            expected,
            pubnonces_tmp,
            signers_tmp,
            tweaks_tmp,
            tweak_modes_tmp,
            msg,
            signer_index,
        )

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        signer_index = test_case["signer_index"]
        my_id = ids_tmp[signer_index]

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        session_ctx = SessionContext(
            aggnonce_tmp, signers_tmp, tweaks_tmp, tweak_modes_tmp, msg
        )
        assert_raises(
            exception,
            lambda: sign(secnonce_p0, secshare_p0, my_id, session_ctx),
            except_fn,
        )


def test_det_sign_vectors():
    with open(os.path.join(sys.path[0], "vectors", "det_sign_vectors.json")) as f:
        test_data = json.load(f)

    n = test_data["n"]
    t = test_data["t"]
    secshare_p0 = bytes.fromhex(test_data["secshare_p0"])
    ids = test_data["identifiers"]
    pubshares = fromhex_all(test_data["pubshares"])
    # The public key corresponding to the first participant (secshare_p0) is at index 0
    assert pubshares[0] == PlainPk(pubkey_gen_plain(secshare_p0))

    thresh_pk = bytes.fromhex(test_data["threshold_pubkey"])
    msgs = fromhex_all(test_data["msgs"])

    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        aggothernonce = bytes.fromhex(test_case["aggothernonce"])
        tweaks = fromhex_all(test_case["tweaks"])
        is_xonly = test_case["is_xonly"]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        my_id = ids_tmp[signer_index]
        rand = (
            bytes.fromhex(test_case["rand"]) if test_case["rand"] is not None else None
        )
        expected = fromhex_all(test_case["expected"])

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        pubnonce, psig = deterministic_sign(
            secshare_p0,
            my_id,
            aggothernonce,
            signers_tmp,
            tweaks,
            is_xonly,
            msg,
            rand,
        )
        assert pubnonce == expected[0]
        assert psig == expected[1]

        pubnonces = [aggothernonce, pubnonce]
        aggnonce_tmp = nonce_agg(pubnonces, [COORDINATOR_ID, my_id])
        session_ctx = SessionContext(aggnonce_tmp, signers_tmp, tweaks, is_xonly, msg)
        assert partial_sig_verify_internal(
            psig, my_id, pubnonce, pubshares_tmp[signer_index], session_ctx
        )

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        aggothernonce = bytes.fromhex(test_case["aggothernonce"])
        tweaks = fromhex_all(test_case["tweaks"])
        is_xonly = test_case["is_xonly"]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        my_id = (
            test_case["signer_id"] if signer_index is None else ids_tmp[signer_index]
        )
        rand = (
            bytes.fromhex(test_case["rand"]) if test_case["rand"] is not None else None
        )

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)

        def try_fn():
            return deterministic_sign(
                secshare_p0,
                my_id,
                aggothernonce,
                signers_tmp,
                tweaks,
                is_xonly,
                msg,
                rand,
            )

        assert_raises(exception, try_fn, except_fn)


def test_sig_agg_vectors():
    with open(os.path.join(sys.path[0], "vectors", "sig_agg_vectors.json")) as f:
        test_data = json.load(f)

    n = test_data["n"]
    t = test_data["t"]
    ids = test_data["identifiers"]
    pubshares = fromhex_all(test_data["pubshares"])
    thresh_pk = bytes.fromhex(test_data["threshold_pubkey"])
    # These nonces are only required if the tested API takes the individual
    # nonces and not the aggregate nonce.
    pubnonces = fromhex_all(test_data["pubnonces"])

    tweaks = fromhex_all(test_data["tweaks"])
    msg = bytes.fromhex(test_data["msg"])

    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = bytes.fromhex(test_case["aggnonce"])
        # Make sure that pubnonces and aggnonce in the test vector are consistent
        assert aggnonce_tmp == nonce_agg(pubnonces_tmp, ids_tmp)

        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        psigs_tmp = fromhex_all(test_case["psigs"])
        expected = bytes.fromhex(test_case["expected"])

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        session_ctx = SessionContext(
            aggnonce_tmp, signers_tmp, tweaks_tmp, tweak_modes_tmp, msg
        )
        # Make sure that the partial signatures in the test vector are consistent. The tested API takes only aggnonce (not pubnonces list), this check can be ignored
        for i in range(len(ids_tmp)):
            partial_sig_verify(
                psigs_tmp[i],
                pubnonces_tmp,
                signers_tmp,
                tweaks_tmp,
                tweak_modes_tmp,
                msg,
                i,
            )

        bip340sig = partial_sig_agg(psigs_tmp, ids_tmp, session_ctx)
        assert bip340sig == expected
        tweaked_thresh_pk = get_xonly_pk(
            thresh_pubkey_and_tweak(thresh_pk, tweaks_tmp, tweak_modes_tmp)
        )
        assert schnorr_verify(msg, tweaked_thresh_pk, bip340sig)

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)

        ids_tmp = [ids[i] for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = bytes.fromhex(test_case["aggnonce"])

        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        psigs_tmp = fromhex_all(test_case["psigs"])

        signers_tmp = SignersContext(n, t, ids_tmp, pubshares_tmp, thresh_pk)
        session_ctx = SessionContext(
            aggnonce_tmp, signers_tmp, tweaks_tmp, tweak_modes_tmp, msg
        )
        assert_raises(
            exception,
            lambda: partial_sig_agg(psigs_tmp, ids_tmp, session_ctx),
            except_fn,
        )


def test_sign_and_verify_random(iterations: int) -> None:
    for itr in range(iterations):
        secure_rng = secrets.SystemRandom()
        # randomly choose a number: 2 <= number <= 10
        n = secure_rng.randrange(2, 11)
        # randomly choose a number: 2 <= number <= n
        t = secure_rng.randrange(2, n + 1)

        thresh_pk, ids, secshares, pubshares = generate_frost_keys(n, t)
        assert len(ids) == len(secshares) == len(pubshares) == n

        # randomly choose the signer set, with len: t <= len <= n
        signer_count = secure_rng.randrange(t, n + 1)
        signer_indices = secure_rng.sample(range(n), signer_count)
        assert (
            len(set(signer_indices)) == signer_count
        )  # signer set must not contain duplicate ids

        signer_ids = [ids[i] for i in signer_indices]
        signer_pubshares = [pubshares[i] for i in signer_indices]
        # NOTE: secret values MUST NEVER BE COPIED!!!
        # we do it here to improve the code readability
        signer_secshares = [secshares[i] for i in signer_indices]

        signers_ctx = SignersContext(n, t, signer_ids, signer_pubshares, thresh_pk)

        # In this example, the message and threshold pubkey are known
        # before nonce generation, so they can be passed into the nonce
        # generation function as a defense-in-depth measure to protect
        # against nonce reuse.
        #
        # If these values are not known when nonce_gen is called, empty
        # byte arrays can be passed in for the corresponding arguments
        # instead.
        msg = secrets.token_bytes(32)
        v = secrets.randbelow(4)
        tweaks = [secrets.token_bytes(32) for _ in range(v)]
        tweak_modes = [secrets.choice([False, True]) for _ in range(v)]
        tweaked_thresh_pk = get_xonly_pk(
            thresh_pubkey_and_tweak(thresh_pk, tweaks, tweak_modes)
        )

        signer_secnonces = []
        signer_pubnonces = []
        for i in range(signer_count - 1):
            # Use a clock for extra_in
            timestamp = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            secnonce_i, pubnonce_i = nonce_gen(
                signer_secshares[i],
                signer_pubshares[i],
                tweaked_thresh_pk,
                msg,
                timestamp.to_bytes(8, "big"),
            )
            signer_secnonces.append(secnonce_i)
            signer_pubnonces.append(pubnonce_i)

        # On even iterations use regular signing algorithm for the final signer,
        # otherwise use deterministic signing algorithm
        if itr % 2 == 0:
            timestamp = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            secnonce_final, pubnonce_final = nonce_gen(
                signer_secshares[-1],
                signer_pubshares[-1],
                tweaked_thresh_pk,
                msg,
                timestamp.to_bytes(8, "big"),
            )
            signer_secnonces.append(secnonce_final)
        else:
            aggothernonce = nonce_agg(signer_pubnonces, signer_ids[:-1])
            rand = secrets.token_bytes(32)
            pubnonce_final, psig_final = deterministic_sign(
                signer_secshares[-1],
                signer_ids[-1],
                aggothernonce,
                signers_ctx,
                tweaks,
                tweak_modes,
                msg,
                rand,
            )

        signer_pubnonces.append(pubnonce_final)
        aggnonce = nonce_agg(signer_pubnonces, signer_ids)
        session_ctx = SessionContext(aggnonce, signers_ctx, tweaks, tweak_modes, msg)

        signer_psigs = []
        for i in range(signer_count):
            if itr % 2 != 0 and i == signer_count - 1:
                psig_i = psig_final  # last signer would have already deterministically signed
            else:
                psig_i = sign(
                    signer_secnonces[i], signer_secshares[i], signer_ids[i], session_ctx
                )
            assert partial_sig_verify(
                psig_i,
                signer_pubnonces,
                signers_ctx,
                tweaks,
                tweak_modes,
                msg,
                i,
            )
            signer_psigs.append(psig_i)

        # An exception is thrown if secnonce is accidentally reused
        assert_raises(
            ValueError,
            lambda: sign(
                signer_secnonces[0], signer_secshares[0], signer_ids[0], session_ctx
            ),
            lambda e: True,
        )

        # Wrong signer index
        assert not partial_sig_verify(
            signer_psigs[0],
            signer_pubnonces,
            signers_ctx,
            tweaks,
            tweak_modes,
            msg,
            1,
        )
        # Wrong message
        assert not partial_sig_verify(
            signer_psigs[0],
            signer_pubnonces,
            signers_ctx,
            tweaks,
            tweak_modes,
            secrets.token_bytes(32),
            0,
        )

        bip340sig = partial_sig_agg(signer_psigs, signer_ids, session_ctx)
        assert schnorr_verify(msg, tweaked_thresh_pk, bip340sig)


def run_test(test_name, test_func):
    max_len = 30
    test_name = test_name.ljust(max_len, ".")
    print(f"Running {test_name}...", end="", flush=True)
    try:
        test_func()
        print("Passed!")
    except Exception as e:
        print(f"Failed :'(\nError: {e}")


if __name__ == "__main__":
    run_test("test_nonce_gen_vectors", test_nonce_gen_vectors)
    run_test("test_nonce_agg_vectors", test_nonce_agg_vectors)
    run_test("test_sign_verify_vectors", test_sign_verify_vectors)
    run_test("test_tweak_vectors", test_tweak_vectors)
    run_test("test_det_sign_vectors", test_det_sign_vectors)
    run_test("test_sig_agg_vectors", test_sig_agg_vectors)
    run_test("test_sign_and_verify_random", lambda: test_sign_and_verify_random(6))
