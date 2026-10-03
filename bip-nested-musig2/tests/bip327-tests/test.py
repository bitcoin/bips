import json
import os
import sys
from pathlib import Path
import sys

TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent.parent

sys.path.insert(0, str(PROJECT_ROOT))

from reference import *

VECTORS_DIR = TEST_DIR / "vectors"

def fromhex_all(l):
    return [bytes.fromhex(l_i) for l_i in l]

# Check if calling `try_fn` raises an exception. If yes, examine it with `except_fn`.
def assert_raises(exception, try_fn, except_fn):
    raised = False
    try:
        try_fn()
    except exception as e:
        raised = True
        assert(except_fn(e))
    except BaseException:
        raise AssertionError("Wrong exception raised in a test.")
    if not raised:
        raise AssertionError("Exception was _not_ raised in a test where it was required.")

def get_error_details(test_case):
    error = test_case["error"]
    if error["type"] == "invalid_contribution":
        exception = InvalidContributionError
        if "contrib" in error:
            except_fn = lambda e: e.signer == error["signer"] and e.contrib == error["contrib"]
        else:
            except_fn = lambda e: e.signer == error["signer"]
    elif error["type"] == "value":
        exception = ValueError
        except_fn = lambda e: str(e) == error["message"]
    else:
        raise RuntimeError(f"Invalid error type: {error['type']}")
    return exception, except_fn

def test_key_sort_vectors() -> None:
    vector_file = VECTORS_DIR / 'key_sort_vectors.json'
    with open(vector_file) as f:
        test_data = json.load(f)

    X = fromhex_all(test_data["pubkeys"])
    X_sorted = fromhex_all(test_data["sorted_pubkeys"])

    assert key_sort(X) == X_sorted

def test_key_agg_vectors() -> None:
    vector_file = VECTORS_DIR / 'key_agg_vectors.json'
    with open(vector_file) as f:
        test_data = json.load(f)

    X = fromhex_all(test_data["pubkeys"])
    T = fromhex_all(test_data["tweaks"])
    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        pubkeys = [X[i] for i in test_case["key_indices"]]
        expected = bytes.fromhex(test_case["expected"])

        assert get_xonly_pk(key_agg(pubkeys)) == expected

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)

        pubkeys = [X[i] for i in test_case["key_indices"]]
        tweaks = [T[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]

        assert_raises(exception, lambda: apply_tweaks(key_agg(pubkeys), tweaks, is_xonly), except_fn)

def test_nonce_gen_vectors() -> None:
    vector_file = VECTORS_DIR / 'nonce_gen_vectors.json'
    with open(vector_file) as f:
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
        sk = get_value_maybe("sk")
        pk = PlainPk(get_value("pk"))
        aggpk = get_value_maybe("aggpk")
        if aggpk is not None:
            aggpk = XonlyPk(aggpk)
        msg = get_value_maybe("msg")
        extra_in = get_value_maybe("extra_in")
        expected_secnonce = get_value("expected_secnonce")
        expected_pubnonce = get_value("expected_pubnonce")

        assert nonce_gen_internal(rand_, sk, pk, aggpk, msg, extra_in) == (expected_secnonce, expected_pubnonce)

def test_nonce_agg_vectors() -> None:
    vector_file = VECTORS_DIR / 'nonce_agg_vectors.json'
    with open(vector_file) as f:
        test_data = json.load(f)

    pnonce = fromhex_all(test_data["pnonces"])
    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        pubnonces = [pnonce[i] for i in test_case["pnonce_indices"]]
        expected = bytes.fromhex(test_case["expected"])
        assert nonce_agg(pubnonces) == expected

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)
        pubnonces = [pnonce[i] for i in test_case["pnonce_indices"]]
        assert_raises(exception, lambda: nonce_agg(pubnonces), except_fn)

def test_sign_verify_vectors() -> None:
    vector_file = VECTORS_DIR / 'sign_verify_vectors.json'
    with open(vector_file) as f:
        test_data = json.load(f)

    sk = bytes.fromhex(test_data["sk"])
    X = fromhex_all(test_data["pubkeys"])
    # The public key corresponding to sk is at index 0
    assert X[0] == individual_pk(sk)

    secnonces = fromhex_all(test_data["secnonces"])
    pnonce = fromhex_all(test_data["pnonces"])
    # The public nonce corresponding to secnonces[0] is at index 0
    k_1 = int_from_bytes(secnonces[0][0:32])
    k_2 = int_from_bytes(secnonces[0][32:64])
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None and R_s2 is not None
    assert pnonce[0] == cbytes(R_s1) + cbytes(R_s2)

    aggnonces = fromhex_all(test_data["aggnonces"])
    # The aggregate of the first three elements of pnonce is at index 0
    assert (aggnonces[0] == nonce_agg([pnonce[0], pnonce[1], pnonce[2]]))
    # The aggregate of the first and fourth elements of pnonce is at index 1,
    # which is the infinity point encoded as a zeroed 33-byte array
    assert (aggnonces[1] == nonce_agg([pnonce[0], pnonce[3]]))

    msgs = fromhex_all(test_data["msgs"])

    valid_test_cases = test_data["valid_test_cases"]
    sign_error_test_cases = test_data["sign_error_test_cases"]
    verify_fail_test_cases = test_data["verify_fail_test_cases"]
    verify_error_test_cases = test_data["verify_error_test_cases"]

    for test_case in valid_test_cases:
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        aggnonce = aggnonces[test_case["aggnonce_index"]]
        # Make sure that pubnonces and aggnonce in the test vector are
        # consistent
        assert nonce_agg(pubnonces) == aggnonce
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        expected = bytes.fromhex(test_case["expected"])

        # remove the pubkey corresponding to sk, from the pk_tree, because the nested musig code does not expect them to be there
        other_pubkeys = [pk for pk in pubkeys if pk != individual_pk(sk)]
        session_ctx = SessionContext([aggnonce], [other_pubkeys], [], [], msg)
        # WARNING: An actual implementation should _not_ copy the secnonce.
        # Reusing the secnonce, as we do here for testing purposes, can leak the
        # secret key.
        secnonce_tmp = bytearray(secnonces[0])
        _, psig = sign(secnonce_tmp, sk, session_ctx)
        assert psig == expected
        assert partial_sig_verify(psig, pubnonces[signer_index], pubkeys[signer_index], session_ctx)

    for test_case in sign_error_test_cases:
        exception, except_fn = get_error_details(test_case)
        if test_case["error"].get("contrib") == "aggnonce":
            # The nested session identifies BIP327's sole aggregator as level 0.
            except_fn = lambda e: e.signer == 0 and e.contrib == "aggnonce"

        pubkeys = [X[i] for i in test_case["key_indices"]]
        aggnonce = aggnonces[test_case["aggnonce_index"]]
        msg = msgs[test_case["msg_index"]]
        secnonce = bytearray(secnonces[test_case["secnonce_index"]])

        # remove the pubkey corresponding to sk, from the pk_tree, because the nested musig code does not expect them to be there
        for i, pk in enumerate(pubkeys):
            if individual_pk(sk) == pk:
                del pubkeys[i]
                break
        session_ctx = SessionContext([aggnonce], [pubkeys], [], [], msg)
        assert_raises(exception, lambda: sign(secnonce, sk, session_ctx), except_fn)

    for test_case in verify_fail_test_cases:
        sig = bytes.fromhex(test_case["sig"])
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]

        other_pubkeys = [pk for pk in pubkeys if pk != pubkeys[signer_index]]
        aggnonce = nonce_agg(pubnonces)
        session_ctx =  SessionContext([aggnonce], [other_pubkeys], [], [], msg)
        assert not partial_sig_verify(sig, pubnonces[signer_index], pubkeys[signer_index], session_ctx)

    for test_case in verify_error_test_cases:
        exception, except_fn = get_error_details(test_case)

        sig = bytes.fromhex(test_case["sig"])
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]

        other_pubkeys = [pk for pk in pubkeys if pk != pubkeys[signer_index]]
        aggnonce = nonce_agg(pubnonces)
        session_ctx =  SessionContext([aggnonce], [other_pubkeys], [], [], msg)
        assert_raises(exception, lambda: partial_sig_verify(sig, pubnonces[signer_index], pubkeys[signer_index], session_ctx), except_fn)

def test_tweak_vectors() -> None:
    vector_file = VECTORS_DIR / 'tweak_vectors.json'
    with open(vector_file) as f:
        test_data = json.load(f)

    sk = bytes.fromhex(test_data["sk"])
    X = fromhex_all(test_data["pubkeys"])
    # The public key corresponding to sk is at index 0
    assert X[0] == individual_pk(sk)

    secnonce = bytearray(bytes.fromhex(test_data["secnonce"]))
    pnonce = fromhex_all(test_data["pnonces"])
    # The public nonce corresponding to secnonce is at index 0
    k_1 = int_from_bytes(bytes(secnonce[0:32]))
    k_2 = int_from_bytes(bytes(secnonce[32:64]))
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None and R_s2 is not None
    assert pnonce[0] == cbytes(R_s1) + cbytes(R_s2)

    aggnonce = bytes.fromhex(test_data["aggnonce"])
    # The aggnonce is the aggregate of the first three elements of pnonce
    assert(aggnonce == nonce_agg([pnonce[0], pnonce[1], pnonce[2]]))

    tweak = fromhex_all(test_data["tweaks"])
    msg = bytes.fromhex(test_data["msg"])

    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        signer_index = test_case["signer_index"]
        expected = bytes.fromhex(test_case["expected"])

        other_pubkeys = [pk for pk in pubkeys if pk != pubkeys[signer_index]]
        aggnonce = nonce_agg(pubnonces)
        session_ctx =  SessionContext([aggnonce], [other_pubkeys], tweaks, is_xonly, msg)
        secnonce_tmp = bytearray(secnonce)
        # WARNING: An actual implementation should _not_ copy the secnonce.
        # Reusing the secnonce, as we do here for testing purposes, can leak the
        # secret key.
        _, psig = sign(secnonce_tmp, sk, session_ctx)
        assert psig == expected
        assert partial_sig_verify(expected, pubnonces[signer_index], pubkeys[signer_index], session_ctx)

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)

        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        signer_index = test_case["signer_index"]

        other_pubkeys = [pk for pk in pubkeys if pk != pubkeys[signer_index]]
        aggnonce = nonce_agg(pubnonces)
        session_ctx =  SessionContext([aggnonce], [other_pubkeys], tweaks, is_xonly, msg)
        assert_raises(exception, lambda: sign(secnonce, sk, session_ctx), except_fn)

def test_sig_agg_vectors() -> None:
    vector_file = VECTORS_DIR / 'sig_agg_vectors.json'
    with open(vector_file) as f:
        test_data = json.load(f)

    X = fromhex_all(test_data["pubkeys"])

    # These nonces are only required if the tested API takes the individual
    # nonces and not the aggregate nonce.
    pnonce = fromhex_all(test_data["pnonces"])

    tweak = fromhex_all(test_data["tweaks"])
    psig = fromhex_all(test_data["psigs"])

    msg = bytes.fromhex(test_data["msg"])

    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        aggnonce = bytes.fromhex(test_case["aggnonce"])
        assert aggnonce == nonce_agg(pubnonces)

        pubkeys = [X[i] for i in test_case["key_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        psigs = [psig[i] for i in test_case["psig_indices"]]
        b = test_case["b"]
        expected = bytes.fromhex(test_case["expected"])

        agg_pk = key_agg(pubkeys)
        session_ctx = SessionContext(None, None, tweaks, is_xonly, msg) # only tweak info is required
        try:
            R_1 = cpoint_ext(aggnonce[0:33])
            R_2 = cpoint_ext(aggnonce[33:66])
        except ValueError:
            # Nonce aggregator sent invalid nonces
            raise InvalidContributionError(None, "aggnonce")
        R_ = point_add(R_1, point_mul(R_2, b))
        R = R_ if not is_infinite(R_) else G
        assert R is not None
        x_r = xbytes(R)
        s = partial_sig_agg(psigs, x_r, session_ctx, agg_pk)
        sig = x_r + s
        assert sig == expected
        aggpk = get_xonly_pk(apply_tweaks(agg_pk, tweaks, is_xonly))
        assert schnorr_verify(msg, aggpk, sig)

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)

        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        aggnonce = nonce_agg(pubnonces)

        pubkeys = [X[i] for i in test_case["key_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]] 
        is_xonly = test_case["is_xonly"]
        psigs = [psig[i] for i in test_case["psig_indices"]]
        b = test_case["b"]

        session_ctx = SessionContext(None, None, tweaks, is_xonly, msg)
        agg_pk = key_agg(pubkeys)
        try:
            R_1 = cpoint_ext(aggnonce[0:33])
            R_2 = cpoint_ext(aggnonce[33:66])
        except ValueError:
            # Nonce aggregator sent invalid nonces
            raise InvalidContributionError(None, "aggnonce")
        R_ = point_add(R_1, point_mul(R_2, b))
        R = R_ if not is_infinite(R_) else G
        assert R is not None
        assert_raises(exception, lambda: partial_sig_agg(psigs, xbytes(R), session_ctx, agg_pk), except_fn)

if __name__ == '__main__':
    test_key_sort_vectors()
    test_key_agg_vectors()
    test_nonce_gen_vectors()
    test_nonce_agg_vectors()
    test_sign_verify_vectors()
    test_tweak_vectors()
    test_sig_agg_vectors()
