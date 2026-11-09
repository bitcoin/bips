from reference import *

def gen_key_agg_vectors():
    print("key_agg_vectors.json: Intermediate tweaking result is point at infinity")
    sk = bytes.fromhex("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671")
    pk = individual_pk(sk)
    keygen_ctx = key_agg([pk])
    aggpoint, _, _ = keygen_ctx
    aggsk = key_agg_coeff([pk], pk)*int_from_bytes(sk) % n
    t = n - aggsk
    assert point_add(point_mul(G, t), aggpoint) == None
    is_xonly = False
    tweak = bytes_from_int(t)
    assert_raises(ValueError, lambda: apply_tweak(keygen_ctx, tweak, is_xonly), lambda e: True)
    print("  pubkey:", pk.hex().upper())
    print("  tweak: ", tweak.hex().upper())

def gen_sign_verify_vectors():
    print("sign_verify_vectors.json: Signature exceeds group size but is valid modulo n")
    with open(os.path.join(sys.path[0], 'vectors', 'sign_verify_vectors.json')) as f:
        test_data = json.load(f)
    X = fromhex_all(test_data["pubkeys"])
    pnonce = fromhex_all(test_data["pnonces"])
    aggnonce = bytes.fromhex(test_data["aggnonces"][0])
    msg = bytes.fromhex(test_data["msgs"][0])
    pubkeys = X[0:3]

    session_ctx = SessionContext(aggnonce, pubkeys, [], [], msg)
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    P = cpoint(pubkeys[0])
    a = get_session_key_agg_coeff(session_ctx, P)
    g = 1 if has_even_y(Q) else n - 1
    # Choose the first half of the pubnonce of signer 0 such that the effective
    # nonce of signer 0 is -e*a*g*gacc*P. Then the partial signature 0 is
    # valid. Since n*G = 0*G, the partial signature n satisfies the
    # verification equation as well, so only the range check rejects it.
    T = point_mul(P, e * a * g * gacc % n)
    Re_s_ = point_negate(T) if has_even_y(R) else T
    R_s2 = cpoint(pnonce[0][33:66])
    R_s1 = point_add(Re_s_, point_negate(point_mul(R_s2, b)))
    # Change the first half of the pubnonce of signer 2 such that the
    # aggregate nonce, and thus b, R and e, stay the same.
    R_s1_2 = point_add(cpoint(aggnonce[0:33]), point_negate(point_add(R_s1, cpoint(pnonce[1][0:33]))))
    pubnonces = [cbytes(R_s1) + pnonce[0][33:66], pnonce[1], cbytes(R_s1_2) + pnonce[2][33:66]]
    assert nonce_agg(pubnonces) == aggnonce
    assert partial_sig_verify(bytes_from_int(0), pubnonces, pubkeys, [], [], msg, 0)
    print("  pnonce of signer 0:", pubnonces[0].hex().upper())
    print("  pnonce of signer 2:", pubnonces[2].hex().upper())

def check_sign_verify_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'sign_verify_vectors.json')) as f:
        test_data = json.load(f)
    X = fromhex_all(test_data["pubkeys"])
    pnonce = fromhex_all(test_data["pnonces"])
    aggnonces = fromhex_all(test_data["aggnonces"])
    msgs = fromhex_all(test_data["msgs"])

    valid_test_cases = test_data["valid_test_cases"]
    for (i, test_case) in enumerate(valid_test_cases):
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        aggnonce = aggnonces[test_case["aggnonce_index"]]
        assert nonce_agg(pubnonces) == aggnonce
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        expected = bytes.fromhex(test_case["expected"])

        session_ctx = SessionContext(aggnonce, pubkeys, [], [], msg)
        (Q, _, _, _, R, _) = get_session_values(session_ctx)
        # Make sure the vectors include tests for both variants of Q and R
        if i == 0:
           assert has_even_y(Q) and not has_even_y(R)
        if i == 1:
           assert not has_even_y(Q) and has_even_y(R)
        if i == 2:
           assert has_even_y(Q) and has_even_y(R)

def check_tweak_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'tweak_vectors.json')) as f:
        test_data = json.load(f)

    X = fromhex_all(test_data["pubkeys"])
    pnonce = fromhex_all(test_data["pnonces"])
    tweak = fromhex_all(test_data["tweaks"])
    valid_test_cases = test_data["valid_test_cases"]

    for (i, test_case) in enumerate(valid_test_cases):
        pubkeys = [X[i] for i in test_case["key_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]

        _, gacc, _ = key_agg_and_tweak(pubkeys, tweaks, is_xonly)
        # Make sure the vectors include tests for gacc = 1 and -1
        if i == 0:
           assert gacc == n - 1
        if i == 1:
           assert gacc == 1

def sig_agg_vectors():
    print("sig_agg_vectors.json:")
    sk = fromhex_all([
        "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671",
        "3874D22DE7A7290C49CE7F1DC17D1A8CD8918E1F799055139D57FC0988D04D10",
        "D0EA1B84481ED1BCFAA39D6775F97BDC9BF8D7C02FD0C009D6D85BAE5EC7B87A",
        "FC2BF9E056B273AF0A8AABB815E541A3552C142AC10D4FE584F01D2CAB84F577"])
    pubkeys = list(map(lambda secret: individual_pk(secret), sk))
    indices32 = [i.to_bytes(32, 'big') for i in range(6)]
    secnonces, pnonces = zip(*[nonce_gen_internal(r, None, pubkeys[0], None, None, None) for r in indices32])
    tweaks = fromhex_all([
        "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
        "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
        "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8"])
    msg = bytes.fromhex("599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869")

    psigs = [None] * 10

    valid_test_cases = [
        {
            "aggnonce": None,
            "nonce_indices": [0, 1],
            "key_indices": [0, 1],
            "tweak_indices": [],
            "is_xonly": [],
            "psig_indices": [0, 1],
        }, {
            "aggnonce": None,
            "nonce_indices": [0, 2],
            "key_indices": [0, 2],
            "tweak_indices": [],
            "is_xonly": [],
            "psig_indices": [2, 3],
        }, {
            "aggnonce": None,
            "nonce_indices": [0, 3],
            "key_indices": [0, 2],
            "tweak_indices": [0],
            "is_xonly": [False],
            "psig_indices": [4, 5],
        }, {
            "aggnonce": None,
            "nonce_indices": [0, 4],
            "key_indices": [0, 3],
            "tweak_indices": [0, 1, 2],
            "is_xonly": [True, False, True],
            "psig_indices": [6, 7],
        }, {
            "aggnonce": None,
            "nonce_indices": [0],
            "key_indices": [0],
            "tweak_indices": [],
            "is_xonly": [],
            "psig_indices": [9],
            "comment": "A single signer. Detects implementations that reject a single signer in PartialSigAgg.",
        },
    ]
    for (i, test_case) in enumerate(valid_test_cases):
        is_xonly = test_case["is_xonly"]
        nonce_indices = test_case["nonce_indices"]
        key_indices = test_case["key_indices"]
        psig_indices = test_case["psig_indices"]
        vec_pnonces = [pnonces[i] for i in nonce_indices]
        vec_pubkeys = [pubkeys[i] for i in key_indices]
        vec_tweaks = [tweaks[i] for i in test_case["tweak_indices"]]

        aggnonce = nonce_agg(vec_pnonces)
        test_case["aggnonce"] = aggnonce.hex().upper()
        session_ctx = SessionContext(aggnonce, vec_pubkeys, vec_tweaks, is_xonly, msg)

        for j in range(len(key_indices)):
            # WARNING: An actual implementation should _not_ copy the secnonce.
            # Reusing the secnonce, as we do here for testing purposes, can leak the
            # secret key.
            secnonce_tmp = bytearray(secnonces[nonce_indices[j]][:64] + pubkeys[key_indices[j]])
            psigs[psig_indices[j]] = sign(secnonce_tmp, sk[key_indices[j]], session_ctx)
        sig = partial_sig_agg([psigs[i] for i in psig_indices], session_ctx)
        keygen_ctx = key_agg_and_tweak(vec_pubkeys, vec_tweaks, is_xonly)
        # To maximize coverage of the sig_agg algorithm, we want one public key
        # point with an even and one with an odd Y coordinate.
        if i == 0:
            assert(has_even_y(keygen_ctx[0]))
        if i == 1:
            assert(not has_even_y(keygen_ctx[0]))
        aggpk = get_xonly_pk(keygen_ctx)
        assert schnorr_verify(msg, aggpk, sig)
        test_case["expected"] = sig.hex().upper()

    error_test_case = {
        "aggnonce": None,
        "nonce_indices": [0, 4],
        "key_indices": [0, 3],
        "tweak_indices": [0, 1, 2],
        "is_xonly": [True, False, True],
        "psig_indices": [7, 8],
        "error": {
            "type": "invalid_contribution",
            "signer": 1,
            "contrib": "psig",
        },
        "comment": "Partial signature is invalid because it exceeds group size"
    }

    psigs[8] = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

    vec_pnonces = [pnonces[i] for i in error_test_case["nonce_indices"]]
    aggnonce = nonce_agg(vec_pnonces)
    error_test_case["aggnonce"] = aggnonce.hex().upper()

    def tohex_all(l):
        return list(map(lambda e: e.hex().upper(), l))

    print(json.dumps({
        "pubkeys": tohex_all(pubkeys),
        "pnonces": tohex_all(pnonces),
        "tweaks": tohex_all(tweaks),
        "psigs": tohex_all(psigs),
        "msg": msg.hex().upper(),
        "valid_test_cases": valid_test_cases,
        "error_test_cases": [error_test_case]
    }, indent=4))

gen_key_agg_vectors()
gen_sign_verify_vectors()
check_sign_verify_vectors()
check_tweak_vectors()
print()
sig_agg_vectors()
