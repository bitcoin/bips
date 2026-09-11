#!/usr/bin/env python3

"""Tests for ChillDKG reference implementation"""

import json
from itertools import combinations
from pathlib import Path
from random import randint
from secrets import token_bytes as random_bytes

from chilldkg_ref import chilldkg, encpedpop, simplpedpop
from chilldkg_ref.util import (
    FaultyCoordinatorError,
    FaultyParticipantOrCoordinatorError,
    UnknownFaultyParticipantOrCoordinatorError,
    tagged_hash_bip_dkg,
)
from chilldkg_ref.vss import VSS, Polynomial, VSSCommitment
from example import simulate_chilldkg_full as simulate_chilldkg_full_example
from gen_vector_utils.util import (
    assert_raises,
    dkg_output_asdict,
    params_asdict,
    params_from_dict,
)

# Import from secp256k1lab after the chilldkg_ref imports because the latter
# modifies sys.path to make sure the vendored copy of secp256k1lab is found.
#
# isort: split
from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import GE, G, Scalar


def test_chilldkg_params_validate():
    hostseckeys = [random_bytes(32) for _ in range(3)]
    hostpubkeys = [chilldkg.hostpubkey_gen(hostseckey) for hostseckey in hostseckeys]

    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    params_with_duplicate = chilldkg.SessionParams(with_duplicate, 2)
    try:
        _ = chilldkg.params_hash(params_with_duplicate)
    except chilldkg.DuplicateHostPubkeyError as e:
        assert {e.participant_id1, e.participant_id2} == {1, 3}
    else:
        assert False, "Expected exception"

    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    params_with_invalid = chilldkg.SessionParams(
        [hostpubkeys[1], invalid_hostpubkey, hostpubkeys[2]], 1
    )
    try:
        _ = chilldkg.params_hash(params_with_invalid)
    except chilldkg.InvalidHostPubkeyError as e:
        assert e.participant_id == 1
    else:
        assert False, "Expected exception"

    try:
        _ = chilldkg.params_hash(
            chilldkg.SessionParams(hostpubkeys, len(hostpubkeys) + 1)
        )
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"

    try:
        _ = chilldkg.params_hash(chilldkg.SessionParams(hostpubkeys, -2))
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"


def test_vss_correctness():
    def rand_polynomial(t):
        return Polynomial([randint(1, GE.ORDER - 1) for _ in range(1, t + 1)])

    for t in range(1, 3):
        for n in range(t, 2 * t + 1):
            f = rand_polynomial(t)
            vss = VSS(f)
            secshares = vss.secshares(n)
            assert len(secshares) == n
            assert all(
                VSSCommitment.verify_secshare(secshares[i], vss.commit().pubshare(i))
                for i in range(n)
            )

            vssc_tweaked, tweak, pubtweak = vss.commit().invalid_taproot_commit()
            assert VSSCommitment.verify_secshare(
                vss.secret() + tweak, vss.commit().commitment_to_secret() + pubtweak
            )
            assert all(
                VSSCommitment.verify_secshare(
                    secshares[i] + tweak, vssc_tweaked.pubshare(i)
                )
                for i in range(n)
            )


def simulate_simplpedpop(
    seeds, t, investigation: bool
) -> list[tuple[simplpedpop.DKGOutput, bytes]] | None:
    n = len(seeds)
    prets = []
    for i in range(n):
        random = random_bytes(32)
        prets += [simplpedpop.participant_step1(seeds[i], t, n, i, random)]

    pstates = [pstate for (pstate, _, _) in prets]
    pmsgs = [pmsg for (_, pmsg, _) in prets]

    cmsg, cout, ceq = simplpedpop.coordinator_step(pmsgs, t, n)
    pre_finalize_rets = [(cout, ceq)]
    for i in range(n):
        partial_secshares = [
            partial_secshares_for[i] for (_, _, partial_secshares_for) in prets
        ]
        if investigation:
            # Let a random participant send incorrect shares to participant i.
            faulty_id = randint(0, n - 1)
            partial_secshares[faulty_id] += Scalar(17)

        secshare = simplpedpop.participant_step2_prepare_secshare(partial_secshares)
        try:
            pre_finalize_rets += [
                simplpedpop.participant_step2(pstates[i], cmsg, secshare)
            ]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = simplpedpop.coordinator_investigate(pmsgs, t)
            assert len(inv_msgs) == len(pmsgs)
            try:
                simplpedpop.participant_investigate(e, inv_msgs[i], partial_secshares)
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_id
                assert e.participant_id == faulty_id
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_id
            return None
    return pre_finalize_rets


def encpedpop_keys(seed: bytes) -> tuple[bytes, bytes]:
    deckey = tagged_hash_bip_dkg("encpedpop deckey", seed)
    enckey = pubkey_gen_plain(deckey)
    return deckey, enckey


def simulate_encpedpop(
    seeds, t, investigation: bool
) -> list[tuple[simplpedpop.DKGOutput, bytes]] | None:
    n = len(seeds)
    enc_prets0 = []
    enc_prets1 = []
    for i in range(n):
        enc_prets0 += [encpedpop_keys(seeds[i])]

    enckeys = [pret[1] for pret in enc_prets0]
    for i in range(n):
        deckey = enc_prets0[i][0]
        random = random_bytes(32)
        enc_prets1 += [
            encpedpop.participant_step1(seeds[i], deckey, enckeys, t, i, random)
        ]

    pstates = [pstate for (pstate, _) in enc_prets1]
    pmsgs = [pmsg for (_, pmsg) in enc_prets1]
    if investigation:
        faulty_id: list[int] = []
        for i in range(n):
            # Let a random participant faulty_id[i] send incorrect shares to
            # participant i.
            faulty_id[i:] = [randint(0, n - 1)]
            faulty_pmsg = encpedpop.ParticipantMsg.from_bytes(
                pmsgs[faulty_id[i]], t=t, n=n
            )
            faulty_pmsg.enc_shares[i] += Scalar(17)
            pmsgs[faulty_id[i]] = faulty_pmsg.to_bytes()

    cmsg, cout, ceq, enc_secshares = encpedpop.coordinator_step(pmsgs, t, enckeys)
    pre_finalize_rets = [(cout, ceq)]
    for i in range(n):
        deckey = enc_prets0[i][0]
        try:
            pre_finalize_rets += [
                encpedpop.participant_step2(pstates[i], deckey, cmsg, enc_secshares[i])
            ]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = encpedpop.coordinator_investigate(pmsgs, t)
            assert len(inv_msgs) == len(pmsgs)
            try:
                encpedpop.participant_investigate(e, inv_msgs[i])
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_id[i]
                assert e.participant_id == faulty_id[i]
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_id[i]
            return None
    return pre_finalize_rets


def simulate_chilldkg(
    hostseckeys, t, investigation: bool
) -> list[tuple[chilldkg.DKGOutput, chilldkg.RecoveryData]] | None:
    n = len(hostseckeys)

    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [chilldkg.hostpubkey_gen(hostseckeys[i])]

    params = chilldkg.SessionParams(hostpubkeys, t)

    prets1 = []
    for i in range(n):
        random = random_bytes(32)
        prets1 += [chilldkg.participant_step1(hostseckeys[i], params, random)]

    pstates1 = [pret[0] for pret in prets1]
    pmsgs = [pret[1] for pret in prets1]
    if investigation:
        faulty_id: list[int] = []
        for i in range(n):
            # Let a random participant faulty_id[i] send incorrect shares
            # to participant i.
            faulty_id[i:] = [randint(0, n - 1)]
            faulty_pmsg = chilldkg.ParticipantMsg1.from_bytes(
                pmsgs[faulty_id[i]], t=t, n=n
            )
            faulty_pmsg.enc_pmsg.enc_shares[i] += Scalar(17)
            pmsgs[faulty_id[i]] = faulty_pmsg.to_bytes()

    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs, params)

    prets2 = []
    for i in range(n):
        try:
            random = random_bytes(32)
            prets2 += [
                chilldkg.participant_step2(hostseckeys[i], pstates1[i], cmsg1, random)
            ]
        except UnknownFaultyParticipantOrCoordinatorError as e:
            if not investigation:
                raise
            inv_msgs = chilldkg.coordinator_investigate(pmsgs, params)
            assert len(inv_msgs) == len(pmsgs)
            try:
                chilldkg.participant_investigate(e, inv_msgs[i])
            # If we're not faulty, we should blame the faulty party.
            except FaultyParticipantOrCoordinatorError as e:
                assert i != faulty_id[i]
                assert e.participant_id == faulty_id[i]
            # If we're faulty, we'll blame the coordinator.
            except FaultyCoordinatorError:
                assert i == faulty_id[i]
            return None

    cmsg2, cout, crec = chilldkg.coordinator_finalize(
        cstate, [pret[1] for pret in prets2]
    )
    outputs = [(cout, crec)]
    for i in range(n):
        out = chilldkg.participant_finalize(prets2[i][0], cmsg2)
        assert out is not None
        outputs += [out]

    return outputs


def simulate_chilldkg_full(
    hostseckeys,
    t,
    investigation: bool,
) -> list[tuple[chilldkg.DKGOutput, chilldkg.RecoveryData] | None]:
    # Investigating is not supported by this wrapper
    assert not investigation

    hostpubkeys = []
    for i in range(n):
        hostpubkeys += [chilldkg.hostpubkey_gen(hostseckeys[i])]
    params = chilldkg.SessionParams(hostpubkeys, t)
    return simulate_chilldkg_full_example(hostseckeys, params, faulty_id=None)


def derive_interpolating_value(L, x_i):
    assert x_i in L
    assert all(L.count(x_j) <= 1 for x_j in L)
    lam = Scalar(1)
    for x_j in L:
        x_j = Scalar(x_j)
        x_i = Scalar(x_i)
        if x_j == x_i:
            continue
        lam *= x_j / (x_j - x_i)
    return lam


def recover_secret(participant_ids, shares) -> Scalar:
    interpolated_shares = []
    t = len(shares)
    assert len(participant_ids) == t
    for i in range(t):
        lam = derive_interpolating_value(participant_ids, participant_ids[i])
        interpolated_shares += [(lam * shares[i])]
    recovered_secret = Scalar.sum(*interpolated_shares)
    return recovered_secret


def test_recover_secret():
    f = Polynomial([23, 42])
    shares = [f(i) for i in [1, 2, 3]]
    assert recover_secret([1, 2], [shares[0], shares[1]]) == f.coeffs[0]
    assert recover_secret([1, 3], [shares[0], shares[2]]) == f.coeffs[0]
    assert recover_secret([2, 3], [shares[1], shares[2]]) == f.coeffs[0]


def test_correctness_dkg_output(t, n, dkg_outputs: list[simplpedpop.DKGOutput]):
    assert len(dkg_outputs) == n + 1
    secshares = [out[0] for out in dkg_outputs]
    thresh_pks = [out[1] for out in dkg_outputs]
    pubshares = [out[2] for out in dkg_outputs]

    # Check that the threshold pubkey and pubshares are the same for the
    # coordinator (at [0]) and all participants (at [1:n + 1]).
    for i in range(n + 1):
        assert thresh_pks[0] == thresh_pks[i]
        assert len(pubshares[i]) == n
        assert pubshares[0] == pubshares[i]
    thresh_pk = thresh_pks[0]

    # Check that the coordinator has no secret share
    assert secshares[0] is None

    # Check that each secshare matches the corresponding pubshare
    secshares_scalar = [
        None if secshare is None else Scalar.from_bytes_checked(secshare)
        for secshare in secshares
    ]
    for i in range(1, n + 1):
        s = secshares_scalar[i]
        assert s is not None
        assert s * G == GE.from_bytes_compressed(pubshares[0][i - 1])

    # Check that all combinations of t participants can recover the threshold pubkey
    for tsubset in combinations(range(1, n + 1), t):
        recovered = recover_secret(tsubset, [secshares_scalar[i] for i in tsubset])
        assert recovered * G == GE.from_bytes_compressed(thresh_pk)


def test_correctness(t, n, simulate_dkg, recovery=False, investigation=False):
    seeds = [None] + [random_bytes(32) for _ in range(n)]

    rets = simulate_dkg(seeds[1:], t, investigation=investigation)
    if investigation:
        assert rets is None
        # The session has failed correctly, so there's nothing further to check.
        return

    # rets[0] are the return values from the coordinator
    # rets[1 : n + 1] are from the participants
    assert len(rets) == n + 1
    dkg_outputs = [ret[0] for ret in rets]
    test_correctness_dkg_output(t, n, dkg_outputs)

    eqs_or_recs = [ret[1] for ret in rets]
    for i in range(1, n + 1):
        assert eqs_or_recs[0] == eqs_or_recs[i]

    if recovery:
        rec = eqs_or_recs[0]
        # Check correctness of chilldkg.participant_recover /
        # chilldkg.coordinator_recover
        for i in range(n + 1):
            if seeds[i] is None:
                (secshare, thresh_pk, pubshares), _ = chilldkg.coordinator_recover(rec)
            else:
                (secshare, thresh_pk, pubshares), _ = chilldkg.participant_recover(
                    seeds[i], rec
                )
            assert secshare == dkg_outputs[i][0]
            assert thresh_pk == dkg_outputs[i][1]
            assert pubshares == dkg_outputs[i][2]


VECTORS_DIR = Path(__file__).parent.parent / "vectors"


def test_hostpubkey_gen_vectors():
    input_file = VECTORS_DIR / "hostpubkey_gen_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    valid_test_cases = test_data["validTestCases"]
    error_test_cases = test_data["errorTestCases"]
    assert test_data["totalTests"] == len(valid_test_cases) + len(error_test_cases)

    for test_case in valid_test_cases:
        hostseckey = bytes.fromhex(test_case["hostseckey"])
        expected_hostpubkey = bytes.fromhex(test_case["expectedHostpubkey"])
        assert expected_hostpubkey == chilldkg.hostpubkey_gen(hostseckey)

    for test_case in error_test_cases:
        hostseckey = bytes.fromhex(test_case["hostseckey"])
        expected_error = test_case["expectedError"]
        assert_raises(lambda: chilldkg.hostpubkey_gen(hostseckey), expected_error)


def test_params_hash_vectors():
    input_file = VECTORS_DIR / "params_hash_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    valid_test_cases = test_data["validTestCases"]
    error_test_cases = test_data["errorTestCases"]
    assert test_data["totalTests"] == len(valid_test_cases) + len(error_test_cases)

    for test_case in valid_test_cases:
        params = params_from_dict(test_case["params"])
        expected_hash = bytes.fromhex(test_case["expectedParamsHash"])
        assert expected_hash == chilldkg.params_hash(params)

    for test_case in error_test_cases:
        params = params_from_dict(test_case["params"])
        expected_error = test_case["expectedError"]
        assert_raises(lambda: chilldkg.params_hash(params), expected_error)


def test_participant_step1_vectors():
    input_file = VECTORS_DIR / "participant_step1_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        for test_case in group["validTestCases"]:
            hostseckey = bytes.fromhex(test_case["hostseckey"])
            params = params_from_dict(test_case["params"])
            random = bytes.fromhex(test_case["random"])
            expected_pmsg1 = bytes.fromhex(test_case["expectedPmsg1"])
            _, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
            assert expected_pmsg1 == pmsg1
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in group["errorTestCases"]:
            hostseckey = bytes.fromhex(test_case["hostseckey"])
            params = params_from_dict(test_case["params"])
            random = bytes.fromhex(test_case["random"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.participant_step1(hostseckey, params, random),
                expected_error,
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_participant_step2_vectors():
    input_file = VECTORS_DIR / "participant_step2_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        # common fields for all test cases
        params = params_from_dict(group["params"])
        hostseckey = bytes.fromhex(group["hostseckey"])
        random = bytes.fromhex(group["random"])
        aux_rand = bytes.fromhex(group["auxRand"])

        state1, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
        assert bytes.fromhex(group["pmsg1"]) == pmsg1  # checkpoint

        for test_case in group["validTestCases"]:
            cmsg1 = bytes.fromhex(test_case["cmsg1"])
            expected_pmsg2 = bytes.fromhex(test_case["expectedPmsg2"])
            _, pmsg2 = chilldkg.participant_step2(hostseckey, state1, cmsg1, aux_rand)
            assert expected_pmsg2 == pmsg2
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in group["errorTestCases"]:
            case_hostseckey = bytes.fromhex(
                test_case.get("hostseckey", group["hostseckey"])
            )
            case_aux_rand = bytes.fromhex(test_case.get("auxRand", group["auxRand"]))
            cmsg1 = bytes.fromhex(test_case["cmsg1"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.participant_step2(
                    case_hostseckey, state1, cmsg1, case_aux_rand
                ),
                expected_error,
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_participant_finalize_vectors():
    input_file = VECTORS_DIR / "participant_finalize_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        # common fields for all test cases
        params = params_from_dict(group["params"])
        hostseckey = bytes.fromhex(group["hostseckey"])
        random = bytes.fromhex(group["random"])
        aux_rand = bytes.fromhex(group["auxRand"])

        # compute state1 and assert pmsg1
        state1, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
        assert bytes.fromhex(group["pmsg1"]) == pmsg1
        # compute state2 and assert pmsg2
        cmsg1 = bytes.fromhex(group["cmsg1"])
        state2, pmsg2 = chilldkg.participant_step2(hostseckey, state1, cmsg1, aux_rand)
        assert bytes.fromhex(group["pmsg2"]) == pmsg2

        for test_case in group["validTestCases"]:
            cmsg2 = bytes.fromhex(test_case["cmsg2"])
            pout, prec = chilldkg.participant_finalize(state2, cmsg2)
            expected_pout = test_case["expectedOutput"]["dkgOutput"]
            expected_prec = bytes.fromhex(test_case["expectedOutput"]["recoveryData"])
            assert expected_pout == dkg_output_asdict(pout)
            assert expected_prec == prec
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in group["errorTestCases"]:
            cmsg2 = bytes.fromhex(test_case["cmsg2"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.participant_finalize(state2, cmsg2), expected_error
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_participant_investigate_vectors():
    input_file = VECTORS_DIR / "participant_investigate_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        # common fields for all test cases
        params = params_from_dict(group["params"])
        hostseckey = bytes.fromhex(group["hostseckey"])
        random = bytes.fromhex(group["random"])
        aux_rand = bytes.fromhex(group["auxRand"])
        cmsg1_pool = group["cmsg1Pool"]

        # Re-derive state1
        state1, pmsg1 = chilldkg.participant_step1(hostseckey, params, random)
        assert bytes.fromhex(group["pmsg1"]) == pmsg1

        for test_case in group["errorTestCases"]:
            cmsg1 = bytes.fromhex(cmsg1_pool[test_case["cmsg1Index"]])
            cinv_msg = bytes.fromhex(test_case["cinvMsg"])
            expected_error = test_case["expectedError"]
            try:
                chilldkg.participant_step2(hostseckey, state1, cmsg1, aux_rand)
            except UnknownFaultyParticipantOrCoordinatorError as e:
                assert_raises(
                    lambda e=e: chilldkg.participant_investigate(e, cinv_msg),
                    expected_error,
                )
            except Exception as e:
                raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
            else:
                raise AssertionError("Expected exception")
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_coordinator_step1_vectors():
    input_file = VECTORS_DIR / "coordinator_step1_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0
    for group in test_data["testGroups"]:
        pmsg1_pool = group["pmsg1Pool"]

        for test_case in group["validTestCases"]:
            pmsgs1 = [bytes.fromhex(pmsg1_pool[i]) for i in test_case["pmsg1Indices"]]
            params = params_from_dict(test_case["params"])
            expected_cmsg1 = test_case["expectedCmsg1"]
            _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
            assert bytes.fromhex(expected_cmsg1) == cmsg1
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in group["errorTestCases"]:
            pmsgs1 = [bytes.fromhex(pmsg1_pool[i]) for i in test_case["pmsg1Indices"]]
            params = params_from_dict(test_case["params"])
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.coordinator_step1(pmsgs1, params), expected_error
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_coordinator_finalize_vectors():
    input_file = VECTORS_DIR / "coordinator_finalize_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0

    for group in test_data["testGroups"]:
        params = params_from_dict(group["params"])
        pmsgs1 = [bytes.fromhex(m) for m in group["pmsgs1"]]
        pmsg2_pool = group["pmsg2Pool"]

        state, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
        assert bytes.fromhex(group["cmsg1"]) == cmsg1

        for test_case in group["validTestCases"]:
            pmsgs2 = [bytes.fromhex(pmsg2_pool[i]) for i in test_case["pmsg2Indices"]]
            cmsg2, cout, crec = chilldkg.coordinator_finalize(state, pmsgs2)
            expected_cmsg2 = test_case["expectedOutput"]["cmsg2"]
            expected_cout = test_case["expectedOutput"]["dkgOutput"]
            expected_crec = test_case["expectedOutput"]["recoveryData"]
            assert bytes.fromhex(expected_cmsg2) == cmsg2
            assert expected_cout == dkg_output_asdict(cout)
            assert bytes.fromhex(expected_crec) == crec
            total_cases += 1
            assert test_case["tcId"] == total_cases

        for test_case in group["errorTestCases"]:
            pmsgs2 = [bytes.fromhex(pmsg2_pool[i]) for i in test_case["pmsg2Indices"]]
            expected_error = test_case["expectedError"]
            assert_raises(
                lambda: chilldkg.coordinator_finalize(state, pmsgs2), expected_error
            )
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_coordinator_investigate_vectors():
    input_file = VECTORS_DIR / "coordinator_investigate_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    total_cases = 0

    for group in test_data["testGroups"]:
        params = params_from_dict(group["params"])
        pmsgs1 = [bytes.fromhex(m) for m in group["pmsgs1"]]

        for test_case in group["validTestCases"]:
            cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
            expected_cinv_msgs = test_case["expectedCinvMsgs"]
            assert [bytes.fromhex(m) for m in expected_cinv_msgs] == cinv_msgs
            total_cases += 1
            assert test_case["tcId"] == total_cases

    assert test_data["totalTests"] == total_cases


def test_recover_vectors():
    input_file = VECTORS_DIR / "recover_vectors.json"
    with open(input_file) as f:
        test_data = json.load(f)

    valid_test_cases = test_data["validTestCases"]
    error_test_cases = test_data["errorTestCases"]
    assert test_data["totalTests"] == len(valid_test_cases) + len(error_test_cases)

    for test_case in valid_test_cases:
        hostseckey = (
            bytes.fromhex(test_case["hostseckey"]) if test_case["hostseckey"] else None
        )
        recovery_data = bytes.fromhex(test_case["recoveryData"])
        if hostseckey is None:
            out, params = chilldkg.coordinator_recover(recovery_data)
        else:
            out, params = chilldkg.participant_recover(hostseckey, recovery_data)
        expected_out = test_case["expectedOutput"]["dkgOutput"]
        expected_params = test_case["expectedOutput"]["params"]
        assert expected_out == dkg_output_asdict(out)
        assert expected_params == params_asdict(params)

    for test_case in error_test_cases:
        hostseckey = (
            bytes.fromhex(test_case["hostseckey"]) if test_case["hostseckey"] else None
        )
        recovery_data = bytes.fromhex(test_case["recoveryData"])
        expected_error = test_case["expectedError"]
        if hostseckey is None:
            assert_raises(
                lambda: chilldkg.coordinator_recover(recovery_data), expected_error
            )
        else:
            assert_raises(
                lambda: chilldkg.participant_recover(hostseckey, recovery_data),
                expected_error,
            )


def test_recovery_acknowledgment():
    t, n = 2, 3
    hostseckeys = [random_bytes(32) for _ in range(n)]
    hostpubkeys = [chilldkg.hostpubkey_gen(hostseckey) for hostseckey in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)

    results = simulate_chilldkg(hostseckeys, t, investigation=False)
    recovery_data = results[1][1]  # First participant's recovery data

    ack_sigs = []
    for i in range(n):
        ack_sig = chilldkg.participant_recovery_ack_sign(
            hostseckeys[i], recovery_data, params, random_bytes(32)
        )
        assert len(ack_sig) == 64
        ack_sigs.append(ack_sig)

    chilldkg.participant_recovery_acks_verify(recovery_data, params, ack_sigs)

    # Wrong hostseckey length
    try:
        chilldkg.participant_recovery_ack_sign(
            random_bytes(16), recovery_data, params, random_bytes(32)
        )
    except ValueError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid hostpubkey in params
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"
    invalid_params = chilldkg.SessionParams([hostpubkeys[0], invalid_hostpubkey], t)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.InvalidHostPubkeyError:
        pass
    else:
        assert False, "Expected exception"

    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, invalid_params, ack_sigs
        )
    except chilldkg.InvalidHostPubkeyError:
        pass
    else:
        assert False, "Expected exception"

    # Duplicate hostpubkey in params
    invalid_params = chilldkg.SessionParams([hostpubkeys[0], hostpubkeys[0]], t)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.DuplicateHostPubkeyError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid threshold in params
    invalid_params = chilldkg.SessionParams(hostpubkeys, n + 1)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.ThresholdOrCountError:
        pass
    else:
        assert False, "Expected exception"

    # Wrong hostseckey
    try:
        chilldkg.participant_recovery_ack_sign(
            random_bytes(32), recovery_data, params, random_bytes(32)
        )
    except chilldkg.HostSeckeyError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid randomness length
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, params, random_bytes(16)
        )
    except ValueError:
        pass
    else:
        assert False, "Expected exception"

    # Mismatched params
    invalid_params = chilldkg.SessionParams(hostpubkeys, t + 1)
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], recovery_data, invalid_params, random_bytes(32)
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, invalid_params, ack_sigs
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    # Corrupted recovery data
    corrupted_recovery_data = random_bytes(len(recovery_data))
    try:
        chilldkg.participant_recovery_ack_sign(
            hostseckeys[0], corrupted_recovery_data, params, random_bytes(32)
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    try:
        chilldkg.participant_recovery_acks_verify(
            corrupted_recovery_data, params, ack_sigs
        )
    except chilldkg.RecoveryDataError:
        pass
    else:
        assert False, "Expected exception"

    # Invalid signature
    invalid_ack_sigs = ack_sigs[:]
    invalid_ack_sigs[1] = random_bytes(64)
    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, params, invalid_ack_sigs
        )
    except chilldkg.InvalidRecoveryAckError as e:
        assert e.participant_id == 1
    else:
        assert False, "Expected exception"

    # Wrong signature length
    wrong_length_sigs = ack_sigs[:]
    wrong_length_sigs[0] = random_bytes(32)
    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, params, wrong_length_sigs
        )
    except ValueError:
        pass
    else:
        assert False, "Expected exception"

    # Wrong number of signatures
    wrong_count_sigs = ack_sigs[:-1]  # n-1 instead of n
    try:
        chilldkg.participant_recovery_acks_verify(
            recovery_data, params, wrong_count_sigs
        )
    except ValueError:
        pass
    else:
        assert False, "Expected exception"


test_chilldkg_params_validate()
test_vss_correctness()
test_recover_secret()
test_recovery_acknowledgment()
for t, n in [(1, 1), (1, 2), (2, 2), (2, 3), (2, 5)]:
    test_correctness(t, n, simulate_simplpedpop)
    test_correctness(t, n, simulate_simplpedpop, investigation=True)
    test_correctness(t, n, simulate_encpedpop)
    test_correctness(t, n, simulate_encpedpop, investigation=True)
    test_correctness(t, n, simulate_chilldkg, recovery=True)
    test_correctness(t, n, simulate_chilldkg, recovery=True, investigation=True)
    test_correctness(t, n, simulate_chilldkg_full, recovery=True)
test_hostpubkey_gen_vectors()
test_params_hash_vectors()
test_participant_step1_vectors()
test_participant_step2_vectors()
test_participant_finalize_vectors()
test_participant_investigate_vectors()
test_coordinator_step1_vectors()
test_coordinator_finalize_vectors()
test_coordinator_investigate_vectors()
test_recover_vectors()
