import copy

from secp256k1lab.secp256k1 import GE, Scalar
from secp256k1lab.util import bytes_from_int

from chilldkg_ref import chilldkg

from .fixtures import AUX_RAND_HEX, HOSTSECKEYS_HEX, RANDOMS_HEX, THRESHOLD_CONFIGS
from .util import (
    assign_tc_ids,
    bytes_to_hex,
    dkg_output_asdict,
    expect_exception,
    expect_faulty_exception,
    hex_list_to_bytes,
    params_asdict,
)

# Arbitrary EC point x-coordinate used as a hardcoded wrong value in test vectors.
ARBITRARY_POINT_X = 0x60C301C1EEC41AD16BF53F55F97B7B6EB842D9E2B8139712BA54695FF7116073

PARTICIPANT_STEP1_DESCRIPTION = [
    "Test vectors for participant_step1(hostseckey, params, random).",
    "Executes the first round of DKG from a participant's perspective.",
    "Takes the participant's host secret key, session parameters, and 32 bytes of fresh randomness.",
    "Returns an opaque state object and a participant message (pmsg1) to send to the coordinator.",
    "",
    "For each valid test case:",
    "  Call participant_step1(hostseckey, params, random).",
    "  Verify the returned pmsg1 equals expectedPmsg1.",
    "",
    "For each error test case:",
    "  Call participant_step1(hostseckey, params, random).",
    "  Verify it raises an exception matching expectedError.",
]


def generate_participant_step1_group(t, n):
    valid_cases = []
    error_cases = []

    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    random = bytes.fromhex(RANDOMS_HEX[0])

    # --- Valid test case ---
    params = chilldkg.SessionParams(hostpubkeys, t)
    _, expected_pmsg1 = chilldkg.participant_step1(hostseckeys[0], params, random)
    valid_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expectedPmsg1": bytes_to_hex(expected_pmsg1),
            "comment": "valid participant step1",
        }
    )

    # --- Error test case: Wrong hostseckey length ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: chilldkg.participant_step1(short_hostseckey, params, random),
        ValueError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(short_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "length of host secret key is not 32 bytes",
        }
    )
    # --- Error test case: zero hostseckey ---
    zero_hostseckey = b"\x00" * 32
    error = expect_exception(
        lambda: chilldkg.participant_step1(zero_hostseckey, params, random),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(zero_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "host secret key is zero",
        }
    )
    # --- Error test case: Out-of-range hostseckey ---
    invalid_hostseckey = bytes_from_int(Scalar.SIZE)
    error = expect_exception(
        lambda: chilldkg.participant_step1(invalid_hostseckey, params, random),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(invalid_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "host secret key is out of range",
        }
    )
    # --- Error test case: Invalid threshold ---
    invalid_params = chilldkg.SessionParams(hostpubkeys, 0)
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.ThresholdOrCountError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "invalid threshold value",
        }
    )
    # --- Error test case: t > n ---
    invalid_params = chilldkg.SessionParams(hostpubkeys, n + 1)
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.ThresholdOrCountError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "threshold exceeds the number of participants",
        }
    )
    # --- Error test case: hostpubkeys list contains a value with an invalid prefix ---
    invalid_hostpubkey = b"\xeb" * 33  # invalid prefix
    with_invalid = hostpubkeys[:-1] + [invalid_hostpubkey]
    invalid_params = chilldkg.SessionParams(with_invalid, t)
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.InvalidHostPubkeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "hostpubkeys list contains an invalid value with invalid prefix",
        }
    )
    # --- Error test case: hostpubkeys list contains a value with an off-curve x-coordinate ---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # invalid x-coordinate
    with_invalid = hostpubkeys[:-1] + [invalid_hostpubkey]
    invalid_params = chilldkg.SessionParams(with_invalid, t)
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.InvalidHostPubkeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "hostpubkeys list contains an invalid value with invalid x-coordinate",
        }
    )
    # --- Error test case: hostpubkeys list contains an infinite value ---
    infinity_hostpubkey = b"\x00" * 33  # infinity
    with_infinity = hostpubkeys[:-1] + [infinity_hostpubkey]
    invalid_params = chilldkg.SessionParams(with_infinity, t)
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], invalid_params, random),
        chilldkg.InvalidHostPubkeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(invalid_params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "hostpubkeys list contains an infinity point",
        }
    )
    # --- Error test case: hostpubkeys list contains duplicate values ---
    with_duplicate = hostpubkeys[:-1] + [hostpubkeys[0]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, t)
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], duplicate_params, random),
        chilldkg.DuplicateHostPubkeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(duplicate_params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "hostpubkeys list contains duplicate values",
        }
    )
    # --- Error test case: hostseckey doesn't match any hostpubkey ---
    rand_hostseckey = bytes.fromhex(
        "759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7"
    )
    error = expect_exception(
        lambda: chilldkg.participant_step1(rand_hostseckey, params, random),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(rand_hostseckey),
            "params": params_asdict(params),
            "random": bytes_to_hex(random),
            "expectedError": error,
            "comment": "host secret key doesn't match any hostpubkey",
        }
    )
    # --- Error test case: Wrong randomness length ---
    short_random = bytes.fromhex("42B53D62E27380D6F7096EDA1C28C57D")  # 16 bytes
    assert len(short_random) == 16
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], params, short_random),
        ValueError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(short_random),
            "expectedError": error,
            "comment": "length of randomness is not 32 bytes",
        }
    )
    # --- Error test case: Zero randomness ---
    zero_random = b"\x00" * 32
    error = expect_exception(
        lambda: chilldkg.participant_step1(hostseckeys[0], params, zero_random),
        chilldkg.RandomnessError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "params": params_asdict(params),
            "random": bytes_to_hex(zero_random),
            "expectedError": error,
            "comment": "randomness is zero",
        }
    )

    return {
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_participant_step1_vectors():
    groups = [generate_participant_step1_group(t, n) for t, n in THRESHOLD_CONFIGS]
    total_tests = assign_tc_ids(groups)
    return {
        "description": PARTICIPANT_STEP1_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }


PARTICIPANT_STEP2_DESCRIPTION = [
    "Test vectors for participant_step2(hostseckey, pstate1, cmsg1, auxRand).",
    "Executes the second round of DKG from a participant's perspective.",
    "Processes the coordinator's aggregated message (cmsg1) and produces a partial signature (pmsg2).",
    "",
    "Harness setup (re-derive state from prior round):",
    "  1. Call participant_step1(hostseckey, params, random) to obtain (pstate1, pmsg1_out).",
    "  2. Assert pmsg1_out == pmsg1 (verifies your step1 implementation before testing step2).",
    "",
    "For each valid test case:",
    "  Call participant_step2(hostseckey, pstate1, cmsg1, auxRand).",
    "  Verify the returned pmsg2 equals expectedPmsg2.",
    "",
    "For each error test case:",
    "  Call participant_step2(hostseckey, pstate1, cmsg1, auxRand).",
    "  Verify it raises an exception matching expectedError.",
    "  Error objects contain 'type' (exception class name) and optionally:",
    "    - 'participantId': identifier of the blamed party (for FaultyParticipantOrCoordinatorError)",
    "    - 'message': human-readable description (informational, not required to match exactly)",
]


def generate_participant_step2_group(t, n):
    valid_cases = []
    error_cases = []

    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:n])
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)
    aux_rand = bytes.fromhex(AUX_RAND_HEX)

    # --- Valid test case ---
    _, pmsg2 = chilldkg.participant_step2(hostseckeys[0], pstates1[0], cmsg1, aux_rand)
    valid_cases.append(
        {
            "cmsg1": bytes_to_hex(cmsg1),
            "expectedPmsg2": bytes_to_hex(pmsg2),
            "comment": "valid participant step2",
        }
    )

    cmsg1_parsed = chilldkg.CoordinatorMsg1.from_bytes(
        cmsg1, t=params.t, n=len(params.hostpubkeys)
    )
    # --- Error test case: Wrong aux randomness length ---
    short_aux_rand = bytes.fromhex("42B53D62E27380D6F7096EDA1C28C57D")
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], cmsg1, short_aux_rand
        ),
        ValueError,
    )
    error_cases.append(
        {
            "auxRand": bytes_to_hex(short_aux_rand),
            "cmsg1": bytes_to_hex(cmsg1),
            "expectedError": error,
            "comment": "length of aux randomness is not 32 bytes",
        }
    )
    # --- Error test case: hostseckey does not match the one in state1 ---
    mismatched_hostseckey = hostseckeys[1]
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            mismatched_hostseckey, pstates1[0], cmsg1, aux_rand
        ),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(mismatched_hostseckey),
            "cmsg1": bytes_to_hex(cmsg1),
            "expectedError": error,
            "comment": "hostseckey does not match the one used in participant_step1",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an invalid prefix at index 0 (own pubnonce) ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[0] = b"\xeb" * 33  # invalid prefix
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has an invalid prefix at index 0 (own pubnonce)",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an invalid prefix at index 1 ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[1] = b"\xeb" * 33  # invalid prefix
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_faulty_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyParticipantOrCoordinatorError,
        1,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has an invalid prefix at index 1",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an off-curve x-coordinate at index 0 (own pubnonce) ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[0] = (
        b"\x03" + 31 * b"\x00" + b"\x05"
    )  # Invalid x-coordinate
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has an off-curve x-coordinate at index 0 (own pubnonce)",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an off-curve x-coordinate at index 1 ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[1] = (
        b"\x03" + 31 * b"\x00" + b"\x05"
    )  # Invalid x-coordinate
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_faulty_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyParticipantOrCoordinatorError,
        1,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has an off-curve x-coordinate at index 1",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an arbitrary value at index 0 (own pubnonce) ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[0] = GE.lift_x(
        ARBITRARY_POINT_X
    ).to_bytes_compressed()
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has an arbitrary value at index 0 (own pubnonce)",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an arbitrary value at index 1 ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[1] = GE.lift_x(
        ARBITRARY_POINT_X
    ).to_bytes_compressed()
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.UnknownFaultyParticipantOrCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has an arbitrary value at index 1",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an infinite value at index 0 (own pubnonce) ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[0] = b"\x00" * 33  # infinity
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has the infinity point at index 0 (own pubnonce)",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has an infinite value at index 1 ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[1] = b"\x00" * 33  # infinity
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_faulty_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyParticipantOrCoordinatorError,
        1,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has the infinity point at index 1",
        }
    )
    # --- Error test case: pubnonces list in cmsg1 has duplicate values ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.pubnonces[1] = (
        invalid_cmsg1_parsed.enc_cmsg.pubnonces[0]
    )
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.UnknownFaultyParticipantOrCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pubnonces list has duplicate values",
        }
    )
    # --- Error test case: missing encrypted secret shares ---
    invalid_cmsg1 = cmsg1[:-1]
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        ValueError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: missing encrypted secret shares",
        }
    )
    # --- Error test case: coms_to_secrets list in cmsg1 has an arbitrary value at index 0 ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.coms_to_secrets[0] = GE.lift_x(
        ARBITRARY_POINT_X
    )
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: coms_to_secrets list has an arbitrary value at index 0",
        }
    )
    # --- Error test case: coms_to_secrets list in cmsg1 has infinity at index 1 ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.coms_to_secrets[1] = GE()  # infinity
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_faulty_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyParticipantOrCoordinatorError,
        1,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: coms_to_secrets list has infinity at index 1",
        }
    )
    # --- Error test case: pop list in cmsg1 has an invalid value at index 1 ---
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.pops[1] = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )  # random 64 bytes (not a valid signature for any key)
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
    error = expect_faulty_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.FaultyParticipantOrCoordinatorError,
        1,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: pop list has an invalid value at index 1",
        }
    )
    if t > 1:
        # --- Error test case: sum_coms_to_nonconst_terms has an arbitrary value at index 0 ---
        invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
        invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.sum_coms_to_nonconst_terms[0] = (
            GE.lift_x(ARBITRARY_POINT_X)
        )
        invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
        error = expect_exception(
            lambda: chilldkg.participant_step2(
                hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
            ),
            chilldkg.UnknownFaultyParticipantOrCoordinatorError,
        )
        error_cases.append(
            {
                "cmsg1": bytes_to_hex(invalid_cmsg1),
                "expectedError": error,
                "comment": "invalid cmsg1: sum_coms_to_nonconst_terms has an arbitrary value at index 0",
            }
        )
        # --- Error test case: sum_coms_to_nonconst_terms has an infinite value at index 0 ---
        invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
        invalid_cmsg1_parsed.enc_cmsg.simpl_cmsg.sum_coms_to_nonconst_terms[0] = (
            GE()  # Infinity
        )
        invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()
        error = expect_exception(
            lambda: chilldkg.participant_step2(
                hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
            ),
            chilldkg.UnknownFaultyParticipantOrCoordinatorError,
        )
        error_cases.append(
            {
                "cmsg1": bytes_to_hex(invalid_cmsg1),
                "expectedError": error,
                "comment": "invalid cmsg1: sum_coms_to_nonconst_terms has the infinity point at index 0",
            }
        )
    # --- Error test case: Participant 1 sent an invalid secshare for participant 0 ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    pmsgs11_parsed = chilldkg.ParticipantMsg1.from_bytes(
        pmsgs1[1], t=params.t, n=len(params.hostpubkeys)
    )
    pmsgs11_parsed.enc_pmsg.enc_shares[0] += Scalar(17)
    invalid_pmsgs1[1] = pmsgs11_parsed.to_bytes()
    _, invalid_cmsg1 = chilldkg.coordinator_step1(invalid_pmsgs1, params)
    error = expect_exception(
        lambda: chilldkg.participant_step2(
            hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand
        ),
        chilldkg.UnknownFaultyParticipantOrCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg1": bytes_to_hex(invalid_cmsg1),
            "expectedError": error,
            "comment": "invalid cmsg1: participant 1 sent an invalid secshare for participant 0",
        }
    )

    return {
        "params": params_asdict(params),
        "hostseckey": bytes_to_hex(hostseckeys[0]),
        "random": bytes_to_hex(randoms[0]),
        "auxRand": bytes_to_hex(aux_rand),
        "pmsg1": bytes_to_hex(pmsgs1[0]),
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_participant_step2_vectors():
    groups = [generate_participant_step2_group(t, n) for t, n in THRESHOLD_CONFIGS]
    total_tests = assign_tc_ids(groups)
    return {
        "description": PARTICIPANT_STEP2_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }


PARTICIPANT_FINALIZE_DESCRIPTION = [
    "Test vectors for participant_finalize(pstate2, cmsg2).",
    "Finalizes the DKG protocol from a participant's perspective.",
    "Verifies the coordinator's certificate (cmsg2) and outputs the DKG result and recovery data.",
    "",
    "Harness setup (re-derive state through two prior rounds):",
    "  1. Call participant_step1(hostseckey, params, random) to obtain (pstate1, pmsg1_out).",
    "     Assert pmsg1_out == pmsg1.",
    "  2. Call participant_step2(hostseckey, pstate1, cmsg1, auxRand) to obtain (pstate2, pmsg2_out).",
    "     Assert pmsg2_out == pmsg2.",
    "",
    "For each valid test case:",
    "  Call participant_finalize(pstate2, cmsg2).",
    "  Verify the result matches expectedOutput (dkgOutput and recoveryData).",
    "",
    "For each error test case:",
    "  Call participant_finalize(pstate2, cmsg2).",
    "  Verify it raises an exception matching expectedError.",
]


def generate_participant_finalize_group(t, n):
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:n])
    assert len(randoms) == len(hostpubkeys)
    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    pstates2 = []
    pmsgs2 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step2(
            hostseckeys[i], pstates1[i], cmsg1, aux_rand
        )
        pstates2.append(state)
        pmsgs2.append(msg)

    valid_cases = []
    error_cases = []

    vectors = {
        "params": params_asdict(params),
        "hostseckey": bytes_to_hex(hostseckeys[0]),
        "random": bytes_to_hex(randoms[0]),
        "auxRand": bytes_to_hex(aux_rand),
        "pmsg1": bytes_to_hex(pmsgs1[0]),
        "cmsg1": bytes_to_hex(cmsg1),
        "pmsg2": bytes_to_hex(pmsgs2[0]),
    }

    # --- Valid test case ---
    cmsg2, _, _ = chilldkg.coordinator_finalize(cstate, pmsgs2)
    pout, prec = chilldkg.participant_finalize(pstates2[0], cmsg2)

    valid_cases.append(
        {
            "cmsg2": bytes_to_hex(cmsg2),
            "expectedOutput": {
                "dkgOutput": dkg_output_asdict(pout),
                "recoveryData": bytes_to_hex(prec),
            },
            "comment": "valid participant finalize",
        }
    )

    # --- Error test case: cmsg2 missing the last signature ---
    invalid_cmsg2 = chilldkg.CoordinatorMsg2(
        cmsg2[:-64]
    ).to_bytes()  # remove last signature
    error = expect_exception(
        lambda: chilldkg.participant_finalize(pstates2[0], invalid_cmsg2),
        ValueError,
    )
    error_cases.append(
        {
            "cmsg2": bytes_to_hex(invalid_cmsg2),
            "expectedError": error,
            "comment": "invalid cmsg2: length is invalid (missing last signature)",
        }
    )
    # --- Error test case: cmsg2 is too long ---
    invalid_cmsg2 = chilldkg.CoordinatorMsg2(cmsg2 + bytes(64)).to_bytes()
    error = expect_exception(
        lambda: chilldkg.participant_finalize(pstates2[0], invalid_cmsg2),
        ValueError,
    )
    error_cases.append(
        {
            "cmsg2": bytes_to_hex(invalid_cmsg2),
            "expectedError": error,
            "comment": "invalid cmsg2: length is invalid (extra data appended)",
        }
    )

    # --- Error test case: cmsg2 has invalid last signature ---
    random_sig = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )
    assert len(random_sig) == 64
    invalid_cmsg2_2 = chilldkg.CoordinatorMsg2(cmsg2[:-64] + random_sig).to_bytes()
    error2 = expect_exception(
        lambda: chilldkg.participant_finalize(pstates2[0], invalid_cmsg2_2),
        chilldkg.FaultyCoordinatorError,
    )
    error_cases.append(
        {
            "cmsg2": bytes_to_hex(invalid_cmsg2_2),
            "expectedError": error2,
            "comment": "invalid cmsg2: last signature is invalid",
        }
    )

    return {
        "params": vectors["params"],
        "hostseckey": vectors["hostseckey"],
        "random": vectors["random"],
        "auxRand": vectors["auxRand"],
        "pmsg1": vectors["pmsg1"],
        "cmsg1": vectors["cmsg1"],
        "pmsg2": vectors["pmsg2"],
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_participant_finalize_vectors():
    groups = [generate_participant_finalize_group(t, n) for t, n in THRESHOLD_CONFIGS]
    total_tests = assign_tc_ids(groups)
    return {
        "description": PARTICIPANT_FINALIZE_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }


PARTICIPANT_INVESTIGATE_DESCRIPTION = [
    "Test vectors for participant_investigate(error, cinv_msg).",
    "Narrows down a faulty party after participant_step2 raised UnknownFaultyParticipantOrCoordinatorError.",
    "This function always raises an exception (FaultyParticipantOrCoordinatorError or FaultyCoordinatorError).",
    "",
    "Harness setup:",
    "  1. Call participant_step1(hostseckey, params, random) to obtain (pstate1, pmsg1_out).",
    "     Assert pmsg1_out == pmsg1.",
    "  2. Per test case: look up cmsg1 from cmsg1Pool using cmsg1Index.",
    "  3. Call participant_step2(hostseckey, pstate1, cmsg1, auxRand).",
    "     It must raise UnknownFaultyParticipantOrCoordinatorError. Capture that error object.",
    "  4. Call participant_investigate(error, cinvMsg) and verify it raises expectedError.",
    "",
    "All test cases are error cases (this function never returns successfully).",
    "Error objects contain 'type' and optionally 'participantId' (identifier of the blamed party).",
]


def generate_participant_investigate_group(t, n):
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:n])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, t)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:n])
    assert len(randoms) == len(hostpubkeys)
    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    _, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    cmsg1_pool = []
    error_cases = []

    # --- Error test case: Participant 1 sent an invalid secshare for participant 0 ---
    invalid_pmsgs1 = copy.deepcopy(pmsgs1)
    invalid_pmsg1_parsed = chilldkg.ParticipantMsg1.from_bytes(
        invalid_pmsgs1[1], t=params.t, n=len(params.hostpubkeys)
    )
    invalid_pmsg1_parsed.enc_pmsg.enc_shares[0] += Scalar(17)
    invalid_pmsgs1[1] = invalid_pmsg1_parsed.to_bytes()
    _, invalid_cmsg1 = chilldkg.coordinator_step1(invalid_pmsgs1, params)
    try:
        chilldkg.participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(invalid_pmsgs1, params)
        error = expect_faulty_exception(
            lambda e=e: chilldkg.participant_investigate(e, cinv_msgs[0]),
            chilldkg.FaultyParticipantOrCoordinatorError,
            1,
        )
    else:
        assert False, "Expected exception"

    cmsg1_pool.append(bytes_to_hex(invalid_cmsg1))  # index 0
    error_cases.append(
        {
            "cmsg1Index": 0,
            "cinvMsg": bytes_to_hex(cinv_msgs[0]),
            "expectedError": error,
            "comment": "participant 1 sent an invalid secshare for participant 0",
        }
    )

    # --- Error test case: Coordinator tampered with participant 0's encrypted secshare ---
    cmsg1_parsed = chilldkg.CoordinatorMsg1.from_bytes(
        cmsg1, t=params.t, n=len(params.hostpubkeys)
    )
    invalid_cmsg1_parsed = copy.deepcopy(cmsg1_parsed)
    invalid_cmsg1_parsed.enc_secshares[0] += Scalar(17)
    invalid_cmsg1 = invalid_cmsg1_parsed.to_bytes()

    try:
        chilldkg.participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
        error = expect_exception(
            lambda e=e: chilldkg.participant_investigate(e, cinv_msgs[0]),
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"

    cmsg1_pool.append(bytes_to_hex(invalid_cmsg1))  # index 1
    error_cases.append(
        {
            "cmsg1Index": 1,
            "cinvMsg": bytes_to_hex(cinv_msgs[0]),
            "expectedError": error,
            "comment": "coordinator tampered with participant 0's encrypted secshare",
        }
    )

    # --- Error test case: Coordinator tampered with self-encrypted partial secshare ---
    try:
        # using the prior invalid_cmsg1 to trigger the error
        chilldkg.participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
        cinv_msg_parsed = chilldkg.CoordinatorInvestigationMsg.from_bytes(
            cinv_msgs[0], n=len(params.hostpubkeys)
        )
        invalid_cinv_msg0_parsed = copy.deepcopy(cinv_msg_parsed)
        invalid_cinv_msg0_parsed.enc_cinv.enc_partial_secshares[0] += Scalar(
            17
        )  # invalid share
        invalid_cinv_msg0 = invalid_cinv_msg0_parsed.to_bytes()
        error = expect_exception(
            lambda e=e: chilldkg.participant_investigate(e, invalid_cinv_msg0),
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"

    error_cases.append(
        {
            "cmsg1Index": 1,
            "cinvMsg": bytes_to_hex(invalid_cinv_msg0),
            "expectedError": error,
            "comment": "coordinator tampered with self-encrypted partial secshare (participant 0)",
        }
    )

    # --- Error test case: partial pubshares list in cinv_msg has an arbitrary value at index 1 ---
    try:
        # using the prior invalid_cmsg1 to trigger the error
        chilldkg.participant_step2(hostseckeys[0], pstates1[0], invalid_cmsg1, aux_rand)
    except chilldkg.UnknownFaultyParticipantOrCoordinatorError as e:
        cinv_msgs = chilldkg.coordinator_investigate(pmsgs1, params)
        cinv_msg_parsed = chilldkg.CoordinatorInvestigationMsg.from_bytes(
            cinv_msgs[0], n=len(params.hostpubkeys)
        )
        invalid_cinv_msg0_parsed = copy.deepcopy(cinv_msg_parsed)
        invalid_cinv_msg0_parsed.enc_cinv.partial_pubshares[1] = GE.lift_x(
            ARBITRARY_POINT_X
        )
        invalid_cinv_msg0 = invalid_cinv_msg0_parsed.to_bytes()
        error = expect_exception(
            lambda e=e: chilldkg.participant_investigate(e, invalid_cinv_msg0),
            chilldkg.FaultyCoordinatorError,
        )
    else:
        assert False, "Expected exception"

    error_cases.append(
        {
            "cmsg1Index": 1,
            "cinvMsg": bytes_to_hex(invalid_cinv_msg0),
            "expectedError": error,
            "comment": "partial pubshares list in cinv_msg has an arbitrary value at index 1",
        }
    )

    # TODO: add runtime_error test case

    return {
        "params": params_asdict(params),
        "hostseckey": bytes_to_hex(hostseckeys[0]),
        "random": bytes_to_hex(randoms[0]),
        "auxRand": bytes_to_hex(aux_rand),
        "pmsg1": bytes_to_hex(pmsgs1[0]),
        "cmsg1Pool": cmsg1_pool,
        "errorTestCases": error_cases,
    }


def generate_participant_investigate_vectors():
    groups = [
        generate_participant_investigate_group(t, n) for t, n in THRESHOLD_CONFIGS
    ]
    total_tests = assign_tc_ids(groups)
    return {
        "description": PARTICIPANT_INVESTIGATE_DESCRIPTION,
        "totalTests": total_tests,
        "testGroups": groups,
    }
