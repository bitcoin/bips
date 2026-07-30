from secp256k1lab.secp256k1 import Scalar
from secp256k1lab.util import bytes_from_int

from chilldkg_ref import chilldkg

from .fixtures import AUX_RAND_HEX, HOSTSECKEYS_HEX, RANDOMS_HEX
from .util import (
    assign_tc_ids,
    bytes_to_hex,
    dkg_output_asdict,
    expect_exception,
    hex_list_to_bytes,
    params_asdict,
)


def generate_hostpubkey_vectors():
    description = [
        "Test vectors for hostpubkey_gen(hostseckey).",
        "Generates a compressed public key (33 bytes) from a 32-byte host secret key.",
        "",
        "For each valid test case:",
        "  Call hostpubkey_gen(hostseckey) and verify the result equals expectedHostpubkey.",
        "",
        "For each error test case:",
        "  Call hostpubkey_gen(hostseckey) and verify it raises an exception matching expectedError.",
        "  The expectedError object contains 'type' (the exception class name).",
    ]
    valid_cases = []
    error_cases = []

    # --- Valid test case ---
    hostseckey = bytes.fromhex(
        "631C047D50A67E45E27ED1FF25FCE179CAF059A2120D346ACD9774C1F2BAB66F"
    )
    expected_pubkey = chilldkg.hostpubkey_gen(hostseckey)
    valid_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckey),
            "expectedHostpubkey": bytes_to_hex(expected_pubkey),
            "comment": "valid host secret key",
        }
    )

    # --- Error test case: Wrong length ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: chilldkg.hostpubkey_gen(short_hostseckey), ValueError
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(short_hostseckey),
            "expectedError": error,
            "comment": "length of host secret key is not 32 bytes",
        }
    )
    # --- Error test case: Out-of-range hostseckey ---
    invalid_hostseckey = bytes_from_int(Scalar.SIZE)
    error = expect_exception(
        lambda: chilldkg.hostpubkey_gen(invalid_hostseckey), chilldkg.HostSeckeyError
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(invalid_hostseckey),
            "expectedError": error,
            "comment": "host secret key is out of range",
        }
    )
    # --- Error test case: zeroed hostseckey ---
    zeroed_hostseckey = b"\x00" * 32
    error = expect_exception(
        lambda: chilldkg.hostpubkey_gen(zeroed_hostseckey), chilldkg.HostSeckeyError
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(zeroed_hostseckey),
            "expectedError": error,
            "comment": "zeroed host secret key",
        }
    )

    groups = [{"validTestCases": valid_cases, "errorTestCases": error_cases}]
    total_tests = assign_tc_ids(groups)
    return {
        "description": description,
        "totalTests": total_tests,
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_params_hash_vectors():
    description = [
        "Test vectors for params_hash(params).",
        "Computes a 32-byte hash of the session parameters (hostpubkeys, threshold).",
        "",
        "For each valid test case:",
        "  Call params_hash(params) and verify the result equals expectedParamsHash.",
        "",
        "For each error test case:",
        "  Call params_hash(params) and verify it raises an exception matching expectedError.",
        "  The expectedError object contains 'type' (the exception class name).",
        "  Some errors include 'participantId' (identifier of the blamed participant)",
        "  or 'participantId1'/'participantId2' (identifiers of participants with duplicate keys).",
    ]
    valid_cases = []
    error_cases = []
    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]

    # --- Valid test cases ---
    cases = [
        {"t": 2, "comment": "standard 2-of-3 threshold"},
        {"t": 1, "comment": "min threshold value"},
        {"t": len(hostpubkeys), "comment": "max threshold value"},
    ]

    for case in cases:
        t = case["t"]
        params = chilldkg.SessionParams(hostpubkeys, t)
        expected_params_hash = chilldkg.params_hash(params)
        test_case = {
            "params": params_asdict(params),
            "expectedParamsHash": bytes_to_hex(expected_params_hash),
            "comment": case["comment"],
        }
        valid_cases.append(test_case)

    # --- Error test case: Invalid threshold ---
    t = 0
    invalid_params = chilldkg.SessionParams(hostpubkeys, t)
    error = expect_exception(
        lambda: chilldkg.params_hash(invalid_params), chilldkg.ThresholdOrCountError
    )
    error_cases.append(
        {
            "params": params_asdict(invalid_params),
            "expectedError": error,
            "comment": "invalid threshold value",
        }
    )
    # --- Error test case: hostpubkeys list contains an invalid value ---
    invalid_hostpubkey = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    t = 2
    with_invalid = [hostpubkeys[0], invalid_hostpubkey, hostpubkeys[2]]
    invalid_params = chilldkg.SessionParams(with_invalid, t)
    error = expect_exception(
        lambda: chilldkg.params_hash(invalid_params), chilldkg.InvalidHostPubkeyError
    )
    error_cases.append(
        {
            "params": params_asdict(invalid_params),
            "expectedError": error,
            "comment": "hostpubkeys list contains an invalid value",
        }
    )
    # --- Error test case: hostpubkeys list contains duplicate values ---
    t = 2
    with_duplicate = [hostpubkeys[0], hostpubkeys[1], hostpubkeys[2], hostpubkeys[1]]
    duplicate_params = chilldkg.SessionParams(with_duplicate, t)
    error = expect_exception(
        lambda: chilldkg.params_hash(duplicate_params),
        chilldkg.DuplicateHostPubkeyError,
    )
    error_cases.append(
        {
            "params": params_asdict(duplicate_params),
            "expectedError": error,
            "comment": "hostpubkeys list contains duplicate values",
        }
    )

    groups = [{"validTestCases": valid_cases, "errorTestCases": error_cases}]
    total_tests = assign_tc_ids(groups)
    return {
        "description": description,
        "totalTests": total_tests,
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }


def generate_recover_vectors():
    description = [
        "Test vectors for participant_recover(hostseckey, recovery_data) and",
        "coordinator_recover(recovery_data).",
        "Recovers a DKG output and session parameters from serialized recovery data.",
        "If hostseckey is null, recovery is performed as coordinator (secshare will be null).",
        "If hostseckey is a 32-byte hex string, recovery is performed as the corresponding participant.",
        "",
        "For each valid test case:",
        "  Call participant_recover(hostseckey, recoveryData) or coordinator_recover(recoveryData)",
        "  (if hostseckey is null) and verify the result matches expectedOutput.",
        "  expectedOutput contains 'dkgOutput' (with secshare, threshPk, pubshares)",
        "  and 'params' (with hostpubkeys, t).",
        "",
        "For each error test case:",
        "  Call participant_recover(hostseckey, recoveryData) or coordinator_recover(recoveryData)",
        "  (if hostseckey is null) and verify it raises an exception matching expectedError.",
    ]
    valid_cases = []
    error_cases = []

    hostseckeys = hex_list_to_bytes(HOSTSECKEYS_HEX[:3])
    hostpubkeys = [chilldkg.hostpubkey_gen(sk) for sk in hostseckeys]
    params = chilldkg.SessionParams(hostpubkeys, 2)
    randoms = hex_list_to_bytes(RANDOMS_HEX[:3])
    assert len(randoms) == len(hostpubkeys)
    pstates1 = []
    pmsgs1 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step1(hostseckeys[i], params, randoms[i])
        pstates1.append(state)
        pmsgs1.append(msg)
    cstate, cmsg1 = chilldkg.coordinator_step1(pmsgs1, params)

    aux_rand = bytes.fromhex(AUX_RAND_HEX)
    pstates2 = []
    pmsgs2 = []
    for i in range(len(hostpubkeys)):
        state, msg = chilldkg.participant_step2(
            hostseckeys[i], pstates1[i], cmsg1, aux_rand
        )
        pstates2.append(state)
        pmsgs2.append(msg)
    cmsg2, cout, crec = chilldkg.coordinator_finalize(cstate, pmsgs2)
    pout, prec = chilldkg.participant_finalize(pstates2[0], cmsg2)
    assert prec == crec

    # --- Valid test case: participant recovery ---
    pout_rec, params_rec = chilldkg.participant_recover(hostseckeys[0], prec)
    assert pout_rec == pout
    assert params_rec == params
    valid_cases.append(
        {
            "hostseckey": bytes_to_hex(hostseckeys[0]),
            "recoveryData": bytes_to_hex(prec),
            "expectedOutput": {
                "dkgOutput": dkg_output_asdict(pout_rec),
                "params": params_asdict(params_rec),
            },
            "comment": "participant recovery",
        }
    )
    # --- Valid test case: coordinator recovery ---
    cout_rec, params_rec = chilldkg.coordinator_recover(crec)
    assert cout_rec == cout
    assert params_rec == params
    valid_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(crec),
            "expectedOutput": {
                "dkgOutput": dkg_output_asdict(cout_rec),
                "params": params_asdict(params_rec),
            },
            "comment": "coordinator recovery",
        }
    )

    # --- Error test case: recovery data of invalid length ---
    invalid_crec = crec[1:]
    error = expect_exception(
        lambda: chilldkg.coordinator_recover(invalid_crec), chilldkg.RecoveryDataError
    )
    error_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(invalid_crec),
            "expectedError": error,
            "comment": "recovery data of invalid length",
        }
    )
    # --- Error test case: first coefficient of sum_coms is invalid ---
    invalid_ge = b"\x03" + 31 * b"\x00" + b"\x05"  # Invalid x-coordinate
    invalid_crec = crec[:4] + invalid_ge + crec[4 + 33 :]
    error = expect_exception(
        lambda: chilldkg.coordinator_recover(invalid_crec), chilldkg.RecoveryDataError
    )
    error_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(invalid_crec),
            "expectedError": error,
            "comment": "first coefficient of sum_coms is invalid",
        }
    )
    # --- Error test case: last share in enc_secshare list is out of range ---
    n = len(hostpubkeys)
    cert_len = chilldkg.certeq_cert_len(n)
    invalid_encshare = bytes.fromhex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    )
    invalid_crec = crec[: -cert_len - 32] + invalid_encshare + crec[-cert_len:]
    error = expect_exception(
        lambda: chilldkg.coordinator_recover(invalid_crec), chilldkg.RecoveryDataError
    )
    error_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(invalid_crec),
            "expectedError": error,
            "comment": "last share in enc_secshare list is invalid",
        }
    )
    # --- Error test case: invalid threshold ---
    t = params.t
    invalid_crec = b"\x00" * 4 + crec[4 + 33 * t :]
    error = expect_exception(
        lambda: chilldkg.coordinator_recover(invalid_crec), chilldkg.RecoveryDataError
    )
    error_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(invalid_crec),
            "expectedError": error,
            "comment": "invalid threshold",
        }
    )
    # --- Error test case: first pubkey in the hostpubkey list is invalid ---
    invalid_ge = b"\x03" + 31 * b"\x00" + b"\x05"
    invalid_crec = crec[: 4 + 33 * t] + invalid_ge + crec[4 + 33 * t + 33 :]
    error = expect_exception(
        lambda: chilldkg.coordinator_recover(invalid_crec), chilldkg.RecoveryDataError
    )
    error_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(invalid_crec),
            "expectedError": error,
            "comment": "first pubkey in the hostpubkey list is invalid",
        }
    )
    # --- Error test case: last pubnonce in the pubnonces list was tampered with ---
    n = len(hostpubkeys)
    cert_len = chilldkg.certeq_cert_len(n)
    rand_ge = bytes.fromhex(
        "03421F5FC9A21065445C96FDB91C0C1E2F2431741C72713B4B99DDCB316F31E9FC"
    )
    invalid_crec = (
        crec[: -cert_len - 32 * n - 33] + rand_ge + crec[-cert_len - 32 * n :]
    )
    error = expect_exception(
        lambda: chilldkg.coordinator_recover(invalid_crec), chilldkg.RecoveryDataError
    )
    error_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(invalid_crec),
            "expectedError": error,
            "comment": "last pubnonce in the pubnonces list was tampered with (doesn't match signed certificate)",
        }
    )
    # --- Error test case: last signature in the certificate is invalid ---
    rand_sig = bytes.fromhex(
        "09C289578B96E6283AB13E4741FB489FC147FB1A5F446A314BA73C052131EFB04B83247A0BCEDF5205202AD64188B24B0BC5B51A17AEB218BD98DBE000C843B9"
    )
    invalid_crec = crec[:-64] + rand_sig
    error = expect_exception(
        lambda: chilldkg.coordinator_recover(invalid_crec), chilldkg.RecoveryDataError
    )
    error_cases.append(
        {
            "hostseckey": None,
            "recoveryData": bytes_to_hex(invalid_crec),
            "expectedError": error,
            "comment": "last signature in the certificate is invalid",
        }
    )
    # --- Error test case: invalid hostseckey ---
    short_hostseckey = bytes.fromhex("631C047D50A67E45E27ED1FF25FCE179")
    assert len(short_hostseckey) == 16
    error = expect_exception(
        lambda: chilldkg.participant_recover(short_hostseckey, crec), ValueError
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(short_hostseckey),
            "recoveryData": bytes_to_hex(crec),
            "expectedError": error,
            "comment": "invalid hostseckey",
        }
    )
    # --- Error test case: hostseckey doesn't match any hostpubkey ---
    rand_hostseckey = bytes.fromhex(
        "759DE9306FB02B3D84C455112BF1F3360401DC383ECD1FCEDE59EC809D6F9FE7"
    )
    error = expect_exception(
        lambda: chilldkg.participant_recover(rand_hostseckey, crec),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(rand_hostseckey),
            "recoveryData": bytes_to_hex(crec),
            "expectedError": error,
            "comment": "host secret key doesn't match any hostpubkey",
        }
    )
    # --- Error test case: zero hostseckey ---
    zero_hostseckey = b"\x00" * 32
    error = expect_exception(
        lambda: chilldkg.participant_recover(zero_hostseckey, crec),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(zero_hostseckey),
            "recoveryData": bytes_to_hex(crec),
            "expectedError": error,
            "comment": "host secret key is zero",
        }
    )
    # --- Error test case: out-of-range hostseckey ---
    overflow_hostseckey = bytes_from_int(Scalar.SIZE)
    error = expect_exception(
        lambda: chilldkg.participant_recover(overflow_hostseckey, crec),
        chilldkg.HostSeckeyError,
    )
    error_cases.append(
        {
            "hostseckey": bytes_to_hex(overflow_hostseckey),
            "recoveryData": bytes_to_hex(crec),
            "expectedError": error,
            "comment": "host secret key is out of range",
        }
    )

    groups = [{"validTestCases": valid_cases, "errorTestCases": error_cases}]
    total_tests = assign_tc_ids(groups)
    return {
        "description": description,
        "totalTests": total_tests,
        "validTestCases": valid_cases,
        "errorTestCases": error_cases,
    }
