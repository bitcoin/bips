#!/usr/bin/env python3

import json
import os
import shutil
import sys
from typing import Dict, List, Sequence, Union
import secrets
import pprint

from frost_ref import (
    InvalidContributionError,
    SessionContext,
    SignersContext,
    deterministic_sign,
    nonce_agg,
    partial_sig_agg,
    partial_sig_verify,
    sign,
)
from frost_ref.signing import nonce_gen_internal
from secp256k1lab.secp256k1 import GE, Scalar
from secp256k1lab.keys import pubkey_gen_plain
from trusted_dealer import trusted_dealer_keygen


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: Sequence[bytes]) -> List[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: List[str]) -> List[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


def int_list_to_bytes(lst: List[int]) -> List[bytes]:
    return [Scalar(x).to_bytes() for x in lst]


ErrorInfo = Dict[str, Union[int, str, None, "ErrorInfo"]]


def exception_asdict(e: Exception) -> dict:
    error_info: ErrorInfo = {"type": e.__class__.__name__}

    for key, value in e.__dict__.items():
        if isinstance(value, (str, int, type(None))):
            error_info[key] = value
        elif isinstance(value, bytes):
            error_info[key] = bytes_to_hex(value)
        else:
            raise NotImplementedError(
                f"Conversion for type {type(value).__name__} is not implemented"
            )

    # If the last argument is not found in the instance’s attributes and
    # is a string, treat it as an extra message.
    if e.args and isinstance(e.args[-1], str) and e.args[-1] not in e.__dict__.values():
        error_info.setdefault("message", e.args[-1])
    return error_info


def expect_exception(try_fn, expected_exception):
    try:
        try_fn()
    except expected_exception as e:
        return exception_asdict(e)
    except Exception as e:
        raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
    else:
        raise AssertionError("Expected exception")


COMMON_RAND = bytes.fromhex(
    "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
)

COMMON_MSGS = [
    bytes.fromhex(
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"
    ),  # 32-byte message
    bytes.fromhex(""),  # Empty message
    bytes.fromhex(
        "2626262626262626262626262626262626262626262626262626262626262626262626262626"
    ),  # 38-byte message
]

COMMON_TWEAKS = hex_list_to_bytes(
    [
        "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
        "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
        "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
        "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",  # Invalid (exceeds group size)
    ]
)

SIG_AGG_TWEAKS = hex_list_to_bytes(
    [
        "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
        "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
        "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8",
    ]
)

INVALID_PUBSHARE = bytes.fromhex(
    "020000000000000000000000000000000000000000000000000000000000000007"
)


def write_test_vectors(filename, vectors):
    output_file = os.path.join("vectors", filename)
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


def get_common_setup():
    t, n, thresh_pk_ge, secshares, pubshares = frost_keygen_fixed()
    return (
        n,
        t,
        thresh_pk_ge.to_bytes_compressed(),
        thresh_pk_ge.to_bytes_xonly(),
        list(range(n)),
        secshares,
        pubshares,
    )


def generate_all_nonces(rand, secshares, pubshares, xonly_thresh_pk, msg=None):
    secnonces = []
    pubnonces = []
    for i in range(len(secshares)):
        sec, pub = nonce_gen_internal(
            rand, secshares[i], pubshares[i], xonly_thresh_pk, msg, None
        )
        secnonces.append(sec)
        pubnonces.append(pub)
    return secnonces, pubnonces


def frost_keygen_fixed():
    n = 3
    t = 2
    thresh_pubkey_bytes = bytes.fromhex(
        "03B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237"
    )
    thresh_pubkey_ge = GE.from_bytes_compressed(thresh_pubkey_bytes)
    secshares = hex_list_to_bytes(
        [
            "CCD2EF4559DB05635091D80189AB3544D6668EFC0500A8D5FF51A1F4D32CC1F1",
            "62A04F63F105A40FCF25634AA645D77AAC692641916E4DFC8C1EEC83CAB5BEBA",
            "F86DAF82883042BC4DB8EE93C2E079AF3D1A9A6DCD24935ED8BE959F9274FCC4",
        ]
    )
    pubshares = hex_list_to_bytes(
        [
            "022B02109FBCFB4DA3F53C7393B22E72A2A51C4AFBF0C01AAF44F73843CFB4B74B",
            "02EC6444271D791A1DA95300329DB2268611B9C60E193DABFDEE0AA816AE512583",
            "03113F810F612567D9552F46AF9BDA21A67D52060F95BD4A723F4B60B1820D3676",
        ]
    )
    return (t, n, thresh_pubkey_ge, secshares, pubshares)


# NOTE: This function is used only once to generate a long-term key for frost_keygen_fixed(). It is intentionally not called anywhere else. It will be used in case we decide to change the long-term key, in future.
def frost_keygen_random():
    random_scalar = Scalar.from_bytes_nonzero_checked(secrets.token_bytes(32))
    threshold_seckey = random_scalar.to_bytes()
    threshold_pubkey = pubkey_gen_plain(threshold_seckey)
    output_tpk, secshares, pubshares = trusted_dealer_keygen(random_scalar, 3, 2)
    assert threshold_pubkey == output_tpk

    print(f"threshold secret key: {threshold_seckey.hex().upper()}")
    print(f"threshold public key: {threshold_pubkey.hex().upper()}")
    print("secret shares:")
    pprint.pprint(bytes_list_to_hex(secshares))
    print("public shares:")
    pprint.pprint(bytes_list_to_hex(pubshares))


def generate_nonce_gen_vectors():
    vectors = {"test_cases": []}

    _, _, thresh_pk_ge, secshares, pubshares = frost_keygen_fixed()
    extra_in = bytes.fromhex(
        "0808080808080808080808080808080808080808080808080808080808080808"
    )
    xonly_thresh_pk = thresh_pk_ge.to_bytes_xonly()

    # --- Valid Test Case 1 ---
    msg = bytes.fromhex(
        "0101010101010101010101010101010101010101010101010101010101010101"
    )
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], xonly_thresh_pk, msg, extra_in
    )
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "threshold_pubkey": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "",
        }
    )
    # --- Valid Test Case 2 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        xonly_thresh_pk,
        COMMON_MSGS[1],
        extra_in,
    )
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "threshold_pubkey": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[1]),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "Empty Message",
        }
    )
    # --- Valid Test Case 3 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        xonly_thresh_pk,
        COMMON_MSGS[2],
        extra_in,
    )
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "threshold_pubkey": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[2]),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "38-byte message",
        }
    )
    # --- Valid Test Case 4 ---
    secnonce, pubnonce = nonce_gen_internal(COMMON_RAND, None, None, None, None, None)
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": None,
            "pubshare": None,
            "threshold_pubkey": None,
            "msg": None,
            "extra_in": None,
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "Every optional parameter is absent",
        }
    )

    write_test_vectors("nonce_gen_vectors.json", vectors)


# REVIEW: we can simply use the pubnonces directly in the valid & error
# test cases, instead of referencing their indices
def generate_nonce_agg_vectors():
    vectors = dict()

    # Special pubnonce indices for test cases
    INVALID_TAG_IDX = 4  # Pubnonce with wrong tag 0x04
    INVALID_XCOORD_IDX = 5  # Pubnonce with invalid X coordinate
    INVALID_EXCEEDS_FIELD_IDX = 6  # Pubnonce X exceeds field size

    pubnonces = hex_list_to_bytes(
        [
            "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
            "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        ]
    )
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    vectors["valid_test_cases"] = []
    # --- Valid Test Case 1 ---
    pubnonce_indices = [0, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    aggnonce = nonce_agg(curr_pubnonces, pids)
    vectors["valid_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "expected_aggnonce": bytes_to_hex(aggnonce),
        }
    )
    # --- Valid Test Case 2 ---
    pubnonce_indices = [2, 3]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    aggnonce = nonce_agg(curr_pubnonces, pids)
    vectors["valid_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "expected_aggnonce": bytes_to_hex(aggnonce),
            "comment": "Sum of second points encoded in the nonces is point at infinity which is serialized as 33 zero bytes",
        }
    )

    vectors["error_test_cases"] = []
    # --- Error Test Case 1 ---
    pubnonce_indices = [0, INVALID_TAG_IDX]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces, pids), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "error": error,
            "comment": "Public nonce from signer 1 is invalid due wrong tag, 0x04, in the first half",
        }
    )
    # --- Error Test Case 2 ---
    pubnonce_indices = [INVALID_XCOORD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces, pids), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "error": error,
            "comment": "Public nonce from signer 0 is invalid because the second half does not correspond to an X coordinate",
        }
    )
    # --- Error Test Case 3 ---
    pubnonce_indices = [INVALID_EXCEEDS_FIELD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces, pids), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "error": error,
            "comment": "Public nonce from signer 0 is invalid because second half exceeds field size",
        }
    )

    write_test_vectors("nonce_agg_vectors.json", vectors)


# TODO: Remove `pubnonces` param from these vectors. It's not used.
def generate_sign_verify_vectors():
    vectors = dict()

    n, t, thresh_pk, xonly_thresh_pk, ids, secshares, pubshares = get_common_setup()
    secshare_p0 = secshares[0]

    # Special indices for test cases
    INVALID_PUBSHARE_IDX = 3  # Invalid pubshare (appended to list)
    INV_PUBNONCE_IDX = 4  # Inverse pubnonce (for infinity test)
    SECNONCE_ZERO_IDX = 1  # All-zero secnonce (nonce reuse)
    AGGNONCE_INF_IDX = 3  # Aggnonce with both halves as infinity
    AGGNONCE_INVALID_TAG_IDX = 4  # Invalid tag 0x04
    AGGNONCE_INVALID_XCOORD_IDX = 5  # Invalid X coordinate
    AGGNONCE_INVALID_EXCEEDS_FIELD_IDX = 6  # X exceeds field size

    vectors["n"] = n
    vectors["t"] = t
    vectors["threshold_pubkey"] = bytes_to_hex(thresh_pk)
    vectors["secshare_p0"] = bytes_to_hex(secshare_p0)
    vectors["identifiers"] = ids
    pubshares.append(INVALID_PUBSHARE)
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    secnonces, pubnonces = generate_all_nonces(
        COMMON_RAND, secshares, pubshares, xonly_thresh_pk
    )
    secnonces_p0 = [
        secnonces[0],
        bytes.fromhex(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),  # all zero
    ]
    vectors["secnonces_p0"] = bytes_list_to_hex(secnonces_p0)
    # compute -(pubnonce[0] + pubnonce[1])
    tmp = nonce_agg(pubnonces[:2], ids[:2])
    R1 = GE.from_bytes_compressed_with_infinity(tmp[0:33])
    R2 = GE.from_bytes_compressed_with_infinity(tmp[33:66])
    neg_R1 = -R1
    neg_R2 = -R2
    inv_pubnonce = (
        neg_R1.to_bytes_compressed_with_infinity()
        + neg_R2.to_bytes_compressed_with_infinity()
    )
    invalid_pubnonce = bytes.fromhex(
        "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    )
    pubnonces += [invalid_pubnonce, inv_pubnonce]
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    # aggnonces indices represent the following
    # 0 - 2 -> valid aggnonces for the three indices group below
    # 3 -> valid aggnonce with both halves as inf points
    # 4 -> wrong parity tag
    # 5 -> invalid x coordinate in second half
    # 6 -> second half exceeds field size
    indices_grp = [[0, 1], [0, 2], [0, 1, 2]]
    aggnonces = [
        nonce_agg([pubnonces[i] for i in indices], [ids[i] for i in indices])
        for indices in indices_grp
    ]
    # aggnonce with inf points
    aggnonces.append(
        nonce_agg(
            [
                pubnonces[0],
                pubnonces[1],
                pubnonces[-1],
            ],  # pubnonces[-1] is inv_pubnonce
            [ids[0], ids[1], ids[2]],
        )
    )
    # invalid aggnonces
    aggnonces += [
        bytes.fromhex(
            "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
        ),  # wrong parity tag 04
        bytes.fromhex(
            "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009"
        ),  # invalid x coordinate in second half
        bytes.fromhex(
            "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
        ),  # second half exceeds field size
    ]
    vectors["aggnonces"] = bytes_list_to_hex(aggnonces)

    vectors["msgs"] = bytes_list_to_hex(COMMON_MSGS)

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    # Every List[int] & int below represents indices
    # REVIEW: add secnonce here (easy readability), than using `secnonce_p0` list as common prefix
    valid_cases = [
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer": 0,
            "comment": "Signing with minimum number of participants",
        },
        {
            "ids": [1, 0],
            "pubshares": [1, 0],
            "pubnonces": [1, 0],
            "aggnonce": 0,
            "msg": 0,
            "signer": 1,
            "comment": "Partial-signature doesn't change if the order of signers set changes (without changing secnonces)",
        },
        {
            "ids": [0, 2],
            "pubshares": [0, 2],
            "pubnonces": [0, 2],
            "aggnonce": 1,
            "msg": 0,
            "signer": 0,
            "comment": "Partial-signature changes if the members of signers set changes",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, 2],
            "aggnonce": 2,
            "msg": 0,
            "signer": 0,
            "comment": "Signing with max number of participants",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, INV_PUBNONCE_IDX],
            "aggnonce": AGGNONCE_INF_IDX,
            "msg": 0,
            "signer": 0,
            "comment": "Both halves of aggregate nonce correspond to point at infinity",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [0, 1],
            "aggnonce": 0,
            "msg": 1,
            "signer": 0,
            "comment": "Empty message",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [0, 1],
            "aggnonce": 0,
            "msg": 2,
            "signer": 0,
            "comment": "Message longer than 32 bytes (38-byte msg)",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_pubnonces = [pubnonces[i] for i in case["pubnonces"]]
        curr_aggnonce = aggnonces[case["aggnonce"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        my_id = curr_ids[case["signer"]]
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        expected_psig = sign(
            bytearray(secnonces_p0[0]), secshare_p0, my_id, session_ctx
        )
        vectors["valid_test_cases"].append(
            {
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "pubnonce_indices": case["pubnonces"],
                "aggnonce_index": case["aggnonce"],
                "msg_index": case["msg"],
                "signer_index": case["signer"],
                "expected": bytes_to_hex(expected_psig),
                "comment": case["comment"],
            }
        )
        # TODO: verify the signatures here

    vectors["sign_error_test_cases"] = []
    # --- Sign Error Test Cases ---
    error_cases = [
        {
            "ids": [2, 1],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": None,
            "signer_id": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The signer's id is not in the participant identifier list",
        },
        {
            "ids": [0, 1, 1],
            "pubshares": [0, 1, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The participant identifier list contains duplicate elements",
        },
        {
            "ids": [0, 1],
            "pubshares": [2, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The signer's pubshare is not in the list of pubshares. This test case is optional: it can be skipped by implementations that do not check that the signer's pubshare is included in the list of pubshares.",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The participant identifiers count exceed the participant public shares count",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, INVALID_PUBSHARE_IDX],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Signer 1 provided an invalid participant public share",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": AGGNONCE_INVALID_TAG_IDX,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid due wrong tag, 0x04, in the first half",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": AGGNONCE_INVALID_XCOORD_IDX,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid because the second half does not correspond to an X coordinate",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": AGGNONCE_INVALID_EXCEEDS_FIELD_IDX,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid because second half exceeds field size",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": SECNONCE_ZERO_IDX,
            "error": "value",
            "comment": "Secnonce is invalid which may indicate nonce reuse",
        },
    ]
    for case in error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_aggnonce = aggnonces[case["aggnonce"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        if case["signer_idx"] is None:
            my_id = case["signer_id"]
        else:
            my_id = curr_ids[case["signer_idx"]]
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        curr_secnonce = bytearray(secnonces_p0[case["secnonce"]])
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: sign(curr_secnonce, secshare_p0, my_id, session_ctx), expected_error
        )
        vectors["sign_error_test_cases"].append(
            {
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "aggnonce_index": case["aggnonce"],
                "msg_index": case["msg"],
                "signer_index": case["signer_idx"],
                **(
                    {"signer_id": case["signer_id"]}
                    if case["signer_idx"] is None
                    else {}
                ),
                "secnonce_index": case["secnonce"],
                "error": error,
                "comment": case["comment"],
            }
        )

    # REVIEW: In the following vectors, pubshare_indices are not required,
    # just aggnonce value would do. But we should include `secshare` and
    # `secnonce` indices tho.
    vectors["verify_fail_test_cases"] = []
    # --- Verify Fail Test Cases ---
    id_indices = [0, 1]
    pubshare_indices = [0, 1]
    pubnonce_indices = [0, 1]
    aggnonce_idx = 0
    msg_idx = 0
    signer_idx = 0

    curr_ids = [ids[i] for i in id_indices]
    curr_pubshares = [pubshares[i] for i in pubshare_indices]
    curr_aggnonce = aggnonces[aggnonce_idx]
    curr_msg = COMMON_MSGS[msg_idx]
    my_id = curr_ids[signer_idx]
    curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
    session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
    curr_secnonce = bytearray(secnonces_p0[0])
    psig = sign(curr_secnonce, secshare_p0, my_id, session_ctx)
    # --- Verify Fail Test Cases 1 ---
    psig_scalar = Scalar.from_bytes_checked(psig)
    neg_psig = (-psig_scalar).to_bytes()
    vectors["verify_fail_test_cases"].append(
        {
            "psig": bytes_to_hex(neg_psig),
            "id_indices": id_indices,
            "pubshare_indices": pubshare_indices,
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx,
            "comment": "Wrong signature (which is equal to the negation of valid signature)",
        }
    )
    # --- Verify Fail Test Cases 2 ---
    vectors["verify_fail_test_cases"].append(
        {
            "psig": bytes_to_hex(psig),
            "id_indices": id_indices,
            "pubshare_indices": pubshare_indices,
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx + 1,
            "comment": "Wrong signer index",
        }
    )
    # --- Verify Fail Test Cases 3 ---
    vectors["verify_fail_test_cases"].append(
        {
            "psig": bytes_to_hex(psig),
            "id_indices": id_indices,
            "pubshare_indices": [2] + pubshare_indices[1:],
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx,
            "comment": "The signer's pubshare is not in the list of pubshares",
        }
    )
    # --- Verify Fail Test Cases 4 ---
    vectors["verify_fail_test_cases"].append(
        {
            "psig": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            "id_indices": id_indices,
            "pubshare_indices": pubshare_indices,
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx,
            "comment": "Signature value is out of range",
        }
    )

    vectors["verify_error_test_cases"] = []
    # --- Verify Error Test Cases ---
    verify_error_cases = [
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [3, 1],
            "msg": 0,
            "signer": 0,
            "error": "invalid_contrib",
            "comment": "Invalid pubnonce",
        },
        {
            "ids": [0, 1],
            "pubshares": [INVALID_PUBSHARE_IDX, 1],
            "pubnonces": [0, 1],
            "msg": 0,
            "signer": 0,
            "error": "invalid_contrib",
            "comment": "Invalid pubshare",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [0, 1, 2],
            "msg": 0,
            "signer": 0,
            "error": "value",
            "comment": "public nonces count is greater than ids and pubshares",
        },
    ]
    for case in verify_error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_pubnonces = [pubnonces[i] for i in case["pubnonces"]]
        msg = case["msg"]
        signer_idx = case["signer"]
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            # reuse the valid `psig` generated at the start of "verify fail test cases"
            lambda: partial_sig_verify(
                psig, curr_pubnonces, curr_signers, [], [], msg, signer_idx
            ),
            expected_error,
        )
        vectors["verify_error_test_cases"].append(
            {
                "psig": bytes_to_hex(psig),
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "pubnonce_indices": case["pubnonces"],
                "msg_index": case["msg"],
                "signer_index": case["signer"],
                "error": error,
                "comment": case["comment"],
            }
        )

    write_test_vectors("sign_verify_vectors.json", vectors)


def generate_tweak_vectors():
    vectors = dict()

    n, t, thresh_pk, xonly_thresh_pk, ids, secshares, pubshares = get_common_setup()
    secshare_p0 = secshares[0]

    # Special indices for test cases
    INVALID_TWEAK_IDX = 4  # Tweak exceeds secp256k1 group order

    vectors["n"] = n
    vectors["t"] = t
    vectors["threshold_pubkey"] = bytes_to_hex(thresh_pk)
    vectors["secshare_p0"] = bytes_to_hex(secshare_p0)
    vectors["identifiers"] = ids
    pubshares_with_invalid = pubshares + [INVALID_PUBSHARE]
    vectors["pubshares"] = bytes_list_to_hex(pubshares_with_invalid)

    secnonces, pubnonces = generate_all_nonces(
        COMMON_RAND, secshares, pubshares, xonly_thresh_pk
    )
    vectors["secnonce_p0"] = bytes_to_hex(secnonces[0])
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    # create valid aggnonces
    indices_grp = [[0, 1], [0, 1, 2]]
    aggnonces = [
        nonce_agg([pubnonces[i] for i in indices], [ids[i] for i in indices])
        for indices in indices_grp
    ]
    # aggnonce with inf points
    aggnonces.append(
        nonce_agg(
            [pubnonces[0], pubnonces[1], pubnonces[-1]],
            [ids[0], ids[1], ids[2]],
        )
    )
    vectors["aggnonces"] = bytes_list_to_hex(aggnonces)

    vectors["tweaks"] = bytes_list_to_hex(COMMON_TWEAKS)
    vectors["msg"] = bytes_to_hex(COMMON_MSGS[0])

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    valid_cases = [
        {"tweaks_indices": [], "is_xonly": [], "comment": "No tweak"},
        {"tweaks_indices": [0], "is_xonly": [True], "comment": "A single x-only tweak"},
        {"tweaks_indices": [0], "is_xonly": [False], "comment": "A single plain tweak"},
        {
            "tweaks_indices": [0, 1],
            "is_xonly": [False, True],
            "comment": "A plain tweak followed by an x-only tweak",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [True, False, True, False],
            "comment": "Four tweaks: x-only, plain, x-only, plain. If an implementation prohibits applying plain tweaks after x-only tweaks, it can skip this test vector or return an error",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "comment": "Four tweaks: plain, plain, x-only, x-only",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "indices": [0, 1, 2],
            "aggnonce_idx": 1,
            "comment": "Tweaking with max number of participants. The expected value (partial sig) must match the previous test vector",
        },
    ]
    for case in valid_cases:
        indices = case.get("indices", [0, 1])
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares_with_invalid[i] for i in indices]
        aggnonce_idx = case.get("aggnonce_idx", 0)
        curr_aggnonce = aggnonces[aggnonce_idx]
        curr_tweaks = [COMMON_TWEAKS[i] for i in case["tweaks_indices"]]
        curr_tweak_modes = case["is_xonly"]
        signer_idx = 0
        my_id = curr_ids[signer_idx]

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(
            curr_aggnonce, curr_signers, curr_tweaks, curr_tweak_modes, COMMON_MSGS[0]
        )
        psig = sign(bytearray(secnonces[0]), secshare_p0, my_id, session_ctx)

        vectors["valid_test_cases"].append(
            {
                "id_indices": indices,
                "pubshare_indices": indices,
                "pubnonce_indices": indices,
                "tweak_indices": case["tweaks_indices"],
                "aggnonce_index": aggnonce_idx,
                "is_xonly": curr_tweak_modes,
                "signer_index": signer_idx,
                "expected": bytes_to_hex(psig),
                "comment": case["comment"],
            }
        )

    vectors["error_test_cases"] = []
    # --- Error Test Cases ---
    error_cases = [
        {
            "tweaks_indices": [INVALID_TWEAK_IDX],
            "is_xonly": [False],
            "comment": "Tweak is invalid because it exceeds group size",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [True, False],
            "comment": "Tweaks count doesn't match the tweak modes count",
        },
    ]
    for case in error_cases:
        indices = [0, 1]
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares_with_invalid[i] for i in indices]
        aggnonce_idx = 0
        curr_aggnonce = aggnonces[aggnonce_idx]
        curr_tweaks = [COMMON_TWEAKS[i] for i in case["tweaks_indices"]]
        curr_tweak_modes = case["is_xonly"]
        signer_idx = 0
        my_id = curr_ids[signer_idx]

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(
            curr_aggnonce, curr_signers, curr_tweaks, curr_tweak_modes, COMMON_MSGS[0]
        )
        error = expect_exception(
            lambda: sign(bytearray(secnonces[0]), secshare_p0, my_id, session_ctx),
            ValueError,
        )
        vectors["error_test_cases"].append(
            {
                "id_indices": indices,
                "pubshare_indices": indices,
                "tweak_indices": case["tweaks_indices"],
                "aggnonce_index": 0,
                "is_xonly": curr_tweak_modes,
                "signer_index": signer_idx,
                "error": error,
                "comment": case["comment"],
            }
        )

    write_test_vectors("tweak_vectors.json", vectors)


def generate_det_sign_vectors():
    vectors = dict()

    n, t, thresh_pk, xonly_thresh_pk, ids, secshares, pubshares = get_common_setup()
    secshare_p0 = secshares[0]

    # Special indices for test cases
    INVALID_PUBSHARE_IDX = 3  # Invalid pubshare (appended to list)
    INVALID_TWEAK_IDX = 1  # Invalid tweak (COMMON_TWEAKS[4])
    RAND_NONE_IDX = 1  # No auxiliary randomness (None)
    RAND_MAX_IDX = 2  # Max auxiliary randomness (0xFF...FF)

    vectors["n"] = n
    vectors["t"] = t
    vectors["threshold_pubkey"] = bytes_to_hex(thresh_pk)
    vectors["secshare_p0"] = bytes_to_hex(secshare_p0)
    vectors["identifiers"] = ids
    pubshares.append(INVALID_PUBSHARE)
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    vectors["msgs"] = bytes_list_to_hex(COMMON_MSGS)
    assert len(COMMON_MSGS[2]) == 38

    rands = [
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        None,
        bytes.fromhex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        ),
    ]

    tweaks = [
        [COMMON_TWEAKS[0]],
        [COMMON_TWEAKS[4]],
    ]

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    valid_cases = [
        {
            "indices": [0, 1],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Signing with minimum number of participants",
        },
        {
            "indices": [1, 0],
            "signer": 1,
            "msg": 0,
            "rand": 0,
            "comment": "Partial-signature shouldn't change if the order of signers set changes. Note: The deterministic sign will generate the same secnonces due to unchanged parameters",
        },
        {
            "indices": [0, 2],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Partial-signature changes if the members of signers set changes",
        },
        {
            "indices": [0, 1],
            "signer": 0,
            "msg": 0,
            "rand": RAND_NONE_IDX,
            "comment": "Signing without auxiliary randomness",
        },
        {
            "indices": [0, 1],
            "signer": 0,
            "msg": 0,
            "rand": RAND_MAX_IDX,
            "comment": "Signing with max auxiliary randomness",
        },
        {
            "indices": [0, 1, 2],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Signing with maximum number of participants",
        },
        {
            "indices": [0, 1],
            "signer": 0,
            "msg": 1,
            "rand": 0,
            "comment": "Empty message",
        },
        {
            "indices": [0, 1],
            "signer": 0,
            "msg": 2,
            "rand": 0,
            "comment": "Message longer than 32 bytes (38-byte msg)",
        },
        {
            "indices": [0, 1],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": 0,
            "is_xonly": [True],
            "comment": "Signing with tweaks",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        curr_rand = rands[case["rand"]]
        signer_index = case["signer"]
        my_id = curr_ids[signer_index]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])

        # generate `aggothernonce`
        other_ids = curr_ids[:signer_index] + curr_ids[signer_index + 1 :]
        other_pubnonces = []
        for i in case["indices"]:
            if i == signer_index:
                continue
            tmp = b"" if curr_rand is None else curr_rand
            _, pub = nonce_gen_internal(
                tmp, secshares[i], pubshares[i], xonly_thresh_pk, curr_msg, None
            )
            other_pubnonces.append(pub)
        curr_aggothernonce = nonce_agg(other_pubnonces, other_ids)

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        expected = deterministic_sign(
            secshare_p0,
            my_id,
            curr_aggothernonce,
            curr_signers,
            curr_tweaks,
            curr_tweak_modes,
            curr_msg,
            curr_rand,
        )

        vectors["valid_test_cases"].append(
            {
                "rand": bytes_to_hex(curr_rand) if curr_rand is not None else curr_rand,
                "aggothernonce": bytes_to_hex(curr_aggothernonce),
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
                "tweaks": bytes_list_to_hex(curr_tweaks),
                "is_xonly": curr_tweak_modes,
                "msg_index": case["msg"],
                "signer_index": signer_index,
                "expected": bytes_list_to_hex(list(expected)),
                "comment": case["comment"],
            }
        )

    vectors["error_test_cases"] = []
    # --- Error Test Cases ---
    error_cases = [
        {
            "ids": [2, 1],
            "pubshares": [0, 1],
            "signer_idx": None,
            "signer_id": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "02FCDBEE416E4426FB4004BAB2B416164845DEC27337AD2B96184236D715965AB2039F71F389F6808DC6176F062F80531E13EA5BC2612B690FC284AE66C2CD859CE9",
            "error": "value",
            "comment": "The signer's id is not in the participant identifier list",
        },
        {
            "ids": [0, 1, 1],
            "pubshares": [0, 1, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "The participant identifier list contains duplicate elements",
        },
        {
            "ids": [0, 1],
            "pubshares": [2, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "The signer's pubshare is not in the list of pubshares. This test case is optional: it can be skipped by implementations that do not check that the signer's pubshare is included in the list of pubshares.",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "02FCDBEE416E4426FB4004BAB2B416164845DEC27337AD2B96184236D715965AB2039F71F389F6808DC6176F062F80531E13EA5BC2612B690FC284AE66C2CD859CE9",
            "error": "value",
            "comment": "The participant identifiers count exceed the participant public shares count",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, INVALID_PUBSHARE_IDX],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "error": "invalid_contrib",
            "comment": "Signer 1 provided an invalid participant public share",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
            "error": "invalid_contrib",
            "comment": "aggothernonce is invalid due wrong tag, 0x04, in the first half",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0000000000000000000000000000000000000000000000000000000000000000000287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
            "error": "invalid_contrib",
            "comment": "aggothernonce is invalid because first half corresponds to point at infinity",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": INVALID_TWEAK_IDX,
            "is_xonly": [False],
            "error": "value",
            "comment": "Tweak is invalid because it exceeds group size",
        },
    ]
    for case in error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        curr_rand = rands[case["rand"]]
        signer_index = case["signer_idx"]
        if case["signer_idx"] is None:
            my_id = case["signer_id"]
        else:
            my_id = curr_ids[case["signer_idx"]]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])

        # generate `aggothernonce`
        is_aggothernonce = case.get("aggothernonce", None)
        if is_aggothernonce is None:
            if signer_index is None:
                other_ids = curr_ids[1:]
            else:
                other_ids = curr_ids[:signer_index] + curr_ids[signer_index + 1 :]
            other_pubnonces = []
            for i in case["ids"]:
                if i == signer_index:
                    continue
                tmp = b"" if curr_rand is None else curr_rand
                _, pub = nonce_gen_internal(
                    tmp, secshares[i], pubshares[i], xonly_thresh_pk, curr_msg, None
                )
                other_pubnonces.append(pub)
            curr_aggothernonce = nonce_agg(other_pubnonces, other_ids)
        else:
            curr_aggothernonce = bytes.fromhex(is_aggothernonce)

        expected_exception = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        error = expect_exception(
            lambda: deterministic_sign(
                secshare_p0,
                my_id,
                curr_aggothernonce,
                curr_signers,
                curr_tweaks,
                curr_tweak_modes,
                curr_msg,
                curr_rand,
            ),
            expected_exception,
        )

        vectors["error_test_cases"].append(
            {
                "rand": bytes_to_hex(curr_rand) if curr_rand is not None else curr_rand,
                "aggothernonce": bytes_to_hex(curr_aggothernonce),
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "tweaks": bytes_list_to_hex(curr_tweaks),
                "is_xonly": curr_tweak_modes,
                "msg_index": case["msg"],
                "signer_index": signer_index,
                **(
                    {"signer_id": case["signer_id"]}
                    if case["signer_idx"] is None
                    else {}
                ),
                "error": error,
                "comment": case["comment"],
            }
        )

    write_test_vectors("det_sign_vectors.json", vectors)


def generate_sig_agg_vectors():
    vectors = dict()

    n, t, thresh_pk, xonly_thresh_pk, ids, secshares, pubshares = get_common_setup()

    vectors["n"] = n
    vectors["t"] = t
    vectors["threshold_pubkey"] = bytes_to_hex(thresh_pk)
    vectors["identifiers"] = ids
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    secnonces, pubnonces = generate_all_nonces(
        COMMON_RAND, secshares, pubshares, xonly_thresh_pk
    )
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    vectors["tweaks"] = bytes_list_to_hex(SIG_AGG_TWEAKS)

    msg = bytes.fromhex(
        "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869"
    )
    vectors["msg"] = bytes_to_hex(msg)

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    valid_cases = [
        {
            "indices": [0, 1],
            "comment": "Signing with minimum number of participants",
        },
        {
            "indices": [1, 0],
            "comment": "Order of the singer set shouldn't affect the aggregate signature. The expected value must match the previous test vector.",
        },
        {
            "indices": [0, 1],
            "tweaks": [0, 1, 2],
            "is_xonly": [True, False, False],
            "comment": "Signing with tweaked threshold public key",
        },
        {
            "indices": [0, 1, 2],
            "comment": "Signing with max number of participants and tweaked threshold public key",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces, curr_ids)
        curr_msg = msg
        tweak_indices = case.get("tweaks", [])
        curr_tweaks = [SIG_AGG_TWEAKS[i] for i in tweak_indices]
        curr_tweak_modes = case.get("is_xonly", [])
        psigs = []
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(
            curr_aggnonce,
            curr_signers,
            curr_tweaks,
            curr_tweak_modes,
            curr_msg,
        )
        for i in case["indices"]:
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            # TODO: verify the signatures here
        bip340_sig = partial_sig_agg(psigs, curr_ids, session_ctx)
        vectors["valid_test_cases"].append(
            {
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
                "pubnonce_indices": case["indices"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "tweak_indices": tweak_indices,
                "is_xonly": curr_tweak_modes,
                "psigs": bytes_list_to_hex(psigs),
                "expected": bytes_to_hex(bip340_sig),
                "comment": case["comment"],
            }
        )

    vectors["error_test_cases"] = []
    # --- Error Test Cases ---
    error_cases = [
        {
            "indices": [0, 1],
            "error": "invalid_contrib",
            "comment": "Partial signature is invalid because it exceeds group size",
        },
        {
            "indices": [0, 1],
            "error": "value",
            "comment": "Partial signature count doesn't match the signer set count",
        },
    ]
    for j, case in enumerate(error_cases):
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces, curr_ids)
        curr_msg = msg
        psigs = []
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        for i in case["indices"]:
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            # TODO: verify the signatures here

        if j == 0:
            invalid_psig = bytes.fromhex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            )
            psigs[1] = invalid_psig
        if j == 1:
            psigs.pop()

        expected_exception = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: partial_sig_agg(psigs, curr_ids, session_ctx), expected_exception
        )
        vectors["error_test_cases"].append(
            {
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
                "pubnonce_indices": case["indices"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "tweak_indices": [],
                "is_xonly": [],
                "psigs": bytes_list_to_hex(psigs),
                "error": error,
                "comment": case["comment"],
            }
        )

    write_test_vectors("sig_agg_vectors.json", vectors)


def create_vectors_directory():
    if os.path.exists("vectors"):
        shutil.rmtree("vectors")
    os.makedirs("vectors")


def run_gen_vectors(test_name, test_func):
    max_len = 30
    test_name = test_name.ljust(max_len, ".")
    print(f"Running {test_name}...", end="", flush=True)
    try:
        test_func()
        print("Done!")
    except Exception as e:
        print(f"Failed :'(\nError: {e}")


def main():
    create_vectors_directory()

    run_gen_vectors("generate_nonce_gen_vectors", generate_nonce_gen_vectors)
    run_gen_vectors("generate_nonce_agg_vectors", generate_nonce_agg_vectors)
    run_gen_vectors("generate_sign_verify_vectors", generate_sign_verify_vectors)
    run_gen_vectors("generate_tweak_vectors", generate_tweak_vectors)
    run_gen_vectors("generate_sig_agg_vectors", generate_sig_agg_vectors)
    run_gen_vectors("generate_det_sign_vectors", generate_det_sign_vectors)
    print("Test vectors generated successfully")


if __name__ == "__main__":
    sys.exit(main())
