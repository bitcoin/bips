#!/usr/bin/env python3

import glob
import json
import os
import re
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
from frost_ref.signing import derive_interpolating_value, nonce_gen_internal
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.keys import pubkey_gen_plain
from trusted_dealer import trusted_dealer_keygen


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: Sequence[bytes]) -> List[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: List[str]) -> List[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


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


_SCALAR_TOKEN = r"-?\d+|true|false|null"
_SCALAR_ARRAY_RE = re.compile(
    rf"\[\s*(?:(?:{_SCALAR_TOKEN})(?:\s*,\s*(?:{_SCALAR_TOKEN}))*)?\s*\]"
)


def _inline_scalar_array(match):
    tokens = re.findall(_SCALAR_TOKEN, match.group(0))
    return "[" + ", ".join(tokens) + "]"


def write_test_vectors(filename, vectors):
    output_file = os.path.join("vectors", filename)
    text = _SCALAR_ARRAY_RE.sub(_inline_scalar_array, json.dumps(vectors, indent=4))
    json.loads(text)  # guard: inlining must keep the JSON parseable
    with open(output_file, "w") as f:
        f.write(text)


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
    thresh_pk_bytes = bytes.fromhex(
        "03B02645D79ABFC494338139410F9D7F0A72BE86C952D6BDE1A66447B8A8D69237"
    )
    thresh_pk_ge = GE.from_bytes_compressed(thresh_pk_bytes)
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
    return (t, n, thresh_pk_ge, secshares, pubshares)


def reconstruct_thresh_sk(ids, secshares):
    assert len(ids) == len(secshares)
    result = Scalar(0)
    for i, s in zip(ids, secshares):
        result = result + derive_interpolating_value(
            ids, i
        ) * Scalar.from_bytes_checked(s)
    return result


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
    vectors = {}
    vectors["valid_test_cases"] = []

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
    vectors["valid_test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "All optional defense-in-depth arguments present",
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
    vectors["valid_test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[1]),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "Empty message",
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
    vectors["valid_test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[2]),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "Non-standard message length (38 bytes)",
        }
    )
    # --- Valid Test Case 4 ---
    secnonce, pubnonce = nonce_gen_internal(COMMON_RAND, None, None, None, None, None)
    vectors["valid_test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": None,
            "pubshare": None,
            "thresh_pk": None,
            "msg": None,
            "extra_in": None,
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "All optional defense-in-depth arguments omitted",
        }
    )
    # --- Valid Test Case 5 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], xonly_thresh_pk, None, extra_in
    )
    vectors["valid_test_cases"].append(
        {
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": None,
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "Message omitted, other optional arguments present",
        }
    )

    write_test_vectors("nonce_gen_vectors.json", vectors)


def generate_nonce_agg_vectors():
    vectors = {}

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
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "expected_aggnonce": bytes_to_hex(aggnonce),
            "comment": "Two well-formed public nonces",
        }
    )
    # --- Valid Test Case 2 ---
    pubnonce_indices = [2, 3]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "expected_aggnonce": bytes_to_hex(aggnonce),
            "comment": "Second halves sum to the point at infinity, which is serialized as the all-zero encoding",
        }
    )

    vectors["error_test_cases"] = []
    # --- Error Test Case 1 ---
    pubnonce_indices = [0, INVALID_TAG_IDX]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "error": error,
            "comment": "Public nonce is invalid: first half has an unknown tag 0x04",
        }
    )
    # --- Error Test Case 2 ---
    pubnonce_indices = [INVALID_XCOORD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "error": error,
            "comment": "Public nonce is invalid: second half is not a point on the curve",
        }
    )
    # --- Error Test Case 3 ---
    pubnonce_indices = [INVALID_EXCEEDS_FIELD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "error": error,
            "comment": "Public nonce is invalid: second half's x-coordinate exceeds the field size",
        }
    )

    write_test_vectors("nonce_agg_vectors.json", vectors)


def generate_sign_verify_vectors():
    vectors = {}

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
    OUT_OF_RANGE_ID_IDX = 3  # identifier value n, out of range [0, n-1]
    assert OUT_OF_RANGE_ID_IDX == n

    # Extend identifiers with an out-of-range value (n) for the L91 test case.
    # Existing cases reference indices 0..2 only and are unaffected.
    ids = ids + [n]

    vectors["n"] = n
    vectors["t"] = t
    vectors["thresh_pk"] = bytes_to_hex(thresh_pk)
    secshares_p0 = [secshare_p0, b"\x00" * 32]
    vectors["secshares"] = bytes_list_to_hex(secshares_p0)
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
    # valid first half (reused from index 0), zero second half.
    k_2_zero_secnonce = secnonces_p0[0][0:32] + b"\x00" * 32
    assert Scalar.from_bytes_nonzero_checked(k_2_zero_secnonce[0:32])
    secnonces_p0.append(k_2_zero_secnonce)
    vectors["secnonces_p0"] = bytes_list_to_hex(secnonces_p0)
    # compute -(pubnonce[0] + pubnonce[1])
    tmp = nonce_agg(pubnonces[:2])
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
    aggnonces = [nonce_agg([pubnonces[i] for i in indices]) for indices in indices_grp]
    # aggnonce with inf points
    aggnonces.append(
        nonce_agg(
            [
                pubnonces[0],
                pubnonces[1],
                pubnonces[-1],
            ],  # pubnonces[-1] is inv_pubnonce
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
    # Every List[int] & int below represents indices, except `my_id` (a value)
    valid_cases = [
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "comment": "Minimum threshold subset of signers (t=2 of n=3)",
        },
        {
            "ids": [1, 0],
            "pubshares": [1, 0],
            "pubnonces": [1, 0],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "comment": "Signer order does not affect the partial signature: the signer set is sorted internally, so this matches the first valid case",
        },
        {
            "ids": [0, 2],
            "pubshares": [0, 2],
            "pubnonces": [0, 2],
            "aggnonce": 1,
            "msg": 0,
            "my_id": 0,
            "comment": "A different threshold subset gives a different partial signature, since the Lagrange coefficients depend on the signer set",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, 2],
            "aggnonce": 2,
            "msg": 0,
            "my_id": 0,
            "comment": "All n=3 signers participate (signer set equals the full group)",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, INV_PUBNONCE_IDX],
            "aggnonce": AGGNONCE_INF_IDX,
            "msg": 0,
            "my_id": 0,
            "comment": "Aggregate nonce is the point at infinity, so the final nonce point falls back to the generator G",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [0, 1],
            "aggnonce": 0,
            "msg": 1,
            "my_id": 0,
            "comment": "Empty message",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "pubnonces": [0, 1],
            "aggnonce": 0,
            "msg": 2,
            "my_id": 0,
            "comment": "Non-standard message length (38 bytes)",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_pubnonces = [pubnonces[i] for i in case["pubnonces"]]
        curr_aggnonce = aggnonces[case["aggnonce"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        my_id = case["my_id"]
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        expected_psig = sign(
            bytearray(secnonces_p0[0]), secshare_p0, my_id, session_ctx
        )
        signer_index = curr_ids.index(my_id)
        assert partial_sig_verify(
            expected_psig, curr_pubnonces, curr_signers, [], [], curr_msg, signer_index
        )
        vectors["valid_test_cases"].append(
            {
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "pubnonce_indices": case["pubnonces"],
                "aggnonce_index": case["aggnonce"],
                "msg_index": case["msg"],
                "my_id": my_id,
                "secshare_index": 0,
                "expected": bytes_to_hex(expected_psig),
                "comment": case["comment"],
            }
        )

    vectors["sign_error_test_cases"] = []
    # --- Sign Error Test Cases ---
    error_cases = [
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 2,
            "secnonce": 0,
            "error": "value",
            "comment": "Signer's own id is not in the signer set",
        },
        {
            "ids": [0, 1, 1],
            "pubshares": [0, 1, 1],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "Signer set contains a duplicate id",
        },
        {
            "ids": [1, 2],
            "pubshares": [1, 2],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 1,
            "secnonce": 0,
            "error": "value",
            "comment": "Signer's own public share is not in the public share list",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, INVALID_PUBSHARE_IDX],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "A public share is not a valid point",
        },
        {
            "ids": [OUT_OF_RANGE_ID_IDX, 1],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 1,
            "secnonce": 0,
            "error": "value",
            "comment": "A signer id is outside the valid range [0, n-1]",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 2],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "Signer set's public shares do not match the threshold public key",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": AGGNONCE_INVALID_TAG_IDX,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid: first half has an unknown tag 0x04",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": AGGNONCE_INVALID_XCOORD_IDX,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid: second half is not a point on the curve",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": AGGNONCE_INVALID_EXCEEDS_FIELD_IDX,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid: second half's x-coordinate exceeds the field size",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "secnonce": SECNONCE_ZERO_IDX,
            "error": "value",
            "comment": "Secret nonce's first half is out of range (all-zero nonce, which may indicate nonce reuse)",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "secnonce": 2,
            "error": "value",
            "comment": "Secret nonce's second half is out of range (zero)",
        },
        {
            "ids": [0],
            "pubshares": [0],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "Fewer signers than the threshold t",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "my_id": 0,
            "secnonce": 0,
            "secshare_index": 1,
            "error": "value",
            "comment": "Secret share is out of range (zero)",
        },
    ]
    for case in error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_aggnonce = aggnonces[case["aggnonce"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        my_id = case["my_id"]
        secshare_index = case.get("secshare_index", 0)
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        curr_secnonce = bytearray(secnonces_p0[case["secnonce"]])
        curr_secshare = secshares_p0[secshare_index]
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: sign(curr_secnonce, curr_secshare, my_id, session_ctx),
            expected_error,
        )
        vectors["sign_error_test_cases"].append(
            {
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "aggnonce_index": case["aggnonce"],
                "msg_index": case["msg"],
                "my_id": my_id,
                "secnonce_index": case["secnonce"],
                "secshare_index": secshare_index,
                "error": error,
                "comment": case["comment"],
            }
        )

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
            "comment": "Negated partial signature fails the verification equation",
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
            "comment": "A valid partial signature checked against the wrong signer fails the verification equation",
        }
    )
    # --- Verify Fail Test Cases 3 ---
    vectors["verify_fail_test_cases"].append(
        {
            "psig": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            "id_indices": id_indices,
            "pubshare_indices": pubshare_indices,
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx,
            "comment": "Partial signature equals the group order, which is out of range",
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
            "signer_index": 0,
            "error": "invalid_contrib",
            "comment": "Public nonce is invalid: first half is not a point on the curve",
        },
        {
            "ids": [0, 1],
            "pubshares": [INVALID_PUBSHARE_IDX, 1],
            "pubnonces": [0, 1],
            "msg": 0,
            "signer_index": 0,
            "error": "value",
            "comment": "A public share is not a valid point",
        },
    ]
    for case in verify_error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_pubnonces = [pubnonces[i] for i in case["pubnonces"]]
        msg = case["msg"]
        signer_index = case["signer_index"]
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            # reuse the valid `psig` generated at the start of "verify fail test cases"
            lambda: partial_sig_verify(
                psig, curr_pubnonces, curr_signers, [], [], msg, signer_index
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
                "signer_index": case["signer_index"],
                "error": error,
                "comment": case["comment"],
            }
        )

    write_test_vectors("sign_verify_vectors.json", vectors)


def generate_tweak_vectors():
    vectors = {}

    n, t, thresh_pk, xonly_thresh_pk, ids, secshares, pubshares = get_common_setup()
    secshare_p0 = secshares[0]

    # Special indices for test cases
    INVALID_TWEAK_IDX = 4  # Tweak exceeds secp256k1 group order

    vectors["n"] = n
    vectors["t"] = t
    vectors["thresh_pk"] = bytes_to_hex(thresh_pk)
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
    aggnonces = [nonce_agg([pubnonces[i] for i in indices]) for indices in indices_grp]
    vectors["aggnonces"] = bytes_list_to_hex(aggnonces)

    # Compute a plain tweak that drives Q + twk*G to the point at infinity: twk = -thresh_sk.
    infinity_tweak_scalar = -reconstruct_thresh_sk([0, 1], secshares[:2])
    assert (GE.from_bytes_compressed(thresh_pk) + infinity_tweak_scalar * G).infinity

    INFINITY_TWEAK_IDX = len(COMMON_TWEAKS)  # index 5
    all_tweaks = list(COMMON_TWEAKS) + [infinity_tweak_scalar.to_bytes()]

    vectors["tweaks"] = bytes_list_to_hex(all_tweaks)
    vectors["msg"] = bytes_to_hex(COMMON_MSGS[0])

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    valid_cases = [
        {
            "tweaks_indices": [],
            "is_xonly": [],
            "comment": "No tweaks applied",
        },
        {
            "tweaks_indices": [0],
            "is_xonly": [True],
            "comment": "Single x-only tweak (used for BIP341 Taproot)",
        },
        {
            "tweaks_indices": [0],
            "is_xonly": [False],
            "comment": "Single plain tweak (used for BIP32 derivation)",
        },
        {
            "tweaks_indices": [0, 1],
            "is_xonly": [False, True],
            "comment": "A plain tweak followed by an x-only tweak",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [True, False, True, False],
            "comment": "Four tweaks alternating x-only and plain",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "comment": "Four tweaks: two plain followed by two x-only",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "indices": [0, 1, 2],
            "aggnonce_idx": 1,
            "comment": "Same tweaks as the previous case but with all 3 signers; the partial signature differs because the Lagrange coefficient depends on the signer set",
        },
    ]
    for case in valid_cases:
        indices = case.get("indices", [0, 1])
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares_with_invalid[i] for i in indices]
        aggnonce_idx = case.get("aggnonce_idx", 0)
        curr_aggnonce = aggnonces[aggnonce_idx]
        curr_tweaks = [all_tweaks[i] for i in case["tweaks_indices"]]
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
                "my_id": my_id,
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
            "comment": "Tweak exceeds the group order",
        },
        {
            "tweaks_indices": [INFINITY_TWEAK_IDX],
            "is_xonly": [False],
            "comment": "Tweak drives the tweaked public key to the point at infinity",
        },
    ]
    for case in error_cases:
        indices = [0, 1]
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares_with_invalid[i] for i in indices]
        aggnonce_idx = 0
        curr_aggnonce = aggnonces[aggnonce_idx]
        curr_tweaks = [all_tweaks[i] for i in case["tweaks_indices"]]
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
                "my_id": my_id,
                "error": error,
                "comment": case["comment"],
            }
        )

    write_test_vectors("tweak_vectors.json", vectors)


def generate_det_sign_vectors():
    vectors = {}

    n, t, thresh_pk, xonly_thresh_pk, ids, secshares, pubshares = get_common_setup()
    secshare_p0 = secshares[0]

    # Special indices for test cases
    INVALID_PUBSHARE_IDX = 3  # Invalid pubshare (appended to list)
    INVALID_TWEAK_IDX = 1  # Invalid tweak (COMMON_TWEAKS[4])
    RAND_NONE_IDX = 1  # No auxiliary randomness (None)
    RAND_MAX_IDX = 2  # Max auxiliary randomness (0xFF...FF)

    vectors["n"] = n
    vectors["t"] = t
    vectors["thresh_pk"] = bytes_to_hex(thresh_pk)
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
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Minimum threshold subset of signers (t=2 of n=3)",
        },
        {
            "indices": [1, 0],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Signer order does not affect the output: the signer set is sorted internally, so this matches the first valid case",
        },
        {
            "indices": [0, 2],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "comment": "A different threshold subset gives a different deterministic nonce, since the signer set is bound into the nonce derivation",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": RAND_NONE_IDX,
            "comment": "No auxiliary randomness (rand omitted)",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": RAND_MAX_IDX,
            "comment": "Maximum auxiliary randomness",
        },
        {
            "indices": [0, 1, 2],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "comment": "All n=3 signers participate (signer set equals the full group)",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 1,
            "rand": 0,
            "comment": "Empty message",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 2,
            "rand": 0,
            "comment": "Non-standard message length (38 bytes)",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": 0,
            "is_xonly": [True],
            "comment": "Single x-only tweak applied",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        curr_rand = rands[case["rand"]]
        my_id = case["my_id"]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])

        # generate `aggothernonce` (every signer's nonce except this signer's own)
        other_pubnonces = []
        for i in case["indices"]:
            if ids[i] == my_id:
                continue
            tmp = b"" if curr_rand is None else curr_rand
            _, pub = nonce_gen_internal(
                tmp, secshares[i], pubshares[i], xonly_thresh_pk, curr_msg, None
            )
            other_pubnonces.append(pub)
        curr_aggothernonce = nonce_agg(other_pubnonces)

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
                "my_id": my_id,
                "expected": bytes_list_to_hex(list(expected)),
                "comment": case["comment"],
            }
        )

    vectors["error_test_cases"] = []
    # --- Error Test Cases ---
    error_cases = [
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 2,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "Signer's own id is not in the signer set",
        },
        {
            "ids": [0, 1, 1],
            "pubshares": [0, 1, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "Signer set contains a duplicate id",
        },
        {
            "ids": [1, 2],
            "pubshares": [1, 2],
            "my_id": 1,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "Signer's own public share is not in the public share list",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, INVALID_PUBSHARE_IDX],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "A public share is not a valid point",
        },
        {
            "ids": [2, 1],
            "pubshares": [0, 1],
            "my_id": 2,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "Signer set's public shares do not match the threshold public key",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: first half has an unknown tag 0x04",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0000000000000000000000000000000000000000000000000000000000000000000287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: first half is all zeros",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0353BC2314D46C813AF81317AF1BDF99816B6444E416BB8D3DC04ACB2F5388D1AC020000000000000000000000000000000000000000000000000000000000000009",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: second half is not a point on the curve",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0353BC2314D46C813AF81317AF1BDF99816B6444E416BB8D3DC04ACB2F5388D1AC02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: second half's x-coordinate exceeds the field size",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": INVALID_TWEAK_IDX,
            "is_xonly": [False],
            "error": "value",
            "comment": "Tweak exceeds the group order",
        },
    ]
    for case in error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        curr_rand = rands[case["rand"]]
        my_id = case["my_id"]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])

        # generate `aggothernonce` (every signer's nonce except this signer's own)
        is_aggothernonce = case.get("aggothernonce", None)
        if is_aggothernonce is None:
            other_pubnonces = []
            for i in case["ids"]:
                if ids[i] == my_id:
                    continue
                tmp = b"" if curr_rand is None else curr_rand
                _, pub = nonce_gen_internal(
                    tmp, secshares[i], pubshares[i], xonly_thresh_pk, curr_msg, None
                )
                other_pubnonces.append(pub)
            curr_aggothernonce = nonce_agg(other_pubnonces)
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
                "my_id": my_id,
                "error": error,
                "comment": case["comment"],
            }
        )

    write_test_vectors("det_sign_vectors.json", vectors)


def generate_sig_agg_vectors():
    vectors = {}

    n, t, thresh_pk, xonly_thresh_pk, ids, secshares, pubshares = get_common_setup()

    vectors["n"] = n
    vectors["t"] = t
    vectors["thresh_pk"] = bytes_to_hex(thresh_pk)
    vectors["identifiers"] = ids
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    secnonces, pubnonces = generate_all_nonces(
        COMMON_RAND, secshares, pubshares, xonly_thresh_pk
    )

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
            "comment": "Minimum threshold subset of signers (t=2 of n=3), no tweaks",
        },
        {
            "indices": [1, 0],
            "comment": "Signer order does not affect the aggregate signature: partial signatures are summed, so this matches the first valid case",
        },
        {
            "indices": [0, 1],
            "tweaks": [0, 1, 2],
            "is_xonly": [True, False, False],
            "comment": "Aggregation with three tweaks applied (one x-only, two plain)",
        },
        {
            "indices": [0, 1, 2],
            "comment": "All n=3 signers participate, no tweaks",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces)
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
        for signer_index, i in enumerate(case["indices"]):
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            assert partial_sig_verify(
                sig,
                curr_pubnonces,
                curr_signers,
                curr_tweaks,
                curr_tweak_modes,
                curr_msg,
                signer_index,
            )
        bip340_sig = partial_sig_agg(psigs, session_ctx)
        vectors["valid_test_cases"].append(
            {
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
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
            "comment": "Partial signature equals the group order, which is out of range",
        },
    ]
    for j, case in enumerate(error_cases):
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces)
        curr_msg = msg
        psigs = []
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        for signer_index, i in enumerate(case["indices"]):
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            assert partial_sig_verify(
                sig,
                curr_pubnonces,
                curr_signers,
                [],
                [],
                curr_msg,
                signer_index,
            )

        if j == 0:
            invalid_psig = bytes.fromhex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            )
            psigs[1] = invalid_psig

        expected_exception = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: partial_sig_agg(psigs, session_ctx), expected_exception
        )
        vectors["error_test_cases"].append(
            {
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
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
    os.makedirs("vectors", exist_ok=True)
    for f in glob.glob("vectors/*.json"):
        os.remove(f)


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
    run_gen_vectors("generate_det_sign_vectors", generate_det_sign_vectors)
    run_gen_vectors("generate_sig_agg_vectors", generate_sig_agg_vectors)
    print("Test vectors generated successfully")


if __name__ == "__main__":
    sys.exit(main())
