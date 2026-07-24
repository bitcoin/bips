from frost_ref import InvalidContributionError, nonce_agg
from frost_ref.signing import nonce_gen_internal

from generators.common import (
    COMMON_MSGS,
    COMMON_RAND,
    SECKEY_2OF3,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    frost_keygen,
    hex_list_to_bytes,
    write_test_vectors,
)


def generate_nonce_gen_vectors():
    vectors = {}
    vectors["valid_tests"] = []
    tc_id = 1

    _, _, thresh_pk, _, secshares, pubshares = frost_keygen(SECKEY_2OF3)
    xonly_thresh_pk = thresh_pk[1:]
    extra_in = bytes.fromhex(
        "0808080808080808080808080808080808080808080808080808080808080808"
    )

    # --- Valid Test Case 1 ---
    msg = bytes.fromhex(
        "0101010101010101010101010101010101010101010101010101010101010101"
    )
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], xonly_thresh_pk, msg, extra_in
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "All optional defense-in-depth arguments present",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 2 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        xonly_thresh_pk,
        COMMON_MSGS[1],
        extra_in,
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Empty message",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[1]),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 3 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        xonly_thresh_pk,
        COMMON_MSGS[2],
        extra_in,
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Non-standard message length (38 bytes)",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[2]),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 4 ---
    secnonce, pubnonce = nonce_gen_internal(COMMON_RAND, None, None, None, None, None)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "All optional defense-in-depth arguments omitted",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": None,
            "pubshare": None,
            "thresh_pk": None,
            "msg": None,
            "extra_in": None,
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 5 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], xonly_thresh_pk, None, extra_in
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Message omitted, other optional arguments present",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": None,
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1

    write_test_vectors("nonce_gen_vectors.json", vectors)


def generate_nonce_agg_vectors():
    vectors = {}

    # Special pubnonce indices for test cases
    INVALID_TAG_IDX = 4
    INVALID_XCOORD_IDX = 5
    INVALID_EXCEEDS_FIELD_IDX = 6

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

    tc_id = 1
    vectors["valid_tests"] = []
    # --- Valid Test Case 1 ---
    pubnonce_indices = [0, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Two well-formed public nonces",
            "pubnonce_indices": pubnonce_indices,
            "expected": bytes_to_hex(aggnonce),
        }
    )
    tc_id += 1
    # --- Valid Test Case 2 ---
    pubnonce_indices = [2, 3]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Second halves sum to the point at infinity, which is serialized as the all-zero encoding",
            "pubnonce_indices": pubnonce_indices,
            "expected": bytes_to_hex(aggnonce),
        }
    )
    tc_id += 1

    vectors["error_tests"] = []
    # --- Error Test Case 1 ---
    pubnonce_indices = [0, INVALID_TAG_IDX]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: first half has an unknown tag 0x04",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1
    # --- Error Test Case 2 ---
    pubnonce_indices = [INVALID_XCOORD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: second half is not a point on the curve",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1
    # --- Error Test Case 3 ---
    pubnonce_indices = [INVALID_EXCEEDS_FIELD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: second half's x-coordinate exceeds the field size",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1

    write_test_vectors("nonce_agg_vectors.json", vectors)
