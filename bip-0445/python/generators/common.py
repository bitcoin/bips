import json
import os
import re
import secrets
from collections import namedtuple
from typing import Dict, List, Sequence, Union

from frost_ref.signing import (
    PlainPk,
    XonlyPk,
    derive_interpolating_value,
    nonce_agg,
    nonce_gen_internal,
)
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
    ]
)

# secp256k1 group order n: the single out-of-range boundary shared by the tweak and
# partial-signature generators
GROUP_ORDER = GE.ORDER.to_bytes(32, "big")
OUT_OF_RANGE_TWEAK = GROUP_ORDER
INVALID_PUBSHARE = bytes.fromhex(
    "020000000000000000000000000000000000000000000000000000000000000007"
)

# Public nonce whose first half is an off-curve compressed point (x=9 not on the
# curve) and whose second half is a valid point
INVALID_PUBNONCE = bytes.fromhex(
    "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
)

AGGNONCE_WRONG_TAG = bytes.fromhex(
    "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
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


def reconstruct_thresh_sk(ids, secshares):
    assert len(ids) == len(secshares)
    result = Scalar(0)
    for i, s in zip(ids, secshares):
        result = result + derive_interpolating_value(
            ids, i
        ) * Scalar.from_bytes_checked(s)
    return result


# Chosen so the threshold pubkey is odd-y (prefix 03)
SECKEY_1OF3 = bytes.fromhex(
    "06D47E05E97481428654563E5AE69C20C49642773B7334220E63110259A30C32"
)
# Chosen so the threshold pubkey is even-y (prefix 02)
SECKEY_2OF3 = bytes.fromhex(
    "4C08C37F5B9A88FAE396A06E286BA41B654457BF5E35B4A693096ED9AB1491F5"
)
# Chosen so the threshold pubkey is even-y (prefix 02)
SECKEY_3OF3 = bytes.fromhex(
    "70E90852E9541FE47552B738A14C2B9B5B38C0979D640BA8C7A5A5EEE1BDA405"
)
# Chosen so the threshold pubkey is odd-y (prefix 03)
SECKEY_3OF5 = bytes.fromhex(
    "C97F278DAC5FC3214F4C2DD7551C84D4854DCA143887F54692735C61A16E902A"
)


def frost_keygen(seckey=None, n=3, t=2):
    # NOTE: don't default `seckey` to secrets.token_bytes(32) in the signature, as that is evaluated once at import time and every no-arg call would reuse it.
    if seckey is None:
        seckey = secrets.token_bytes(32)
    assert len(seckey) == 32
    assert 1 <= t <= n
    thresh_pk, secshares, pubshares = trusted_dealer_keygen(seckey, n, t)
    assert thresh_pk == pubkey_gen_plain(seckey)
    return (n, t, thresh_pk, list(range(n)), secshares, pubshares)


# --- Multi-(t, n) config machinery (shared by all four signing generators) ---

Config = namedtuple("Config", ["tg_id", "t", "n", "seckey"])

CONFIGS = [
    Config("2of3", 2, 3, SECKEY_2OF3),
    Config("1of3", 1, 3, SECKEY_1OF3),
    Config("3of3", 3, 3, SECKEY_3OF3),
    Config("3of5", 3, 5, SECKEY_3OF5),
]


class SharedGroupInputs:
    """The maximal per-test-group bundle: real key/nonce material plus the union pools
    (real entries followed by appended fault slots) and the named offsets that index
    those slots. Built once per test group; each generator slices what it needs."""

    def __init__(self, cfg):
        n, t, thresh_pk, _ids, secshares, pubshares = frost_keygen(
            cfg.seckey, cfg.n, cfg.t
        )
        self.n = n
        self.t = t
        self.thresh_pk = thresh_pk
        self.xonly_thresh_pk = XonlyPk(thresh_pk[1:])
        self.secshares = secshares
        self.pubshares = pubshares
        self.secnonces, self.pubnonces = generate_all_nonces(
            COMMON_RAND, secshares, pubshares, self.xonly_thresh_pk
        )

        # pubshares pool: off-curve point at slot n.
        self.pool_pubshares = pubshares + [PlainPk(INVALID_PUBSHARE)]
        # secshares pool: zero scalar at slot n.
        self.pool_secshares = secshares + [b"\x00" * 32]

        # pubnonces pool: off-curve nonce at slot n, then the inverse nonce at slot
        # n+1 (negation of the aggregate of the first n-1 real pubnonces). It only
        # sums to infinity when paired with indices [0..n-2] plus INVERSE_PUBNONCE_IDX.
        # Any other size n-1 subset yields a non-infinity aggregate.
        tmp = nonce_agg(self.pubnonces[: n - 1])
        R1 = GE.from_bytes_compressed_with_infinity(tmp[0:33])
        R2 = GE.from_bytes_compressed_with_infinity(tmp[33:66])
        inverse_pubnonce = (-R1).to_bytes_compressed_with_infinity() + (
            -R2
        ).to_bytes_compressed_with_infinity()
        self.pool_pubnonces = self.pubnonces + [INVALID_PUBNONCE, inverse_pubnonce]

        # secnonces pool: all-zero at slot n, nonzero-first/zero-second at slot n+1.
        zero_second_secnonce = self.secnonces[0][0:32] + b"\x00" * 32
        assert Scalar.from_bytes_nonzero_checked(zero_second_secnonce[0:32])
        self.pool_secnonces = self.secnonces + [b"\x00" * 64, zero_second_secnonce]

        # tweaks pool: 4 common tweaks, out-of-range tweak, then the per-config
        # infinity tweak (negation of the reconstructed threshold secret over the
        # minimum set; degenerates to -secshares[0] at t=1).
        infinity_tweak_scalar = -reconstruct_thresh_sk(list(range(t)), secshares[:t])
        assert (
            GE.from_bytes_compressed(self.thresh_pk) + infinity_tweak_scalar * G
        ).infinity
        infinity_tweak = infinity_tweak_scalar.to_bytes()
        self.tweaks_pool = list(COMMON_TWEAKS) + [OUT_OF_RANGE_TWEAK, infinity_tweak]

        # named offsets into the pools, all derived from n
        self.INVALID_PUBSHARE_IDX = n
        self.SECSHARE_ZERO_IDX = n
        self.INVALID_PUBNONCE_IDX = n
        self.INVERSE_PUBNONCE_IDX = n + 1
        self.SECNONCE_ZERO_IDX = n
        self.SECNONCE_ZERO_SECOND_IDX = n + 1
        self.OUT_OF_RANGE_ID = n
        # tweaks-pool offsets, n-independent
        self.OUT_OF_RANGE_TWEAK_IDX = len(COMMON_TWEAKS)
        self.INFINITY_TWEAK_IDX = len(COMMON_TWEAKS) + 1


def has_excl0_subset(t, n):
    # The "excl0" subset (a size-t signer set that excludes participant 0) is
    # usable only when t >= 2 and t < n. At t=n no size-t set can exclude id 0,
    # and at t=1 all shares are identical, so excluding id 0 changes nothing.
    return t >= 2 and t < n


def get_subset(cfg, strategy="min"):
    match strategy:
        case "min":  # minimum threshold subset, the first t ids
            return list(range(cfg.t))
        case "full":  # all n participants
            return list(range(cfg.n))
        case "alt":  # id 0 + the last t-1 ids; collapses to [0] at t=1 (caller guards)
            return [0] + list(range(cfg.n - cfg.t + 1, cfg.n))
        case "min2":  # size-at-least-2 baseline; [0, 1] at t=1
            return list(range(max(cfg.t, 2)))
        case "excl0":  # t ids from 1, excludes id 0 (only valid when has_excl0_subset)
            assert has_excl0_subset(cfg.t, cfg.n)
            return list(range(1, cfg.t + 1))
        case _:
            raise ValueError(f"Unknown subset strategy: {strategy}")


def swap_last_two(indices):
    result = list(indices)
    assert len(result) >= 2
    result[-1], result[-2] = result[-2], result[-1]
    return result


def set_group_config(group, cfg, inputs):
    group["tg_id"] = cfg.tg_id
    group["t"] = cfg.t
    group["n"] = cfg.n
    group["thresh_pk"] = bytes_to_hex(inputs.thresh_pk)


def assign_tc_ids(groups):
    tc_id = 1
    for group in groups:
        for key, value in group.items():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                for i, case in enumerate(value):
                    group[key][i] = {"tc_id": tc_id, **case}
                    tc_id += 1
