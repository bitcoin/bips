#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Public BIP32 key parsing and exact-index derivation."""

import hmac
import re

from encoding import base58check_decode
from secp256k1lab.secp256k1 import G, GE


VERSIONS = {"mainnet": bytes.fromhex("0488b21e"), "testnet": bytes.fromhex("043587cf")}


def parse_point(data: bytes) -> GE:
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("Expected a compressed public key")
    return GE.from_bytes_compressed(data)


def child_number(text: str) -> int:
    if re.fullmatch(r"[0-9]+[h']?", text) is None:
        raise ValueError("Invalid derivation step")
    value = int(text.rstrip("h'"))
    if value >= 2**31:
        raise ValueError("Derivation step out of range")
    return value + (2**31 if text[-1] in "h'" else 0)


def parse_xpub(key_info: str) -> tuple[bytes, bytes]:
    """Validate an xpub/tpub with optional origin; return public key and chain code."""
    if key_info.startswith("["):
        origin = re.match(r"\[([0-9a-fA-F]{8})((?:/[0-9]+[h']?)*)\]", key_info)
        if origin is None:
            raise ValueError("Invalid key origin")
        for step in origin[2].split("/")[1:]:
            child_number(step)
        key_info = key_info[origin.end():]
    data = base58check_decode(key_info)
    if len(data) != 78 or data[:4] not in VERSIONS.values():
        raise ValueError("Expected an xpub or tpub")
    if data[4] == 0 and data[5:13] != bytes(8):
        raise ValueError("A depth-zero xpub must have zero parent and child fields")
    parse_point(data[45:])
    return data[45:], data[13:45]


def ckd_pub(public_key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if type(index) is not int or not 0 <= index < 2**31:
        raise ValueError("Child index must be unhardened")
    if len(chain_code) != 32:
        raise ValueError("Chain code must be 32 bytes")
    parent = parse_point(public_key)
    digest = hmac.digest(chain_code, public_key + index.to_bytes(4, "big"), "sha512")
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= GE.ORDER:
        raise ValueError("Invalid child: tweak out of range")
    child = parent + tweak * G
    if child.infinity:
        raise ValueError("Invalid child: point at infinity")
    return child.to_bytes_compressed(), digest[32:]
