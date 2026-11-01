#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Base58Check and CompactSize serialization helpers."""

from secp256k1lab.util import hash_sha256 as sha256


BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_encode(payload: bytes) -> str:
    data = payload + sha256(sha256(payload))[:4]
    number = int.from_bytes(data, "big")
    result = ""
    while number:
        number, digit = divmod(number, 58)
        result = BASE58[digit] + result
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + result


def base58check_decode(text: str) -> bytes:
    number = 0
    for char in text:
        if char not in BASE58:
            raise ValueError("Invalid Base58 character")
        number = number * 58 + BASE58.index(char)
    data = b"\0" * (len(text) - len(text.lstrip("1")))
    data += number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(data) < 4 or sha256(sha256(data[:-4]))[:4] != data[-4:]:
        raise ValueError("Invalid Base58Check checksum")
    return data[:-4]


def compact_size(number: int) -> bytes:
    if type(number) is not int or not 0 <= number < 2**64:
        raise ValueError("CompactSize value out of range")
    if number < 253:
        return bytes([number])
    for prefix, size in ((253, 2), (254, 4), (255, 8)):
        if number < 1 << (8 * size):
            return bytes([prefix]) + number.to_bytes(size, "little")
    raise AssertionError("Unreachable")
