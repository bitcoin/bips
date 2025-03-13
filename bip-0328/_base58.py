"""
Base 58 conversion utilities
****************************
"""

#
# base58.py
# Original source: git://github.com/joric/brutus.git
# which was forked from git://github.com/samrushing/caesure.git
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from binascii import hexlify, unhexlify
from typing import List

from _common import hash256


b58_digits: str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def encode(b: bytes) -> str:
    """
    Encode bytes to a base58-encoded string

    :param b: Bytes to encode
    :return: Base58 encoded string of ``b``
    """

    # Convert big-endian bytes to integer
    n: int = int('0x0' + hexlify(b).decode('utf8'), 16)

    # Divide that integer into base58
    temp: List[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        temp.append(b58_digits[r])
    res: str = ''.join(temp[::-1])

    # Encode leading zeros as base58 zeros
    czero: int = 0
    pad: int = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def decode(s: str) -> bytes:
    """
    Decode a base58-encoding string, returning bytes

    :param s: Base48 string to decode
    :return: Bytes encoded by ``s``
    """
    if not s:
        return b''

    # Convert the string to an integer
    n: int = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise Exception('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h: str = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res

def decode_check(s: str) -> bytes:
    """
    Decode a Base58Check encoded string, returning bytes

    :param s: Base58 string to decode
    :return: Bytes encoded by ``s``
    """
    data = decode(s)
    payload = data[:-4]
    checksum = data[-4:]
    calc_checksum = hash256(payload)
    if checksum != calc_checksum[:4]:
        raise ValueError("Invalid checksum")
    return payload

def encode_check(b: bytes) -> str:
    checksum = hash256(b)[0:4]
    data = b + checksum
    return encode(data)

def get_xpub_fingerprint(s: str) -> bytes:
    """
    Get the parent fingerprint from an extended public key

    :param s: The extended pubkey
    :return: The parent fingerprint bytes
    """
    data = decode(s)
    fingerprint = data[5:9]
    return fingerprint

def get_xpub_fingerprint_hex(xpub: str) -> str:
    """
    Get the parent fingerprint as a hex string from an extended public key

    :param s: The extended pubkey
    :return: The parent fingerprint as a hex string
    """
    data = decode(xpub)
    fingerprint = data[5:9]
    return hexlify(fingerprint).decode()

def to_address(b: bytes, version: bytes) -> str:
    """
    Base58 Check Encode the data with the version number.
    Used to encode legacy style addresses.

    :param b: The data to encode
    :param version: The version number to encode with
    :return: The Base58 Check Encoded string
    """
    data = version + b
    checksum = hash256(data)[0:4]
    data += checksum
    return encode(data)

def xpub_to_pub_hex(xpub: str) -> str:
    """
    Get the public key as a string from the extended public key.

    :param xpub: The extended pubkey
    :return: The pubkey hex string
    """
    data = decode(xpub)
    pubkey = data[-37:-4]
    return hexlify(pubkey).decode()


def xpub_to_xonly_pub_hex(xpub: str) -> str:
    """
    Get the public key as a string from the extended public key.

    :param xpub: The extended pubkey
    :return: The pubkey hex string
    """
    data = decode(xpub)
    pubkey = data[-36:-4]
    return hexlify(pubkey).decode()


def xpub_main_2_test(xpub: str) -> str:
    """
    Convert an extended pubkey from mainnet version to testnet version.

    :param xpub: The extended pubkey
    :return: The extended pubkey re-encoded using testnet version bytes
    """
    data = decode(xpub)
    test_data = b'\x04\x35\x87\xCF' + data[4:-4]
    checksum = hash256(test_data)[0:4]
    return encode(test_data + checksum)
