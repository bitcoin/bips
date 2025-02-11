"""
Common Classes and Utilities
****************************
"""

import hashlib

def sha256(s: bytes) -> bytes:
    """
    Perform a single SHA256 hash.

    :param s: Bytes to hash
    :return: The hash
    """
    return hashlib.new('sha256', s).digest()


def ripemd160(s: bytes) -> bytes:
    """
    Perform a single RIPEMD160 hash.

    :param s: Bytes to hash
    :return: The hash
    """
    return hashlib.new('ripemd160', s).digest()


def hash256(s: bytes) -> bytes:
    """
    Perform a double SHA256 hash.
    A SHA256 is performed on the input, and then a second
    SHA256 is performed on the result of the first SHA256

    :param s: Bytes to hash
    :return: The hash
    """
    return sha256(sha256(s))


def hash160(s: bytes) -> bytes:
    """
    perform a single SHA256 hash followed by a single RIPEMD160 hash on the result of the SHA256 hash.

    :param s: Bytes to hash
    :return: The hash
    """
    return ripemd160(sha256(s))
