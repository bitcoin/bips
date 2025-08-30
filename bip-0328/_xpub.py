#!/usr/bin/env python3
# Copyright (c) 2020 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Key Classes and Utilities
*************************

Classes and utilities for working with extended public keys, key origins, and other key related things.
"""

import _base58 as base58
from _common import (
    hash256,
    hash160,
)
import binascii
import hmac
import hashlib
import struct
from typing import (
    Dict,
    Optional,
    Sequence,
    Tuple,
)


HARDENED_FLAG = 1 << 31

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Optional[Tuple[int, int]]

def H_(x: int) -> int:
    """
    Shortcut function that "hardens" a number in a BIP44 path.
    """
    return x | HARDENED_FLAG

def is_hardened(i: int) -> bool:
    """
    Returns whether an index is hardened
    """
    return i & HARDENED_FLAG != 0


def point_add(p1: Point, p2: Point) -> Point:
    if (p1 is None):
        return p2
    if (p2 is None):
        return p1
    if (p1[0] == p2[0] and p1[1] != p2[1]):
        return None
    if (p1 == p2):
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], p - 2, p)) % p
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], p - 2, p)) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    return (x3, (lam * (p1[0] - x3) - p1[1]) % p)


def point_mul(p: Point, n: int) -> Point:
    r = None
    for i in range(256):
        if ((n >> i) & 1):
            r = point_add(r, p)
        p = point_add(p, p)
    return r


def deserialize_point(b: bytes) -> Point:
    x = int.from_bytes(b[1:], byteorder="big")
    y = pow((x * x * x + 7) % p, (p + 1) // 4, p)
    if (y & 1 != b[0] & 1):
        y = p - y
    return (x, y)


def bytes_to_point(point_bytes: bytes) -> Point:
    header = point_bytes[0]
    if header == 4:
        x = point_bytes[1:33]
        y = point_bytes[33:65]
        return (int(binascii.hexlify(x), 16), int(binascii.hexlify(y), 16))
    return deserialize_point(point_bytes)

def point_to_bytes(p: Point) -> bytes:
    if p is None:
        raise ValueError("Cannot convert None to bytes")
    return (b'\x03' if p[1] & 1 else b'\x02') + p[0].to_bytes(32, byteorder="big")


# An extended public key (xpub) or private key (xprv). Just a data container for now.
# Only handles deserialization of extended keys into component data to be handled by something else
class ExtendedKey(object):
    """
    A BIP 32 extended public key.
    """

    MAINNET_PUBLIC = b'\x04\x88\xB2\x1E'
    MAINNET_PRIVATE = b'\x04\x88\xAD\xE4'
    TESTNET_PUBLIC = b'\x04\x35\x87\xCF'
    TESTNET_PRIVATE = b'\x04\x35\x83\x94'

    def __init__(self, version: bytes, depth: int, parent_fingerprint: bytes, child_num: int, chaincode: bytes, privkey: Optional[bytes], pubkey: bytes) -> None:
        """
        :param version: The version bytes for this xpub
        :param depth: The depth of this xpub as defined in BIP 32
        :param parent_fingerprint: The 4 byte fingerprint of the parent xpub as defined in BIP 32
        :param child_num: The number of this xpub as defined in BIP 32
        :param chaincode: The chaincode of this xpub as defined in BIP 32
        :param privkey: The private key for this xpub if available
        :param pubkey: The public key for this xpub
        """
        self.version: bytes = version
        self.is_testnet: bool = version == ExtendedKey.TESTNET_PUBLIC or version == ExtendedKey.TESTNET_PRIVATE
        self.is_private: bool = version == ExtendedKey.MAINNET_PRIVATE or version == ExtendedKey.TESTNET_PRIVATE
        self.depth: int = depth
        self.parent_fingerprint: bytes = parent_fingerprint
        self.child_num: int = child_num
        self.chaincode: bytes = chaincode
        self.pubkey: bytes = pubkey
        self.privkey: Optional[bytes] = privkey

    @classmethod
    def deserialize(cls, xpub: str) -> 'ExtendedKey':
        """
        Create an :class:`~ExtendedKey` from a Base58 check encoded xpub

        :param xpub: The Base58 check encoded xpub
        """
        data = base58.decode(xpub)[:-4] # Decoded xpub without checksum
        return cls.from_bytes(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ExtendedKey':
        """
        Create an :class:`~ExtendedKey` from a serialized xpub

        :param xpub: The serialized xpub
        """

        version = data[0:4]
        if version not in [ExtendedKey.MAINNET_PRIVATE, ExtendedKey.MAINNET_PUBLIC, ExtendedKey.TESTNET_PRIVATE, ExtendedKey.TESTNET_PUBLIC]:
            raise Exception(f"Extended key magic of {version.hex()} is invalid")
        is_private = version == ExtendedKey.MAINNET_PRIVATE or version == ExtendedKey.TESTNET_PRIVATE
        depth = data[4]
        parent_fingerprint = data[5:9]
        child_num = struct.unpack('>I', data[9:13])[0]
        chaincode = data[13:45]

        if is_private:
            privkey = data[46:]
            pubkey = point_to_bytes(point_mul(G, int.from_bytes(privkey, byteorder="big")))
            return cls(version, depth, parent_fingerprint, child_num, chaincode, privkey, pubkey)
        else:
            pubkey = data[45:78]
            return cls(version, depth, parent_fingerprint, child_num, chaincode, None, pubkey)

    def serialize(self) -> bytes:
        """
        Serialize the ExtendedKey with the serialization format described in BIP 32.
        Does not create an xpub string, but the bytes serialized here can be Base58 check encoded into one.

        :return: BIP 32 serialized extended key
        """
        r = self.version + struct.pack('B', self.depth) + self.parent_fingerprint + struct.pack('>I', self.child_num) + self.chaincode
        if self.is_private:
            if self.privkey is None:
                raise ValueError("Somehow we are private but don't have a privkey")
            r += b"\x00" + self.privkey
        else:
            r += self.pubkey
        return r

    def to_string(self) -> str:
        """
        Serialize the ExtendedKey as a Base58 check encoded xpub string

        :return: Base58 check encoded xpub
        """
        data = self.serialize()
        checksum = hash256(data)[0:4]
        return base58.encode(data + checksum)

    def get_printable_dict(self) -> Dict[str, object]:
        """
        Get the attributes of this ExtendedKey as a dictionary that can be printed

        :return: Dictionary containing ExtendedKey information that can be printed
        """
        d: Dict[str, object] = {}
        d['testnet'] = self.is_testnet
        d['private'] = self.is_private
        d['depth'] = self.depth
        d['parent_fingerprint'] = binascii.hexlify(self.parent_fingerprint).decode()
        d['child_num'] = self.child_num
        d['chaincode'] = binascii.hexlify(self.chaincode).decode()
        if self.is_private and isinstance(self.privkey, bytes):
            d['privkey'] = binascii.hexlify(self.privkey).decode()
        d['pubkey'] = binascii.hexlify(self.pubkey).decode()
        return d

    def derive_pub(self, i: int) -> 'ExtendedKey':
        """
        Derive the public key at the given child index.

        :param i: The child index of the pubkey to derive
        """
        if is_hardened(i):
            raise ValueError("Index cannot be larger than 2^31")

        # Data to HMAC.  Same as CKDpriv() for public child key.
        data = self.pubkey + struct.pack(">L", i)

        # Get HMAC of data
        Ihmac = hmac.new(self.chaincode, data, hashlib.sha512).digest()
        Il = Ihmac[:32]
        Ir = Ihmac[32:]

        # Construct curve point Il*G+K
        Il_int = int(binascii.hexlify(Il), 16)
        child_pubkey = point_add(point_mul(G, Il_int), bytes_to_point(self.pubkey))

        # Construct and return a new BIP32Key
        pubkey = point_to_bytes(child_pubkey)
        chaincode = Ir
        fingerprint = hash160(self.pubkey)[0:4]
        return ExtendedKey(ExtendedKey.TESTNET_PUBLIC if self.is_testnet else ExtendedKey.MAINNET_PUBLIC, self.depth + 1, fingerprint, i, chaincode, None, pubkey)

    def derive_pub_path(self, path: Sequence[int]) -> 'ExtendedKey':
        """
        Derive the public key at the given path

        :param path: Sequence of integers for the path of the pubkey to derive
        """
        key = self
        for i in path:
            key = key.derive_pub(i)
        return key
