#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin test framework primitive and message structures

CBlock, CTransaction, CBlockHeader, CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives

msg_block, msg_tx, msg_headers, etc.:
    data structures that represent network messages

ser_*, deser_*: functions that handle serialization/deserialization.

Classes use __slots__ to ensure extraneous attributes aren't accidentally added
by tests, compromising their intended effect.
"""

########################################################################
# Adapted from Bitcoin Core test framework messages.py
#  for BIP-375 PSBT validation tests.
########################################################################

import copy
import hashlib
import math
from io import BytesIO

COIN = 100000000  # 1 btc in satoshis
WITNESS_SCALE_FACTOR = 4

# ============================================================================
# Serialization utilities
# ============================================================================

def hash160(s: bytes) -> bytes:
    return hashlib.new("ripemd160", sha256(s)).digest()


def sha256(s: bytes) -> bytes:
    return hashlib.sha256(s).digest()


def hash256(s: bytes) -> bytes:
    return sha256(sha256(s))


def ser_compact_size(l):
    r = b""
    if l < 253:
        r = l.to_bytes(1, "little")
    elif l < 0x10000:
        r = (253).to_bytes(1, "little") + l.to_bytes(2, "little")
    elif l < 0x100000000:
        r = (254).to_bytes(1, "little") + l.to_bytes(4, "little")
    else:
        r = (255).to_bytes(1, "little") + l.to_bytes(8, "little")
    return r


def deser_compact_size(f):
    nit = int.from_bytes(f.read(1), "little")
    if nit == 253:
        nit = int.from_bytes(f.read(2), "little")
    elif nit == 254:
        nit = int.from_bytes(f.read(4), "little")
    elif nit == 255:
        nit = int.from_bytes(f.read(8), "little")
    return nit


def ser_varint(l):
    r = b""
    while True:
        r = bytes([(l & 0x7f) | (0x80 if len(r) > 0 else 0x00)]) + r
        if l <= 0x7f:
            return r
        l = (l >> 7) - 1


def deser_varint(f):
    n = 0
    while True:
        dat = f.read(1)[0]
        n = (n << 7) | (dat & 0x7f)
        if (dat & 0x80) > 0:
            n += 1
        else:
            return n


def deser_string(f):
    nit = deser_compact_size(f)
    return f.read(nit)


def ser_string(s):
    return ser_compact_size(len(s)) + s


def deser_uint256(f):
    return int.from_bytes(f.read(32), 'little')


def ser_uint256(u):
    return u.to_bytes(32, 'little')


def uint256_from_str(s):
    return int.from_bytes(s[:32], 'little')


def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v


# deser_function_name: Allow for an alternate deserialization function on the
# entries in the vector.
def deser_vector(f, c, deser_function_name=None):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        if deser_function_name:
            getattr(t, deser_function_name)(f)
        else:
            t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector (we use this for serializing the vector of transactions
# for a witness block).
def ser_vector(l, ser_function_name=None):
    r = ser_compact_size(len(l))
    for i in l:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += ser_uint256(i)
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(l):
    r = ser_compact_size(len(l))
    for sv in l:
        r += ser_string(sv)
    return r

# like from_hex, but without the hex part
def from_binary(cls, stream):
    """deserialize a binary stream (or bytes object) into an object"""
    # handle bytes object by turning it into a stream
    was_bytes = isinstance(stream, bytes)
    if was_bytes:
        stream = BytesIO(stream)
    obj = cls()
    obj.deserialize(stream)
    if was_bytes:
        assert len(stream.read()) == 0
    return obj


# ============================================================================
# Transaction data structures
# ============================================================================

class COutPoint:
    __slots__ = ("hash", "n")

    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        self.n = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = b""
        r += ser_uint256(self.hash)
        r += self.n.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)

class CTxIn:
    __slots__ = ("nSequence", "prevout", "scriptSig")

    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = b""
        r += self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += self.nSequence.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" \
            % (repr(self.prevout), self.scriptSig.hex(),
               self.nSequence)


class CTxOut:
    __slots__ = ("nValue", "scriptPubKey")

    def __init__(self, nValue=0, scriptPubKey=b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f):
        self.nValue = int.from_bytes(f.read(8), "little", signed=True)
        self.scriptPubKey = deser_string(f)

    def serialize(self):
        r = b""
        r += self.nValue.to_bytes(8, "little", signed=True)
        r += ser_string(self.scriptPubKey)
        return r

    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" \
            % (self.nValue // COIN, self.nValue % COIN,
               self.scriptPubKey.hex())


class CScriptWitness:
    __slots__ = ("stack",)

    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "CScriptWitness(%s)" % \
               (",".join([x.hex() for x in self.stack]))

    def is_null(self):
        if self.stack:
            return False
        return True


class CTxInWitness:
    __slots__ = ("scriptWitness",)

    def __init__(self):
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f):
        self.scriptWitness.stack = deser_string_vector(f)

    def serialize(self):
        return ser_string_vector(self.scriptWitness.stack)

    def __repr__(self):
        return repr(self.scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()


class CTxWitness:
    __slots__ = ("vtxinwit",)

    def __init__(self):
        self.vtxinwit = []

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self):
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    def __repr__(self):
        return "CTxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True


class CTransaction:
    __slots__ = ("nLockTime", "version", "vin", "vout", "wit")

    def __init__(self, tx=None):
        if tx is None:
            self.version = 2
            self.vin = []
            self.vout = []
            self.wit = CTxWitness()
            self.nLockTime = 0
        else:
            self.version = tx.version
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.wit = copy.deepcopy(tx.wit)

    def deserialize(self, f):
        self.version = int.from_bytes(f.read(4), "little")
        self.vin = deser_vector(f, CTxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = int.from_bytes(f.read(1), "little")
            # Not sure why flags can't be zero, but this
            # matches the implementation in bitcoind
            if (flags != 0):
                self.vin = deser_vector(f, CTxIn)
                self.vout = deser_vector(f, CTxOut)
        else:
            self.vout = deser_vector(f, CTxOut)
        if flags != 0:
            self.wit.vtxinwit = [CTxInWitness() for _ in range(len(self.vin))]
            self.wit.deserialize(f)
        else:
            self.wit = CTxWitness()
        self.nLockTime = int.from_bytes(f.read(4), "little")

    def serialize_without_witness(self):
        r = b""
        r += self.version.to_bytes(4, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += self.nLockTime.to_bytes(4, "little")
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = b""
        r += self.version.to_bytes(4, "little")
        if flags:
            dummy = []
            r += ser_vector(dummy)
            r += flags.to_bytes(1, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        r += self.nLockTime.to_bytes(4, "little")
        return r

    # Regular serialization is with witness -- must explicitly
    # call serialize_without_witness to exclude witness data.
    def serialize(self):
        return self.serialize_with_witness()

    @property
    def wtxid_hex(self):
        """Return wtxid (transaction hash with witness) as hex string."""
        return hash256(self.serialize())[::-1].hex()

    @property
    def wtxid_int(self):
        """Return wtxid (transaction hash with witness) as integer."""
        return uint256_from_str(hash256(self.serialize_with_witness()))

    @property
    def txid_hex(self):
        """Return txid (transaction hash without witness) as hex string."""
        return hash256(self.serialize_without_witness())[::-1].hex()

    @property
    def txid_int(self):
        """Return txid (transaction hash without witness) as integer."""
        return uint256_from_str(hash256(self.serialize_without_witness()))

    def is_valid(self):
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > 21000000 * COIN:
                return False
        return True

    # Calculate the transaction weight using witness and non-witness
    # serialization size (does NOT use sigops).
    def get_weight(self):
        with_witness_size = len(self.serialize_with_witness())
        without_witness_size = len(self.serialize_without_witness())
        return (WITNESS_SCALE_FACTOR - 1) * without_witness_size + with_witness_size

    def get_vsize(self):
        return math.ceil(self.get_weight() / WITNESS_SCALE_FACTOR)

    def __repr__(self):
        return "CTransaction(version=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
            % (self.version, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)