import hashlib
import struct
from io import BytesIO
from secp256k1 import ECKey
from typing import Union


def from_hex(hex_string):
    """Deserialize from a hex string representation (e.g. from RPC)"""
    return BytesIO(bytes.fromhex(hex_string))


def ser_uint32(u: int) -> bytes:
    return u.to_bytes(4, "big")


def ser_uint256(u):
    return u.to_bytes(32, 'little')


def deser_uint256(f):
    return int.from_bytes(f.read(32), 'little')


def deser_txid(txid: str):
    # recall that txids are serialized little-endian, but displayed big-endian
    # this means when converting from a human readable hex txid, we need to first
    # reverse it before deserializing it
    dixt = "".join(map(str.__add__, txid[-2::-2], txid[-1::-2]))
    return bytes.fromhex(dixt)


def deser_compact_size(f: BytesIO):
    view = f.getbuffer()
    nbytes = view.nbytes;
    view.release()
    if (nbytes == 0):
        return 0 # end of stream

    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


def deser_string(f: BytesIO):
    nit = deser_compact_size(f)
    return f.read(nit)


def deser_string_vector(f: BytesIO):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


class COutPoint:
    __slots__ = ("hash", "n",)

    def __init__(self, hash=b"", n=0,):
        self.hash = hash
        self.n = n

    def serialize(self):
        r = b""
        r += self.hash
        r += struct.pack("<I", self.n)
        return r

    def deserialize(self, f):
        self.hash = f.read(32)
        self.n = struct.unpack("<I", f.read(4))[0]


class VinInfo:
    __slots__ = ("outpoint", "scriptSig", "txinwitness", "prevout", "private_key")

    def __init__(self, outpoint=None, scriptSig=b"", txinwitness=None, prevout=b"", private_key=None):
        if outpoint is None:
            self.outpoint = COutPoint()
        else:
            self.outpoint = outpoint
        if txinwitness is None:
            self.txinwitness = CTxInWitness()
        else:
            self.txinwitness = txinwitness
        if private_key is None:
            self.private_key = ECKey()
        else:
            self.private_key = private_key
        self.scriptSig = scriptSig
        self.prevout = prevout


class CScriptWitness:
    __slots__ = ("stack",)

    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def is_null(self):
        if self.stack:
            return False
        return True


class CTxInWitness:
    __slots__ = ("scriptWitness",)

    def __init__(self):
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f: BytesIO):
        self.scriptWitness.stack = deser_string_vector(f)
        return self

    def is_null(self):
        return self.scriptWitness.is_null()


def hash160(s: Union[bytes, bytearray]) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()


def is_p2tr(spk: bytes) -> bool:
    if len(spk) != 34:
        return False
    # OP_1 OP_PUSHBYTES_32 <32 bytes>
    return (spk[0] == 0x51) & (spk[1] == 0x20)


def is_p2wpkh(spk: bytes) -> bool:
    if len(spk) != 22:
        return False
    # OP_0 OP_PUSHBYTES_20 <20 bytes>
    return (spk[0] == 0x00) & (spk[1] == 0x14)


def is_p2sh(spk: bytes) -> bool:
    if len(spk) != 23:
        return False
    # OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUAL
    return (spk[0] == 0xA9) & (spk[1] == 0x14) & (spk[-1] == 0x87)


def is_p2pkh(spk: bytes) -> bool:
    if len(spk) != 25:
        return False
    # OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    return (spk[0] == 0x76) & (spk[1] == 0xA9) & (spk[2] == 0x14) & (spk[-2] == 0x88) & (spk[-1] == 0xAC)




