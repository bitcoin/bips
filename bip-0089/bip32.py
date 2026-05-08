"""BIP32 helpers for the CCD reference implementation."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
from hashlib import new as hashlib_new, sha256, sha512
from typing import List, Tuple, Mapping, Sequence

from secp256k1lab.secp256k1 import G, GE, Scalar

CURVE_N = Scalar.SIZE

def int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")

def compress_point(point: GE) -> bytes:
    if point.infinity:
        raise ValueError("Cannot compress point at infinity")
    return point.to_bytes_compressed()


def decompress_point(data: bytes) -> GE:
    return GE.from_bytes_compressed(data)

def apply_tweak_to_public(base_public: bytes, tweak: int) -> bytes:
    base_point = GE.from_bytes_compressed(base_public)
    tweaked_point = base_point + (tweak % CURVE_N) * G
    if tweaked_point.infinity:
        raise ValueError("Tweaked key is at infinity")
    return tweaked_point.to_bytes_compressed()


def apply_tweak_to_secret(base_secret: int, tweak: int) -> int:
    if not (0 < base_secret < CURVE_N):
        raise ValueError("Invalid base secret scalar")
    return (base_secret + tweak) % CURVE_N

def decode_path(path_elements: Sequence[object]) -> List[int]:
    result: List[int] = []
    for element in path_elements:
        if isinstance(element, int):
            index = element
        else:
            element_str = str(element)
            hardened = element_str.endswith("'") or element_str.endswith("h")
            suffix = element_str[:-1] if hardened else element_str
            if not suffix:
                raise AssertionError("invalid derivation index")
            index = int(suffix)
            if hardened:
                index |= HARDENED_INDEX
        result.append(index)
    return result

HARDENED_INDEX = 0x80000000


def _hash160(data: bytes) -> bytes:
    return hashlib_new("ripemd160", sha256(data).digest()).digest()


@dataclass
class ExtendedPublicKey:
    point: GE
    chain_code: bytes
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_number: int = 0

    def fingerprint(self) -> bytes:
        return _hash160(compress_point(self.point))[:4]

    def derive_child(self, index: int) -> Tuple[int, "ExtendedPublicKey"]:
        tweak, child_point, child_chain = derive_public_child(self.point, self.chain_code, index)
        child = ExtendedPublicKey(
            point=child_point,
            chain_code=child_chain,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint(),
            child_number=index,
        )
        return tweak, child


def derive_public_child(parent_point: GE, chain_code: bytes, index: int) -> Tuple[int, GE, bytes]:
    if index >= HARDENED_INDEX:
        raise ValueError("Hardened derivations are not supported for delegates")

    data = compress_point(parent_point) + int_to_bytes(index, 4)
    il_ir = hmac.new(chain_code, data, sha512).digest()
    il, ir = il_ir[:32], il_ir[32:]
    tweak = bytes_to_int(il)
    if tweak >= CURVE_N:
        raise ValueError("Invalid tweak derived (>= curve order)")

    child_point_bytes = apply_tweak_to_public(compress_point(parent_point), tweak)
    child_point = decompress_point(child_point_bytes)
    return tweak, child_point, ir


def parse_path(path: str) -> List[int]:
    if not path or path in {"m", "M"}:
        return []
    if path.startswith(("m/", "M/")):
        path = path[2:]

    components: List[int] = []
    for element in path.split("/"):
        if element.endswith("'") or element.endswith("h"):
            raise ValueError("Hardened steps are not allowed in CCD derivations")
        index = int(element)
        if index < 0 or index >= HARDENED_INDEX:
            raise ValueError("Derivation index out of range")
        components.append(index)
    return components

def parse_extended_public_key(data: Mapping[str, object]) -> ExtendedPublicKey:
    compressed_hex = data.get("compressed")
    if not isinstance(compressed_hex, str):
        raise ValueError("Compressed must be a string")

    chain_code_hex = data.get("chain_code")
    if not isinstance(chain_code_hex, str):
        raise ValueError("Chain code must be a string")
    
    depth = data.get("depth")
    if not isinstance(depth, int):
        raise ValueError("Depth must be an integer")
    
    child_number = data.get("child_number", 0)
    if not isinstance(child_number, int):
        raise ValueError("Child number must be an integer")

    parent_fp_hex = data.get("parent_fingerprint", "00000000")

    compressed = bytes.fromhex(compressed_hex)
    chain_code = bytes.fromhex(chain_code_hex)
    parent_fp = bytes.fromhex(str(parent_fp_hex))
    return build_extended_public_key(
        compressed,
        chain_code,
        depth=depth,
        parent_fingerprint=parent_fp,
        child_number=child_number,
    )


def build_extended_public_key(
    compressed: bytes,
    chain_code: bytes,
    *,
    depth: int = 0,
    parent_fingerprint: bytes = b"\x00\x00\x00\x00",
    child_number: int = 0,
) -> ExtendedPublicKey:
    if len(chain_code) != 32:
        raise ValueError("Chain code must be 32 bytes")
    point = decompress_point(compressed)
    return ExtendedPublicKey(
        point=point,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
    )
