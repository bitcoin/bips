"""
Simple example of construction for Pay-to-Merkle-Root (P2MR) outputs and control blocks.

Usage: python -m p2mr
"""

from enum import Enum
from typing import Any, Dict, List, Union

import binascii
import hashlib
import json


class Encoding(Enum):
    """enum type to list supported encodings"""

    BECH32 = 1
    BECH32M = 2


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3
MAX_COMPACT_SIZE = 2**64 - 1

# A script tree node is either a leaf (dict) or a branch (list of nodes)
ScriptTree = Union[Dict[str, Any], List["ScriptTree"]]


#
# Utility Functions
#
def sha256(b: bytes) -> bytes:
    """sha256 hash function"""
    return hashlib.sha256(b).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Compute tagged hash of data as per BIP-340"""
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)


def h2b(h: str) -> bytes:
    """hex-to-byte converter"""
    return binascii.unhexlify(h)


def s2w(script: str) -> List[int]:
    """Convert a script/witprog hex string to a List[int] of its bytes"""
    return list(h2b(script))


def get_compact_size(n: int) -> bytes:
    """Get the compact size byte for given script"""
    if not isinstance(n, int) or not (0 <= n <= MAX_COMPACT_SIZE):
        raise ValueError(
            "get_compact_size: out of bounds! must be 0 <= n <= 0xffffffffffffffff"
        )
    if n < 0xFD:  # single-byte case when size < 0xffff
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    else:  # n > 0xffffffff
        return b"\xff" + n.to_bytes(8, "little")


def serialize_varbytes(b: bytes) -> bytes:
    """Serialize variably-sized data as: compact-size byte || data bytes."""
    return get_compact_size(len(b)) + b


#
# P2MR-specific Functions
#
def tapleaf_hash(script: bytes, tapleaf_ver: int = 0xc0) -> bytes:
    """Hash function for tree leaves"""
    if not script:
        raise ValueError("tapleaf_hash: script is required")
    leaf = bytes([tapleaf_ver & 0xfe]) + serialize_varbytes(script)
    return tagged_hash("TapLeaf", leaf)


def tapbranch_hash(left: bytes, right: bytes) -> bytes:
    """Hash function for tree branches"""
    return tagged_hash("TapBranch", b"".join(sorted((left, right))))


def compute_merkle_root(tree: ScriptTree) -> bytes:
    """Recursively compute script tree merkle root"""
    if isinstance(tree, dict):  # Leaf
        version = tree["leafVersion"]
        script = h2b(tree["script"])
        return tapleaf_hash(script=script, tapleaf_ver=version)

    elif isinstance(tree, list):  # Branch
        # Script trees are treated strictly as binary trees; each branch node should have
        # exactly 2 children. This isn't a general n-ary fold, and combining
        # more than 2 children sequentially would not produce a valid P2MR merkle root.
        assert len(tree) == 2, f"expected binary branch, got {len(tree)} children"
        left, right = compute_merkle_root(tree[0]), compute_merkle_root(tree[1])
        return tapbranch_hash(left, right)

    else:  # badbadnotgood
        raise ValueError("Invalid tree node")


def compute_control_block(path: int, tree: ScriptTree) -> bytes:
    """
    Compute the control block for a script leaf at a given position in the script tree.
    The `path` argument encodes the position as follows.

    Starting at depth zero, follow the branches of the script tree until reaching a leaf.
    When we encounter a branch at any depth `d` (steps from the root), we look at the bit
    `(path >> d) & 1` to decide whether to take the left or right branch.
    """
    if isinstance(tree, dict):
        return bytes([tree["leafVersion"] | 1])
    assert isinstance(tree, list) and len(tree) == 2

    control_block = b""

    while isinstance(tree, list):
        assert len(tree) == 2
        sibling = tree[(path & 1) ^ 1]
        tree = tree[(path & 1)]
        control_block = compute_merkle_root(sibling) + control_block
        path >>= 1

    assert isinstance(tree, dict)
    return bytes([tree["leafVersion"] | 1]) + control_block


#
# Bech32/Bech32m Encoding
#
# Bech32 encoding code is taken from sipa (BIP-0350), and has been tested against the test vectors therein:
# https://github.com/sipa/bech32/blob/master/ref/python/tests.py
#
def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data chars."""
    if not data:
        raise ValueError("bech32 data portion must be provided")
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None


def bech32_create_checksum(hrp, data, spec):
    """Compute the checksum values given HRP and data."""
    if not data:
        raise ValueError("bech32 data portion must be provided")
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data, spec):
    """Compute a Bech32 string given HRP and data."""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([BECH32_CHARSET[c] for c in combined])


def bech32_decode(bech):
    """Validate a Bech32/Bech32m string, and determine HRP and data."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)
    if not all(c in BECH32_CHARSET for c in bech[pos + 1 :]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(c) for c in bech[pos + 1 :]]
    spec = bech32_verify_checksum(hrp, data)
    if not spec:
        return (None, None, None)
    return (hrp, data[:-6], spec)


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion"""
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def decode(hrp, addr):
    """Decode a SegWit address."""
    hrpgot, data, spec = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    if (
        data[0] == 0
        and spec != Encoding.BECH32
        or data[0] != 0
        and spec != Encoding.BECH32M
    ):
        return (None, None)
    return (data[0], decoded)


def encode(hrp, witver, witprog):
    """Encode a SegWit address."""
    spec = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5), spec)
    if decode(hrp, ret) == (None, None):
        return None
    return ret


#
# BIP-360 Test Code
#
def collect_leaf_hashes(tree: ScriptTree) -> List[bytes]:
    """Recursively collect leaf hashes in order (for verification)"""
    if isinstance(tree, dict):  # Leaf
        version = tree["leafVersion"]
        script = h2b(tree["script"])
        return [tapleaf_hash(script=script, tapleaf_ver=version)]

    elif isinstance(tree, list):  # Branch: recurse on children
        hashes: List[bytes] = []
        for sub in tree:
            hashes.extend(collect_leaf_hashes(sub))
        return hashes

    else:
        raise ValueError("Invalid tree node")


def walk_script_tree_paths(
    script_tree: ScriptTree, path: int = 0, depth: int = 0
) -> List[int]:
    """Walk through a script tree and produce a list of the bit-encoded traversal paths for each leaf.
    Used for testing compute_control_block."""
    if isinstance(script_tree, dict):
        return [path]
    assert isinstance(script_tree, list) and len(script_tree) == 2
    lchild_paths = walk_script_tree_paths(script_tree[0], path, depth + 1)
    rchild_paths = walk_script_tree_paths(
        script_tree[1], path | (1 << depth), depth + 1
    )
    return lchild_paths + rchild_paths


def collect_control_blocks(script_tree: ScriptTree) -> List[bytes]:
    """Return control blocks for all leaves in tree declaration order.
    Note: This ordering is for testing purposes. In practice, you would
    compute the control block for a specific leaf at spend-time using
    `compute_control_block(path, tree)`."""
    leaf_node_paths: List[int] = walk_script_tree_paths(script_tree)
    return [compute_control_block(path, script_tree) for path in leaf_node_paths]


def extract_test_data(v: Dict[str, Any]) -> Dict[str, Any]:
    """Extract test data from a test vector, returning None for missing keys"""
    given = v.get("given", {})
    intermediary = v.get("intermediary", {})
    expected = v.get("expected", {})

    return {
        "id": v["id"],
        "objective": v["objective"],
        "script_tree": given.get("scriptTree"),
        "leaf_hashes": intermediary.get("leafHashes"),
        "merkle_root": intermediary.get("merkleRoot"),
        "script_pubkey": expected.get("scriptPubKey"),
        "bip350_address": expected.get("bip350Address"),
        "script_path_control_blocks": expected.get("scriptPathControlBlocks"),
        "error": expected.get("error"),
        "has_internal_pubkey": "internalPubkey" in given,
    }


def run_single_test(v: Dict[str, Any], test_num: int) -> bool:
    """Run a single test vector. Returns True if passed."""
    print(f"\nBIP-360 Test Vector {test_num}\n{'-' * 25}")

    v = extract_test_data(v)

    try:
        # Error Case: P2MR misuse / presence of internal pubkey
        if v["has_internal_pubkey"]:
            assert v["error"], "expected an error message"
            print(f"Error: {v['error']}")

        # Error Case: Null/missing tree
        elif v["script_tree"] is None:
            assert (
                v["merkle_root"] is None
            ), f"expected merkle_root None for null tree, got {v['merkle_root']}"
            assert (
                v["leaf_hashes"] is None
            ), f"expected leaf_hashes None for null tree, got {v['leaf_hashes']}"
            assert (
                v["script_pubkey"] is None
            ), f"expected script_pubkey None for null tree, got {v['script_pubkey']}"
            assert v["error"], "expected an error message"
            print(f"Error: {v['error']}")

        # General Case: Single- and Multi-Leaf script trees
        else:
            # test script leaf hashing
            derived_leaf_hashes = [
                h.hex() for h in collect_leaf_hashes(v["script_tree"])
            ]
            assert derived_leaf_hashes == v["leaf_hashes"], (
                f"leaf hash mismatch:\n"
                f"  derived: {derived_leaf_hashes}\n"
                f"  expected: {v['leaf_hashes']}"
            )
            print("Leaf Hashes: [\n" + ",\n".join(derived_leaf_hashes) + "\n]")

            # test merkle root computation
            derived_merkle_root = compute_merkle_root(v["script_tree"]).hex()
            assert derived_merkle_root == v["merkle_root"], (
                f"merkle root mismatch: "
                f"derived={derived_merkle_root}, expected={v['merkle_root']}"
            )
            print(f"Merkle Root: {derived_merkle_root}")

            # test scriptPubkey formation
            derived_scriptPubkey = f"5220{derived_merkle_root}"
            assert derived_scriptPubkey == v["script_pubkey"], (
                f"scriptPubKey mismatch: "
                f"derived={derived_scriptPubkey}, expected={v['script_pubkey']}"
            )
            print(f"ScriptPubkey: {derived_scriptPubkey}")

            # test address encoding
            if v["bip350_address"]:
                derived_bip350_address = encode(
                    hrp="bc", witver=2, witprog=s2w(derived_merkle_root)
                )
                assert derived_bip350_address == v["bip350_address"], (
                    f"bip350 address mismatch: "
                    f"derived={derived_bip350_address}, expected={v['bip350_address']}"
                )
                print(f"BIP350 Address: {derived_bip350_address}")

            # test control block derivation
            if v["script_path_control_blocks"]:
                derived_control_blocks = [
                    cb.hex() for cb in collect_control_blocks(v["script_tree"])
                ]
                assert derived_control_blocks == v["script_path_control_blocks"], (
                    f"control blocks mismatch:\n"
                    f"  derived: {derived_control_blocks}\n"
                    f"  expected: {v['script_path_control_blocks']}"
                )
                print(
                    "ScriptPathControlBlocks: [\n"
                    + ",\n".join(derived_control_blocks)
                    + "\n]"
                )

        print(f"\nPASSED '{v['id']}' with objective '{v['objective']}'")
        return True

    except AssertionError as e:
        print(f"FAILED '{v['id']}': {e}")
        return False


def BIP360_tests() -> None:
    """Run all BIP-360 Test Vectors."""
    print("\nRunning BIP-0360 Pay-to-Merkle-Root (P2MR) Tests...")

    with open("../common/tests/data/p2mr_construction.json", "r") as f:
        test_vectors = json.load(f)["test_vectors"]

    passed = sum(run_single_test(v, i + 1) for i, v in enumerate(test_vectors))
    print(f"\n{passed}/{len(test_vectors)} BIP-360 tests passed successfully.")


if __name__ == "__main__":
    BIP360_tests()
