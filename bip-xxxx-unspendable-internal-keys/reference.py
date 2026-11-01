#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reference construction for unspendable internal keys; Python 3.10+.

For demonstration and interoperability testing, not production use. Parsing
checks the construction's syntax, not Miniscript typing, safety, satisfaction,
or wallet-policy validity. No private keys or signing operations are supported.

The parser and normalizer use recursion. Deeply nested inputs may exceed
Python's recursion limit and raise RecursionError.
"""

from dataclasses import dataclass
import re

from bip32 import VERSIONS, ckd_pub, child_number, parse_xpub
from encoding import base58check_encode, compact_size
from policy import Key, Node, Parser, Step, keys, render
from secp256k1lab.util import tagged_hash


H = bytes.fromhex("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")


def key_record(key_info: str) -> bytes:
    """Return the commitment record, excluding origin and extended-key metadata."""
    public_key, chain_code = parse_xpub(key_info)
    return public_key + chain_code


def validate_paths(root: Node) -> None:
    internal = root.args[0]
    if not internal.path or internal.path[-1] != Step("wildcard", ("*",)):
        raise ValueError("The internal path must end in /*")
    for step in internal.path:
        if step.kind != "wildcard" and any(child_number(v) >= 2**31 for v in step.values):
            raise ValueError("The internal path must be unhardened")
    lengths = {len(s.values) for key in keys(root) for s in key.path if s.kind == "tuple"}
    if len(lengths) > 1:
        raise ValueError("Multipath tuples must have equal lengths")
    if lengths:
        count = next(iter(lengths))
        tuples = [s.values for s in internal.path if s.kind == "tuple"]
        if tuples != [tuple(str(i) for i in range(count))]:
            raise ValueError("The internal tuple must be <0;...;m-1>")


def parse_policy(template: str) -> Node:
    root = Parser(template).parse()
    validate_paths(root)
    return root


def expanded(node):
    """Expand sugar into structural nodes before choosing canonical spellings."""
    if not isinstance(node, Node):
        return node
    args = tuple(expanded(arg) for arg in node.args)
    if node.op in ("pk", "pkh"):
        return Node("c:", (Node("pk_k" if node.op == "pk" else "pk_h", args),))
    if node.op == "and_n":
        return Node("andor", args + (Node("0", ()),))
    if node.op == "t:":
        return Node("and_v", args + (Node("1", ()),))
    if node.op == "l:":
        return Node("or_i", (Node("0", ()),) + args)
    if node.op == "u:":
        return Node("or_i", args + (Node("0", ()),))
    return Node(node.op, args)


def sugared(node):
    if not isinstance(node, Node):
        return node
    args = tuple(sugared(arg) for arg in node.args)
    if node.op == "c:" and args[0].op in ("pk_k", "pk_h"):
        return Node("pk" if args[0].op == "pk_k" else "pkh", args[0].args)
    if node.op == "andor" and args[2] == Node("0", ()):
        return Node("and_n", args[:2])
    if node.op == "and_v" and args[1] == Node("1", ()):
        return Node("t:", args[:1])
    if node.op == "or_i":
        if args[0] == Node("0", ()):
            return Node("l:", args[1:])
        if args[1] == Node("0", ()):
            return Node("u:", args[:1])
    return Node(node.op, args)


def sort_tree(node, records: dict[int, bytes]):
    if isinstance(node, Key):
        indexes = tuple(sorted(node.indexes, key=records.__getitem__)) if node.kind == "musig" else node.indexes
        return Key(node.kind, indexes, node.path)
    if not isinstance(node, Node):
        return node
    args = tuple(sort_tree(arg, records) for arg in node.args)
    resolved = lambda arg: render(arg, lambda i: records[i].hex()).encode("ascii")
    if node.op == "branch":
        args = tuple(sorted(args, key=resolved))
    elif node.op == "sortedmulti_a":
        args = args[:1] + tuple(sorted(args[1:], key=resolved))
    return Node(node.op, args)


@dataclass(frozen=True)
class NormalizedPolicy:
    template: str
    records: tuple[bytes, ...]


def normalize_policy(template: str, keys_info: list[str]) -> NormalizedPolicy:
    root = parse_policy(template)
    records = {}
    for key in keys(root):
        for i in key.indexes:
            if i >= len(keys_info):
                raise ValueError("Key index out of range")
            if i not in records:
                records[i] = key_record(keys_info[i])
    root = sort_tree(sugared(expanded(root)), records)
    assigned = {}

    def reference(i: int) -> str:
        record = records[i]
        if record not in assigned:
            assigned[record] = len(assigned)
        return "@" + str(assigned[record])

    normalized = render(root, reference)
    return NormalizedPolicy(normalized, tuple(assigned))


@dataclass(frozen=True)
class SyntheticRoot:
    preimage: bytes
    chain_code: bytes

    def serialize(self, network: str = "mainnet") -> str:
        if network not in VERSIONS:
            raise ValueError("Network must be mainnet or testnet")
        return base58check_encode(VERSIONS[network] + bytes(9) + self.chain_code + H)


def construct_root(policy: NormalizedPolicy) -> SyntheticRoot:
    template = policy.template.encode("ascii")
    preimage = compact_size(len(template)) + template + compact_size(len(policy.records)) + b"".join(policy.records)
    return SyntheticRoot(preimage, tagged_hash("WalletPolicy/NUMS/1", preimage))


def selected_path(policy: NormalizedPolicy, expansion: int, index: int) -> tuple[int, ...]:
    internal = parse_policy(policy.template).args[0]
    count = next((len(s.values) for s in internal.path if s.kind == "tuple"), 1)
    if type(expansion) is not int or not 0 <= expansion < count:
        raise ValueError("Expansion out of range")
    if type(index) is not int or not 0 <= index < 2**31:
        raise ValueError("Wildcard index out of range")
    return tuple(index if s.kind == "wildcard" else child_number(s.values[expansion if s.kind == "tuple" else 0])
                 for s in internal.path)


def derive_internal_key(policy: NormalizedPolicy, expansion: int, index: int) -> bytes:
    public_key, chain_code = H, construct_root(policy).chain_code
    for child in selected_path(policy, expansion, index):
        public_key, chain_code = ckd_pub(public_key, chain_code, child)
    return public_key[1:]


@dataclass(frozen=True)
class ExportedPolicy:
    template: str
    keys_info: tuple[str, ...]
    descriptor: str


def export_policy(template: str, keys_info: list[str], network: str = "mainnet") -> ExportedPolicy:
    policy = normalize_policy(template, keys_info)
    root = construct_root(policy).serialize(network)
    # Parsing has established that the first underscore is the internal key.
    exported_template = template.replace("_", "@" + str(len(keys_info)), 1)
    exported_keys = tuple(keys_info) + (root,)
    descriptor = re.sub(r"@([0-9]+)", lambda m: exported_keys[int(m[1])], exported_template)
    return ExportedPolicy(exported_template, exported_keys, descriptor.replace("/**", "/<0;1>/*"))
