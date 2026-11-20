#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Reference construction for unspendable internal keys; Python 3.10+.

For demonstration and interoperability testing, not production use. Parsing
checks the construction's syntax, not Miniscript typing, safety, satisfaction,
or wallet-policy validity. No private keys or signing operations are supported.

Template parsing uses recursion. Deeply nested inputs may exceed
Python's recursion limit and raise RecursionError.
"""

from dataclasses import dataclass
import re

from bip32 import VERSIONS, ckd_pub, parse_xpub
from encoding import base58check_encode, compact_size
from policy import DerivationPath, Parser
from secp256k1lab.util import tagged_hash


H = bytes.fromhex("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
TAG = "WalletPolicy/NUMS/2"


def key_record(key_info: str) -> bytes:
    """Return the commitment record, excluding origin and extended-key metadata."""
    public_key, chain_code = parse_xpub(key_info)
    return public_key + chain_code


@dataclass(frozen=True)
class PreparedPolicy:
    """Validated internal derivation path and sorted, unique commitment records."""

    internal_path: DerivationPath
    records: tuple[bytes, ...]


def prepare_policy(template: str, keys_info: list[str]) -> PreparedPolicy:
    """Validate the policy and collect its sorted, unique commitment records."""
    parsed = Parser(template).parse()
    records = set()
    for index in parsed.key_indexes:
        if index >= len(keys_info):
            raise ValueError("Key index out of range")
        records.add(key_record(keys_info[index]))
    return PreparedPolicy(parsed.internal_path, tuple(sorted(records)))


@dataclass(frozen=True)
class SyntheticRoot:
    preimage: bytes
    chain_code: bytes

    def serialize(self, network: str = "mainnet") -> str:
        if network not in VERSIONS:
            raise ValueError("Network must be mainnet or testnet")
        return base58check_encode(VERSIONS[network] + bytes(9) + self.chain_code + H)


def construct_root(policy: PreparedPolicy) -> SyntheticRoot:
    preimage = compact_size(len(policy.records)) + b"".join(policy.records)
    return SyntheticRoot(preimage, tagged_hash(TAG, preimage))


def selected_path(policy: PreparedPolicy, expansion: int, index: int) -> tuple[int, ...]:
    count = next((len(step) for step in policy.internal_path if isinstance(step, tuple)), 1)
    if type(expansion) is not int or not 0 <= expansion < count:
        raise ValueError("Expansion out of range")
    if type(index) is not int or not 0 <= index < 2**31:
        raise ValueError("Wildcard index out of range")
    path = []
    for step in policy.internal_path:
        if step is None:
            path.append(index)
        elif isinstance(step, tuple):
            path.append(step[expansion])
        else:
            path.append(step)
    return tuple(path)


def derive_internal_key(policy: PreparedPolicy, expansion: int, index: int) -> bytes:
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
    policy = prepare_policy(template, keys_info)
    root = construct_root(policy).serialize(network)
    assigned = {}

    def reindex(match):
        i = int(match[1])
        if i not in assigned:
            assigned[i] = len(assigned) + 1
        return "@" + str(assigned[i])

    exported_template = re.sub(r"@([0-9]+)", reindex, template)
    # Parsing has established that the first underscore is the internal key.
    exported_template = exported_template.replace("_", "@0", 1)
    order = list(assigned) + [i for i in range(len(keys_info)) if i not in assigned]
    exported_keys = (root,) + tuple(keys_info[i] for i in order)
    descriptor = re.sub(r"@([0-9]+)", lambda m: exported_keys[int(m[1])], exported_template)
    return ExportedPolicy(exported_template, exported_keys, descriptor.replace("/**", "/<0;1>/*"))
