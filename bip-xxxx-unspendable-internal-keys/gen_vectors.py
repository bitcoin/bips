#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Print deterministic candidate vectors. Review before replacing vectors.json."""

import json
from bip32 import VERSIONS
from encoding import base58check_decode, base58check_encode
import reference as ref


# Public keys from BIP 32 test vectors 1 and 2; no private keys are needed.
A = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
B = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
C = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"


def changed_xpub(xpub, *, network=None, metadata=None, chain_code=None, public_key=None):
    data = bytearray(base58check_decode(xpub))
    if network is not None:
        data[:4] = VERSIONS[network]
    if metadata is not None:
        data[4:13] = metadata
    if chain_code is not None:
        data[13:45] = chain_code
    if public_key is not None:
        data[45:] = public_key
    return base58check_encode(bytes(data))


def valid_case(name, template, keys_info, selections=((0, 0), (0, 1)), network="mainnet"):
    policy = ref.normalize_policy(template, keys_info)
    root = ref.construct_root(policy)
    export = ref.export_policy(template, keys_info, network)
    return {
        "name": name,
        "given": {"template": template, "keys_info": keys_info, "network": network,
                  "selections": [{"expansion": b, "index": i} for b, i in selections]},
        "intermediary": {
            "normalized_template": policy.template,
            "records": [r.hex() for r in policy.records],
            "preimage": root.preimage.hex(),
            "chain_code": root.chain_code.hex(),
        },
        "expected": {
            "synthetic_xpub": root.serialize(network),
            "derivations": [{"path": list(ref.selected_path(policy, b, i)),
                             "internal_key": ref.derive_internal_key(policy, b, i).hex()}
                            for b, i in selections],
            "export": {"template": export.template, "keys_info": list(export.keys_info),
                       "descriptor": export.descriptor},
        },
    }


def generate():
    cases = []

    def add(*args, **kwargs):
        cases.append(valid_case(*args, **kwargs))

    add("single", "tr(_/**,pk(@0/**))", [A], ((0, 0), (1, 0), (0, 2**31 - 1)))
    add("single-expanded", "tr(_/<0;1>/*,c:pk_k(@0/<0;1>/*))", [A])
    add("single-unused", "tr(_/**,pk(@1/**))", [B, A, C])
    add("single-origin", "tr(_/**,pk(@0/**))", ["[1234ABCD/44h/0'/000]" + A])
    add("single-metadata", "tr(_/**,pk(@0/**))", [changed_xpub(A, metadata=bytes.fromhex("037856341200000009"))])
    add("single-testnet", "tr(_/**,pk(@0/**))", [changed_xpub(A, network="testnet")], network="testnet")
    add("single-chain-code", "tr(_/**,pk(@0/**))", [changed_xpub(A, chain_code=bytes(32))])
    add("single-path", "tr(_/**,pk(@0/7/**))", [A])
    add("single-fixed", "tr(_/**,pk(@0))", [A])
    add("single-no-multipath", "tr(_/*,pk(@0/*))", [A])
    add("four-expansions", "tr(_/12/<0;1;2;3>/5/*,pk(@0/<4;5;6;7>/*))", [A], ((0, 0), (1, 0), (3, 17)))
    add("four-expansions-reordered", "tr(_/12/<0;1;2;3>/5/*,pk(@0/<5;4;6;7>/*))", [A])
    add("sorted", "tr(_/**,sortedmulti_a(2,@0/**,@1/**,@2/**))", [A, B, C])
    add("sorted-permuted", "tr(_/**,sortedmulti_a(2,@1/**,@0/**,@2/**))", [C, B, A])
    add("sorted-threshold", "tr(_/**,sortedmulti_a(1,@0/**,@1/**,@2/**))", [A, B, C])
    add("ordered", "tr(_/**,multi_a(2,@0/**,@1/**,@2/**))", [A, B, C])
    add("ordered-reversed", "tr(_/**,multi_a(2,@2/**,@1/**,@0/**))", [A, B, C])
    add("musig", "tr(_/**,pk(musig(@0,@1,@2)/**))", [A, B, C])
    add("musig-permuted", "tr(_/**,pk(musig(@2,@0,@1)/**))", [C, A, B])
    add("musig-repeated", "tr(_/**,pk(musig(@0,@1,@0)/**))", [A, B])
    add("musig-duplicate-record", "tr(_/**,pk(musig(@2,@1,@0)/**))", [A, B, A])
    add("musig-without-repeat", "tr(_/**,pk(musig(@0,@1)/**))", [A, B])
    same_key = changed_xpub(A, chain_code=bytes(32))
    add("musig-same-point", "tr(_/**,pk(musig(@0,@1)/**))", [A, same_key])
    add("musig-same-point-reversed", "tr(_/**,pk(musig(@1,@0)/**))", [A, same_key])
    add("tree", "tr(_/**,{pk(@0/**),{pk(@1/**),pk(@2/**)}})", [A, B, C])
    add("tree-swapped", "tr(_/**,{{pk(@2/**),pk(@1/**)},pk(@0/**)})", [A, B, C])
    add("tree-reshaped", "tr(_/**,{{pk(@0/**),pk(@1/**)},pk(@2/**)})", [A, B, C])
    add("tree-repeated", "tr(_/**,{pk(@0/**),pk(@0/**)})", [A])
    add("tree-duplicate-record", "tr(_/**,{pk(@0/**),pk(@1/**)})", [A, A])
    add("timelock", "tr(_/**,and_v(v:pk(@0/**),older(144)))", [A])
    add("timelock-changed", "tr(_/**,and_v(v:pk(@0/**),older(145)))", [A])
    add("sugar", "tr(_/**,and_n(pk(@0/**),tv:pkh(@1/**)))", [A, B])
    add("sugar-expanded", "tr(_/**,andor(c:pk_k(@0/**),and_v(vc:pk_h(@1/**),1),0))", [A, B])
    add("zero-records", "tr(_/*,older(144))", [], ((0, 0), (0, 1), (0, 2)))
    add("false", "tr(_/**,0)", [])
    add("true", "tr(_/**,1)", [])
    add("l-zero", "tr(_/**,l:0)", [])
    add("u-zero", "tr(_/**,u:0)", [])
    add("or-zero", "tr(_/**,or_i(0,0))", [])
    add("numeric-spelling", "tr(_/000/*,after(000144))", [])
    add("numeric-canonical", "tr(_/0/*,after(144))", [])
    add("hashlock", "tr(_/**,and_v(v:pk(@0/**),sha256(" + "AB" * 32 + ")))", [A])
    add("hashlock-lower", "tr(_/**,and_v(v:pk(@0/**),sha256(" + "ab" * 32 + ")))", [A])
    add("hashlock-changed", "tr(_/**,and_v(v:pk(@0/**),sha256(" + "ac" * 32 + ")))", [A])
    add("sorted-expressions", "tr(_/**,sortedmulti_a(1,musig(@1,@0)/**,@0/9/**,@0/**))", [A, B])
    # These exercise syntax only; construction acceptance is not a safety check.
    add("fragments", "tr(_/**,{thresh(2,pk(@0/**),s:pk(@1/**),a:pk(@2/**)),or_d(pk(@0/**),or_b(pk(@1/**),s:pk(@2/**)))})", [A, B, C])
    add("wrappers", "tr(_/**,and_b(ndv:after(5),a:or_i(j:pk(@0/**),u:pk(@1/**))))", [A, B])
    add("or-c", "tr(_/**,t:or_c(pk(@0/**),v:pk(@1/**)))", [A, B])
    add("hash-fragments", "tr(_/**,{hash256(" + "12" * 32 + "),{ripemd160(" + "34" * 20 + "),hash160(" + "56" * 20 + ")}})", [])
    add("hardened-leaf-syntax", "tr(_/**,pk(@0/1h/<2';3h>/*'))", [A])
    add("index-ten", "tr(_/**,multi_a(1,@1/**,@10/**))", [A, B] + [C] * 9)

    equivalent = [
        ["single", "single-expanded", "single-unused", "single-origin", "single-metadata", "single-testnet"],
        ["sorted", "sorted-permuted"], ["musig", "musig-permuted"],
        ["musig-repeated", "musig-duplicate-record"], ["musig-same-point", "musig-same-point-reversed"],
        ["tree", "tree-swapped"], ["tree-repeated", "tree-duplicate-record"],
        ["sugar", "sugar-expanded"], ["l-zero", "u-zero", "or-zero"],
        ["numeric-spelling", "numeric-canonical"], ["hashlock", "hashlock-lower"],
    ]
    distinct = [
        ["single", "single-chain-code"], ["single", "single-path"], ["single", "single-fixed"],
        ["single", "single-no-multipath"], ["four-expansions", "four-expansions-reordered"],
        ["sorted", "sorted-threshold"], ["ordered", "ordered-reversed"], ["ordered", "sorted"],
        ["musig-repeated", "musig-without-repeat"], ["tree", "tree-reshaped"],
        ["single", "tree-repeated"], ["timelock", "timelock-changed"], ["hashlock", "hashlock-changed"],
    ]
    invalid = []
    malformed = {
        "missing-tree": "tr(_/**)",
        "missing-internal-wildcard": "tr(_,pk(@0))",
        "internal-hardened": "tr(_/1h/*,pk(@0/*))",
        "internal-hardened-wildcard": "tr(_/*h,pk(@0/*))",
        "internal-hardened-tuple": "tr(_/<0;1h>/*,pk(@0/**))",
        "internal-tuple-missing": "tr(_/*,pk(@0/**))",
        "internal-tuple-nonconsecutive": "tr(_/<1;2>/*,pk(@0/**))",
        "internal-tuple-reversed": "tr(_/<1;0>/*,pk(@0/**))",
        "tuple-length-mismatch": "tr(_/**,pk(@0/<0;1;2>/*))",
        "duplicate-tuple-value": "tr(_/**,pk(@0/<0;0>/*))",
        "duplicate-hardened-value": "tr(_/**,pk(@0/<1h;1'>/*))",
        "multiple-tuples": "tr(_/**,pk(@0/<0;1>/<2;3>/*))",
        "one-tuple-value": "tr(_/*,pk(@0/<0>/*))",
        "step-out-of-range": "tr(_/2147483648/*,pk(@0/*))",
        "wildcard-not-final": "tr(_/*/0,pk(@0/*))",
        "double-star-not-final": "tr(_/**/0,pk(@0/**))",
        "nums-in-leaf": "tr(_/**,pk(_/**))",
        "literal-key": "tr(_/**,pk(" + A + "/**))",
        "unknown-fragment": "tr(_/**,raw(51))",
        "p2wsh-fragment": "tr(_/**,multi(1,@0/**))",
        "wrong-arity": "tr(_/**,and_v(pk(@0/**)))",
        "sortedmulti-nested": "tr(_/**,and_v(v:pk(@0/**),sortedmulti_a(1,@0/**)))",
        "sortedmulti-wrapped": "tr(_/**,v:sortedmulti_a(1,@0/**))",
        "nested-musig": "tr(_/**,pk(musig(@0,musig(@0,@1))/**))",
        "musig-participant-path": "tr(_/**,pk(musig(@0/0,@1)/**))",
        "empty-musig": "tr(_/**,pk(musig()/**))",
        "missing-reference": "tr(_/**,pk(@3/**))",
        "leading-zero-index": "tr(_/**,pk(@00/**))",
        "negative-number": "tr(_/**,older(-1))",
        "short-hash": "tr(_/**,sha256(ab))",
        "bad-wrapper": "tr(_/**,z:pk(@0/**))",
        "unbalanced-tree": "tr(_/**,{pk(@0/**),pk(@1/**)})x",
        "trailing-data": "tr(_/**,pk(@0/**))junk",
        "checksum-on-template": "tr(_/**,pk(@0/**))#12345678",
        "whitespace": "tr(_/**, pk(@0/**))",
        "unicode": "tr(_/**,older(１４４))",
    }
    for name, template in malformed.items():
        invalid.append({"name": name, "given": {"template": template, "keys_info": [A, B]},
                        "error_stage": "normalize"})
    bad_keys = {
        "bad-checksum": A[:-1] + ("1" if A[-1] != "1" else "2"),
        "bad-origin": "[xyz]" + A,
        "origin-out-of-range": "[12345678/2147483648]" + A,
        "xpub-trailing-path": A + "/0",
        "invalid-point": changed_xpub(A, public_key=b"\x02" + (7).to_bytes(32, "big")),
        "invalid-prefix": changed_xpub(A, public_key=b"\x04" + ref.H[1:]),
        "depth-zero-metadata": changed_xpub(A, metadata=bytes.fromhex("000000000100000000")),
        "unknown-version": base58check_encode(bytes(4) + base58check_decode(A)[4:]),
        "wrong-payload-length": base58check_encode(base58check_decode(A)[:-1]),
        "private-version": base58check_encode(bytes.fromhex("0488ade4") + base58check_decode(A)[4:]),
    }
    for name, value in bad_keys.items():
        invalid.append({"name": name, "given": {"template": "tr(_/**,pk(@0/**))", "keys_info": [value]},
                        "error_stage": "normalize"})
    for name, expansion, index in (("negative-expansion", -1, 0), ("large-expansion", 2, 0),
                                   ("negative-index", 0, -1), ("hardened-index", 0, 2**31)):
        invalid.append({"name": name, "given": {"template": "tr(_/**,pk(@0/**))", "keys_info": [A],
                                                  "expansion": expansion, "index": index}, "error_stage": "derive"})
    return {"version": 1, "valid": cases, "equivalent": equivalent, "distinct": distinct, "invalid": invalid}


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2))
