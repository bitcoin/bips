#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Offline tests. Expected results are read from disk, never regenerated."""

import hashlib
import itertools
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import bip32
from encoding import base58check_decode, base58check_encode, compact_size
import reference as ref
from secp256k1lab.secp256k1 import FE, G, GE


HERE = Path(__file__).resolve().parent


class ConstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads((HERE / "vectors.json").read_text())
        cls.cases = {case["name"]: case for case in cls.vectors["valid"]}

    def test_fixed_vectors(self):
        self.assertEqual(self.vectors["version"], 1)
        for case in self.vectors["valid"]:
            with self.subTest(case=case["name"]):
                given, middle, expected = case["given"], case["intermediary"], case["expected"]
                policy = ref.normalize_policy(given["template"], given["keys_info"])
                self.assertEqual(policy.template, middle["normalized_template"])
                self.assertEqual([r.hex() for r in policy.records], middle["records"])
                root = ref.construct_root(policy)
                self.assertEqual(root.preimage.hex(), middle["preimage"])
                self.assertEqual(root.chain_code.hex(), middle["chain_code"])
                self.assertEqual(root.serialize(given["network"]), expected["synthetic_xpub"])
                self.assertEqual(len(expected["derivations"]), len(given["selections"]))
                for selection, derived in zip(given["selections"], expected["derivations"]):
                    branch, index = selection["expansion"], selection["index"]
                    self.assertEqual(list(ref.selected_path(policy, branch, index)), derived["path"])
                    self.assertEqual(ref.derive_internal_key(policy, branch, index).hex(), derived["internal_key"])
                exported = ref.export_policy(given["template"], given["keys_info"], given["network"])
                self.assertEqual(exported.template, expected["export"]["template"])
                self.assertEqual(list(exported.keys_info), expected["export"]["keys_info"])
                self.assertEqual(exported.descriptor, expected["export"]["descriptor"])

    def commitment(self, name):
        given = self.cases[name]["given"]
        return ref.construct_root(ref.normalize_policy(given["template"], given["keys_info"])).chain_code

    def test_equivalences_and_distinctions(self):
        for group in self.vectors["equivalent"]:
            with self.subTest(equivalent=group):
                self.assertEqual(len({self.commitment(name) for name in group}), 1)
        for left, right in self.vectors["distinct"]:
            with self.subTest(distinct=(left, right)):
                self.assertNotEqual(self.commitment(left), self.commitment(right))

    def test_invalid_vectors(self):
        for case in self.vectors["invalid"]:
            with self.subTest(case=case["name"]):
                given = case["given"]
                if case["error_stage"] == "normalize":
                    with self.assertRaises(ValueError):
                        ref.normalize_policy(given["template"], given["keys_info"])
                else:
                    self.assertEqual(case["error_stage"], "derive")
                    policy = ref.normalize_policy(given["template"], given["keys_info"])
                    with self.assertRaises(ValueError):
                        ref.derive_internal_key(policy, given["expansion"], given["index"])

    def test_recorded_core_results_match_vectors(self):
        report = json.loads((HERE / "core-checks.json").read_text())
        self.assertEqual(report["network"], "regtest")
        self.assertTrue(report["core_version"])
        self.assertTrue(report["checks"])
        for check in report["checks"]:
            with self.subTest(case=check["name"], index=check["index"]):
                case = self.cases[check["name"]]
                selection = {"expansion": check["expansion"], "index": check["index"]}
                position = case["given"]["selections"].index(selection)
                self.assertEqual(check["internal_key"], case["expected"]["derivations"][position]["internal_key"])
                self.assertTrue(check["addresses"])

    def test_normalization_idempotence(self):
        for case in self.vectors["valid"]:
            with self.subTest(case=case["name"]):
                given = case["given"]
                first = ref.normalize_policy(given["template"], given["keys_info"])
                keys_info = [base58check_encode(bip32.VERSIONS["mainnet"] + bytes(9) + r[33:] + r[:33])
                             for r in first.records]
                self.assertEqual(ref.normalize_policy(first.template, keys_info), first)

    def test_manual_preimages(self):
        # Fixed bytes are independent of the normalizer and vector generator.
        xpub = self.cases["single"]["given"]["keys_info"][0]
        record = bytes.fromhex(
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
        policy = ref.normalize_policy("tr(_/**,pk(@0/**))", [xpub])
        self.assertEqual(policy.records, (record,))
        preimage = b"\x12tr(_/**,pk(@0/**))\x01" + record
        self.assertEqual(ref.construct_root(policy).preimage, preimage)
        tag = hashlib.sha256(b"WalletPolicy/NUMS/1").digest()
        self.assertEqual(ref.construct_root(policy).chain_code, hashlib.sha256(tag + tag + preimage).digest())
        empty = ref.normalize_policy("tr(_/*,older(144))", [])
        self.assertEqual(ref.construct_root(empty).preimage, b"\x12tr(_/*,older(144))\x00")
        self.assertEqual(ref.construct_root(empty).chain_code.hex(),
                         "c827a369333ab24ec0f3668defed7fcb9a5f157b08052d6d098b9148aac7c691")

    def test_all_key_permutations(self):
        original = self.cases["sorted"]["given"]["keys_info"]
        reference = ref.normalize_policy("tr(_/**,sortedmulti_a(2,@0/**,@1/**,@2/**))", original)
        for permutation in itertools.permutations(range(3)):
            keys_info = [original[i] for i in permutation]
            template = "tr(_/**,sortedmulti_a(2," + ",".join(f"@{i}/**" for i in reversed(range(3))) + "))"
            self.assertEqual(ref.normalize_policy(template, keys_info), reference)

    def test_full_records_control_musig_sorting(self):
        given = self.cases["musig-same-point"]["given"]
        records = [ref.key_record(x) for x in given["keys_info"]]
        self.assertEqual(records[0][:33], records[1][:33])
        self.assertNotEqual(records[0][33:], records[1][33:])
        normalized = ref.normalize_policy(given["template"], given["keys_info"])
        self.assertEqual(normalized.records, tuple(sorted(records)))

    def test_export_preserves_input_and_indexes(self):
        given = self.cases["index-ten"]["given"]
        exported = ref.export_policy(given["template"], given["keys_info"])
        self.assertEqual(exported.template, "tr(@11/**,multi_a(1,@1/**,@10/**))")
        self.assertEqual(exported.keys_info[:-1], tuple(given["keys_info"]))
        self.assertEqual(exported.descriptor,
                         f"tr({exported.keys_info[-1]}/<0;1>/*,multi_a(1,"
                         f"{given['keys_info'][1]}/<0;1>/*,{given['keys_info'][10]}/<0;1>/*))")
        original = self.cases["single-origin"]["given"]
        self.assertIn(original["keys_info"][0], ref.export_policy(original["template"], original["keys_info"]).descriptor)

    def test_export_preserves_bip388_public_key_conflicts(self):
        # Check BIP 388's "Additional rules" directly, without a wallet validator.
        first, second = self.cases["musig-same-point"]["given"]["keys_info"]
        template = "tr(_/**,{pk(@0/**),pk(@1/**)})"
        for name, keys_info, record_count in (
                ("different-chain-codes", [first, second], 2),
                ("identical-xpubs", [first, first], 1)):
            with self.subTest(case=name):
                policy = ref.normalize_policy(template, keys_info)
                self.assertEqual(len(policy.records), record_count)
                self.assertEqual(len(ref.derive_internal_key(policy, 0, 0)), 32)
                exported = ref.export_policy(template, keys_info)
                self.assertEqual(exported.template, "tr(@2/**,{pk(@0/**),pk(@1/**)})")
                self.assertEqual(exported.keys_info[:-1], tuple(keys_info))
                parsed = [bip32.parse_xpub(info) for info in exported.keys_info[:-1]]
                # BIP 388 requires distinct public keys, regardless of chain codes.
                self.assertEqual(parsed[0][0], parsed[1][0])
                self.assertEqual(len({chain_code for _, chain_code in parsed}), record_count)

    def test_export_preserves_bip388_repeated_musig_indexes(self):
        given = self.cases["musig-repeated"]["given"]
        policy = ref.normalize_policy(given["template"], given["keys_info"])
        self.assertEqual(len(ref.derive_internal_key(policy, 0, 0)), 32)
        exported = ref.export_policy(given["template"], given["keys_info"])
        self.assertEqual(exported.template, "tr(@2/**,pk(musig(@0,@1,@0)/**))")
        self.assertEqual(exported.keys_info[:-1], tuple(given["keys_info"]))
        tree = ref.Parser(exported.template.split(",", 1)[1][:-1]).tree()
        key, = ref.keys(tree)
        self.assertEqual(key.kind, "musig")
        # BIP 388 forbids repeated key indexes within a musig placeholder.
        self.assertLess(len(set(key.indexes)), len(key.indexes))

    def test_export_preserves_bip388_path_conflicts(self):
        original = self.cases["sorted"]["given"]["keys_info"]
        for tree, key_count, overlap in (
                ("{pk(@0/**),pk(@0/**)}", 1, {"0", "1"}),
                ("{pk(@0/<0;1>/*),pk(@0/<1;2>/*)}", 1, {"1"}),
                ("{pk(musig(@0,@1)/**),pk(musig(@1,@0)/<1;2>/*)}", 2, {"1"})):
            with self.subTest(tree=tree):
                template = f"tr(_/**,{tree})"
                keys_info = original[:key_count]
                policy = ref.normalize_policy(template, keys_info)
                self.assertEqual(len(ref.derive_internal_key(policy, 0, 0)), 32)
                exported = ref.export_policy(template, keys_info)
                self.assertEqual(exported.template, f"tr(@{key_count}/**,{tree})")
                self.assertEqual(exported.keys_info[:-1], tuple(keys_info))
                exported_tree = ref.Parser(exported.template.split(",", 1)[1][:-1]).tree()
                left, right = ref.keys(exported_tree)
                # BIP 388 identifies musig placeholders by their set of indexes.
                self.assertEqual(left.kind, right.kind)
                self.assertEqual(set(left.indexes), set(right.indexes))
                # Alternatives for the same placeholder must be disjoint in BIP 388.
                self.assertEqual(set(left.path[0].values) & set(right.path[0].values), overlap)

    def test_network_only_changes_root_version_and_checksum(self):
        given = self.cases["single"]["given"]
        root = ref.construct_root(ref.normalize_policy(given["template"], given["keys_info"]))
        main = base58check_decode(root.serialize("mainnet"))
        test = base58check_decode(root.serialize("testnet"))
        self.assertEqual(main[4:], test[4:])
        self.assertEqual(main[4:13], bytes(9))
        self.assertEqual(main[45:], ref.H)
        with self.assertRaises(ValueError):
            root.serialize("unknown")

    def test_record_count_compactsize_boundary(self):
        original = base58check_decode(self.cases["single"]["given"]["keys_info"][0])
        for count in (252, 253):
            keys_info = [base58check_encode(original[:13] + i.to_bytes(32, "big") + original[45:])
                         for i in range(count)]
            template = "tr(_/*,multi_a(1," + ",".join(f"@{i}/*" for i in range(count)) + "))"
            policy = ref.normalize_policy(template, keys_info)
            root = ref.construct_root(policy)
            prefix = compact_size(len(policy.template)) + policy.template.encode()
            self.assertTrue(root.preimage.startswith(prefix + (b"\xfc" if count == 252 else b"\xfd\xfd\x00")))

    def test_template_length_compactsize_boundary(self):
        for length in (252, 253):
            # The construction grammar does not impose script resource limits.
            wrappers = "n" * (length - len("tr(_/*,:1)"))
            template = "tr(_/*," + wrappers + ":1)"
            policy = ref.normalize_policy(template, [])
            self.assertEqual(len(policy.template), length)
            expected = b"\xfc" if length == 252 else b"\xfd\xfd\x00"
            self.assertTrue(ref.construct_root(policy).preimage.startswith(expected + policy.template.encode()))

    def test_stops_at_first_invalid_child(self):
        policy = ref.normalize_policy("tr(_/7/8/*,1)", [])
        with patch.object(ref, "ckd_pub", side_effect=ValueError("invalid child")) as ckd:
            with self.assertRaises(ValueError):
                ref.derive_internal_key(policy, 0, 9)
            self.assertEqual(ckd.call_count, 1)
            self.assertEqual(ckd.call_args.args[2], 7)

    def test_no_multipath_has_one_expansion(self):
        policy = ref.normalize_policy("tr(_/*,1)", [])
        with self.assertRaises(ValueError):
            ref.derive_internal_key(policy, 1, 0)

    def test_compressed_parity_is_preserved_between_steps(self):
        given = self.cases["four-expansions"]["given"]
        policy = ref.normalize_policy(given["template"], given["keys_info"])
        public_key, chain_code = ref.H, ref.construct_root(policy).chain_code
        parities = set()
        for index in (12, 3, 5, 17):
            public_key, chain_code = bip32.ckd_pub(public_key, chain_code, index)
            parities.add(public_key[0])
        self.assertEqual(parities, {2, 3})
        expected = self.cases["four-expansions"]["expected"]["derivations"][2]["internal_key"]
        self.assertEqual(public_key[1:].hex(), expected)


class PrimitiveTests(unittest.TestCase):
    def test_nums_point_and_fingerprint(self):
        self.assertEqual(bip32.parse_point(ref.H).to_bytes_compressed(), ref.H)
        fingerprint = hashlib.new("ripemd160", hashlib.sha256(ref.H).digest()).digest()[:4]
        self.assertEqual(fingerprint.hex(), "7c461e5d")

    def test_compactsize(self):
        for value, expected in ((0, "00"), (252, "fc"), (253, "fdfd00"), (65535, "fdffff"),
                                (65536, "fe00000100"), (2**32 - 1, "feffffffff"),
                                (2**32, "ff0000000001000000"), (2**64 - 1, "ffffffffffffffffff")):
            self.assertEqual(compact_size(value).hex(), expected)
        for value in (-1, 2**64, True, 0.0):
            with self.assertRaises(ValueError):
                compact_size(value)

    def test_base58check(self):
        self.assertEqual(base58check_encode(bytes(21)), "1111111111111111111114oLvT2")
        for payload in (b"", b"\0", bytes(21), bytes(range(78))):
            self.assertEqual(base58check_decode(base58check_encode(payload)), payload)
        for text in ("", "1", "0", "O", "l", "1111111111111111111114oLvT3"):
            with self.assertRaises(ValueError):
                base58check_decode(text)

    def test_bip32_public_derivation(self):
        # Published BIP 32 vectors, including multi-level public derivation.
        pairs = [
            ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", [1],
             "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
            ("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", [2, 1000000000],
             "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"),
            ("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB", [0],
             "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"),
        ]
        for parent, path, expected in pairs:
            with self.subTest(path=path):
                record = ref.key_record(parent)
                public_key, chain_code = record[:33], record[33:]
                for index in path:
                    public_key, chain_code = bip32.ckd_pub(public_key, chain_code, index)
                self.assertEqual(public_key + chain_code, ref.key_record(expected))

    def test_invalid_children_and_zero_tweak(self):
        public_key = G.to_bytes_compressed()
        for tweak in (GE.ORDER, 2**256 - 1, GE.ORDER - 1):
            with self.subTest(tweak=tweak):
                with patch.object(bip32.hmac, "digest", return_value=tweak.to_bytes(32, "big") + bytes(32)) as digest:
                    with self.assertRaises(ValueError):
                        bip32.ckd_pub(public_key, bytes(32), 7)
                    self.assertEqual(digest.call_count, 1)
                    self.assertEqual(digest.call_args.args[1][-4:], b"\x00\x00\x00\x07")
        with patch.object(bip32.hmac, "digest", return_value=bytes(32) + b"\x42" * 32):
            self.assertEqual(bip32.ckd_pub(public_key, bytes(32), 7), (public_key, b"\x42" * 32))
        for index in (-1, 2**31, True, 1.0):
            with self.assertRaises(ValueError):
                bip32.ckd_pub(public_key, bytes(32), index)

    def test_invalid_points(self):
        for data in (b"", b"\x04" + bytes(32), b"\x02" + FE.SIZE.to_bytes(32, "big"),
                     b"\x02" + (7).to_bytes(32, "big")):
            with self.assertRaises(ValueError):
                bip32.parse_point(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
