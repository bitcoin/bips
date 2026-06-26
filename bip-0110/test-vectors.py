#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate and verify BIP-110 (REDUCED_DATA) consensus test vectors.

For each BIP-110 rule this test constructs a transaction (or output) that
exercises the rule's boundary, submits it inside a block to a regtest node
that is enforcing REDUCED_DATA, and asserts the node accepts/rejects it as
the BIP specifies. Verified cases are written to a portable JSON file so the
exact same vectors can be replayed against any other implementation.

Coverage:
  Rule 1: output scriptPubKey size (<=34, or OP_RETURN <=83)   [per-output]
  Rule 2: push / script-argument witness item size (<=256)
  Rule 3: spending undefined witness / Tapleaf versions
  Rule 4: Taproot annex
  Rule 5: Taproot control block size (<=257)
  Rule 6: OP_SUCCESS* in tapscript
  Rule 7: OP_IF / OP_NOTIF in tapscript
  Grandfathering: inputs spending pre-activation UTXOs are exempt from the
                  per-input script rules (2-7); the per-output rule (1) still
                  applies to outputs created while active.

This is a Bitcoin Core / Knots functional test; it needs the test framework and
a built bitcoind, so it is not run from the bips repository. To regenerate and
verify test-vectors.json against the reference implementation:

  1. Check out the reference implementation
     (https://github.com/dathonohm/bitcoin, branch uasf-modified-bip9) and copy
     this file into its test/functional/ directory.
  2. Configure and build (this also symlinks the test into the build tree):
       cmake -B build && cmake --build build -j"$(nproc)"
  3. Run it from the build tree (which auto-discovers the test config):
       TEST_VECTOR_OUT=/path/to/test-vectors.json python3 build/test/functional/test-vectors.py

The generator is deterministic, so a successful run reproduces test-vectors.json
byte-for-byte while re-verifying every case against the node.
"""

import json
import os
from io import BytesIO

from test_framework.blocktools import (
    COINBASE_MATURITY,
    create_block,
    create_coinbase,
    add_witness_commitment,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import (
    CScript,
    OP_1,
    OP_2,
    OP_DROP,
    OP_ENDIF,
    OP_IF,
    OP_RETURN,
    OP_TRUE,
    taproot_construct,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.key import generate_privkey, compute_xonly_pubkey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

from test_framework.wallet import MiniWallet, MiniWalletMode

REDUCED_DATA_BIT = 4
VERSIONBITS_TOP_BITS = 0x20000000
ACTIVATION_HEIGHT = 432  # with min_activation_height=288 (period 3 start)

FEE = 1000
FUND_AMOUNT = 100000


def block_hash(block):
    """Block hash hex, portable across test-framework versions."""
    h = getattr(block, 'hash_hex', None)
    return h if h is not None else block.hash


def normalize_reject(res):
    """Make the rejection reason implementation-agnostic.

    A REDUCED_DATA script-verification failure is reported as
    "mandatory-script-verify-flag-failed (...)" by Bitcoin Knots and as
    "block-script-verify-flag-failed (...)" by the Bitcoin Core port; the
    parenthetical detail is identical. Canonicalize the differing prefix so the
    vectors reproduce identically against either implementation.
    """
    if res is None:
        return None
    for prefix in ("mandatory-script-verify-flag-failed",
                   "block-script-verify-flag-failed"):
        if res.startswith(prefix):
            return "script-verify-flag-failed" + res[len(prefix):]
    return res


def cb(version, info, leaf):
    """Control block for a taproot leaf."""
    return bytes([leaf.version + info.negflag]) + info.internal_pubkey + leaf.merklebranch


def deepen(item, depth):
    """Wrap a taproot tree item under `depth` fictitious partner branches so the
    target leaf ends up at the given Merkle depth (control block = 33 + 32*depth)."""
    node = item
    for i in range(depth):
        partner = bytes([0x80 + i]) * 32
        node = [node, (lambda h, p=partner: p)]
    return node


class ReducedDataTestVectors(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        # start=0, timeout=never, min_activation_height=288, max disabled, active_duration permanent
        self.extra_args = [[
            '-vbparams=reduced_data:0:999999999999:288:2147483647:2147483647',
            '-acceptnonstdtxn=1',
        ]]

    # ---- block helpers -------------------------------------------------------

    def tip_block(self, txs, signal=False):
        node = self.nodes[0]
        tip = node.getbestblockhash()
        height = node.getblockcount() + 1
        block_time = node.getblockheader(tip)['time'] + 1
        block = create_block(int(tip, 16), create_coinbase(height), ntime=block_time, txlist=txs)
        if signal:
            block.nVersion = VERSIONBITS_TOP_BITS | (1 << REDUCED_DATA_BIT)
        add_witness_commitment(block)
        block.solve()
        return block

    def mine(self, count, signal=False):
        node = self.nodes[0]
        for _ in range(count):
            block = self.tip_block([], signal=signal)
            res = node.submitblock(block.serialize().hex())
            assert res is None, f"submitblock failed: {res}"
            assert_equal(node.getbestblockhash(), block_hash(block))

    def rd_status(self):
        return self.nodes[0].getdeploymentinfo()['deployments']['reduced_data']['bip9']

    def activate(self):
        # Mine until ACTIVE, signaling on every block while STARTED so the
        # threshold is met. Activation height is captured dynamically.
        node = self.nodes[0]
        while True:
            info = self.rd_status()
            if info['status'] == 'active':
                break
            self.mine(1, signal=(info['status'] == 'started'))
        self.activation_height = self.rd_status()['since']
        assert node.getblockcount() >= self.activation_height
        self.log.info(f"REDUCED_DATA active since height {self.activation_height}")

    # ---- funding -------------------------------------------------------------

    def fund(self, spk):
        """Create and confirm an output paying `spk`; return (COutPoint, amount, height)."""
        node = self.nodes[0]
        sent = self.wallet.send_to(from_node=node, scriptPubKey=spk, amount=FUND_AMOUNT)
        self.generate(self.wallet, 1)
        txid_int = int(sent['txid'], 16)
        return COutPoint(txid_int, sent['sent_vout']), FUND_AMOUNT, node.getblockcount()

    def spend(self, outpoint, amount, witness_stack, outputs=None, scriptsig=b''):
        tx = CTransaction()
        tx.vin = [CTxIn(outpoint, scriptsig)]
        if outputs is None:
            outputs = [CTxOut(amount - FEE, CScript([OP_TRUE]))]
        tx.vout = outputs
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return tx

    # ---- vector recording ----------------------------------------------------

    def check(self, rule, name, description, spent, tx, expect_valid, spent_age):
        """Submit `tx` in a block, assert accept/reject, record the vector.

        The transaction is validated through the node using its real funding
        outpoint, then the recorded copy has its input(s) rewritten to a
        deterministic synthetic outpoint so the vector is self-contained and
        reproducible. None of these spends carry signatures committing to the
        prevout, so the rewrite does not change script validity.
        """
        node = self.nodes[0]
        block = self.tip_block([tx], signal=False)
        res = node.submitblock(block.serialize().hex())
        accepted = res is None
        if expect_valid:
            assert accepted, f"[{name}] expected VALID, node rejected: {res}"
            assert_equal(node.getbestblockhash(), block_hash(block))
        else:
            assert not accepted, f"[{name}] expected INVALID, node accepted"
        self.log.info(f"  rule {rule} [{name}] -> {'valid' if accepted else 'invalid'} "
                      f"({'reject: ' + str(res) if res else 'accepted'})")

        # Rewrite to synthetic, deterministic outpoints for the recorded vector.
        spent_outputs = []
        for j, (spk, amount) in enumerate(spent):
            self._outpoint_counter += 1
            synth = self._outpoint_counter
            tx.vin[j].prevout = COutPoint(synth, 0)
            spent_outputs.append({
                "prevout": {"txid": "%064x" % synth, "vout": 0},
                "scriptPubKey": spk.hex(),
                "amount": amount,
            })
        self.vectors.append({
            "rule": rule,
            "name": name,
            "description": description,
            "reduced_data_active": True,
            "spent_utxo": spent_age,
            "spent_outputs": spent_outputs,
            "tx": tx.serialize().hex(),
            "expected": "valid" if expect_valid else "invalid",
            "reject_reason": normalize_reject(res),
        })
        return accepted

    # ---- the test ------------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]
        self.vectors = []
        self._outpoint_counter = 0x1100000000000000000000000000000000000000000000000000000000000000
        self.wallet = MiniWallet(node, mode=MiniWalletMode.RAW_OP_TRUE)

        self.generate(self.wallet, COINBASE_MATURITY)

        # Fixed internal key for taproot constructions (deterministic vectors)
        sec = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
        pub = compute_xonly_pubkey(sec)[0]

        # P2WSH(OP_TRUE) anyone-can-spend, used for output-size (rule 1) cases
        wsh_true = CScript([OP_TRUE])
        wsh_true_spk = script_to_p2wsh_script(wsh_true)
        # P2WSH(OP_DROP OP_TRUE) lets us inject an arbitrary witness data element (rule 2)
        wsh_drop = CScript([OP_DROP, OP_TRUE])
        wsh_drop_spk = script_to_p2wsh_script(wsh_drop)

        # Fund "old" UTXOs BEFORE activation so they are grandfathered (exempt
        # from the per-input script rules). Done first, at a low height.
        self.log.info("Funding pre-activation (grandfathered) UTXOs...")
        old_drop_o, old_drop_a, old_drop_h = self.fund(wsh_drop_spk)
        old_true_o, old_true_a, old_true_h = self.fund(wsh_true_spk)

        self.log.info("Activating REDUCED_DATA...")
        self.activate()
        assert old_drop_h < self.activation_height
        assert old_true_h < self.activation_height
        self.generate(self.wallet, 20)  # spendable coins for funding "new" UTXOs

        self.log.info("=== Rule 1: output scriptPubKey size (per-output) ===")
        # boundary-valid: P2WSH (34 bytes) and 83-byte OP_RETURN
        op = self.fund(wsh_true_spk)[0:2]; o, a = op
        self.check(1, "spk_p2wsh_34_valid", "Create a 34-byte P2WSH output (boundary)",
                   [(wsh_true_spk, a)], self.spend(o, a, [bytes(wsh_true)],
                   outputs=[CTxOut(a - FEE, wsh_true_spk)]), True, "post-activation")
        o, a = self.fund(wsh_true_spk)[0:2]
        opret83 = bytes([OP_RETURN, 0x4c, 0x50]) + b'\x00' * 80
        self.check(1, "opreturn_83_valid", "Create an 83-byte OP_RETURN output (boundary)",
                   [(wsh_true_spk, a)], self.spend(o, a, [bytes(wsh_true)],
                   outputs=[CTxOut(a - FEE, CScript(opret83))]), True, "post-activation")
        # invalid: 35-byte non-OP_RETURN spk, and 84-byte OP_RETURN
        o, a = self.fund(wsh_true_spk)[0:2]
        spk35 = CScript(bytes([OP_1]) + b'\x00' * 34)
        self.check(1, "spk_35_nonopreturn_invalid", "Create a 35-byte non-OP_RETURN output (>34)",
                   [(wsh_true_spk, a)], self.spend(o, a, [bytes(wsh_true)],
                   outputs=[CTxOut(a - FEE, spk35)]), False, "post-activation")
        o, a = self.fund(wsh_true_spk)[0:2]
        opret84 = bytes([OP_RETURN, 0x4c, 0x51]) + b'\x00' * 81
        self.check(1, "opreturn_84_invalid", "Create an 84-byte OP_RETURN output (>83)",
                   [(wsh_true_spk, a)], self.spend(o, a, [bytes(wsh_true)],
                   outputs=[CTxOut(a - FEE, CScript(opret84))]), False, "post-activation")

        self.log.info("=== Rule 2: script-argument witness item size ===")
        o, a = self.fund(wsh_drop_spk)[0:2]
        self.check(2, "witness_item_256_valid", "Spend with a 256-byte witness item (boundary)",
                   [(wsh_drop_spk, a)], self.spend(o, a, [b'\x42' * 256, bytes(wsh_drop)]),
                   True, "post-activation")
        o, a = self.fund(wsh_drop_spk)[0:2]
        self.check(2, "witness_item_257_invalid", "Spend with a 257-byte witness item (>256)",
                   [(wsh_drop_spk, a)], self.spend(o, a, [b'\x42' * 257, bytes(wsh_drop)]),
                   False, "post-activation")

        self.log.info("=== Rule 3: undefined witness / Tapleaf versions ===")
        # Undefined witness version v2 (OP_2 <32 bytes>): spending is invalid.
        wv2_spk = CScript([OP_2, b'\x42' * 32])
        o, a = self.fund(wv2_spk)[0:2]
        self.check(3, "spend_witness_v2_invalid", "Spend an undefined witness v2 output",
                   [(wv2_spk, a)], self.spend(o, a, [b'']), False, "post-activation")
        # Undefined Tapleaf version (0xc2): spending that leaf is invalid.
        leafv = (b'\x51', 0xc2)  # (code=OP_1, version=0xc2)
        infov = taproot_construct(pub, [("u", leafv[0], leafv[1])])
        o, a = self.fund(infov.scriptPubKey)[0:2]
        lv = infov.leaves["u"]
        self.check(3, "spend_tapleaf_v0xc2_invalid", "Spend an undefined (0xc2) Tapleaf version",
                   [(bytes(infov.scriptPubKey), a)],
                   self.spend(o, a, [lv.script, cb(0xc2, infov, lv)]), False, "post-activation")

        self.log.info("=== Rule 4: Taproot annex ===")
        info1 = taproot_construct(pub, [("ok", CScript([OP_1]))])
        o, a = self.fund(info1.scriptPubKey)[0:2]
        leaf = info1.leaves["ok"]
        annex = bytes([0x50]) + b'\x00' * 10
        self.check(4, "taproot_annex_invalid", "Spend a taproot script path with an annex",
                   [(bytes(info1.scriptPubKey), a)],
                   self.spend(o, a, [leaf.script, cb(0xc0, info1, leaf), annex]),
                   False, "post-activation")

        self.log.info("=== Rule 5: Taproot control block size ===")
        info7 = taproot_construct(pub, [deepen(("d7", CScript([OP_1])), 7)])
        o, a = self.fund(info7.scriptPubKey)[0:2]
        l7 = info7.leaves["d7"]
        assert_equal(len(cb(0xc0, info7, l7)), 257)
        self.check(5, "control_block_257_valid", "Spend a leaf at depth 7 (257-byte control block, boundary)",
                   [(bytes(info7.scriptPubKey), a)],
                   self.spend(o, a, [l7.script, cb(0xc0, info7, l7)]), True, "post-activation")
        info8 = taproot_construct(pub, [deepen(("d8", CScript([OP_1])), 8)])
        o, a = self.fund(info8.scriptPubKey)[0:2]
        l8 = info8.leaves["d8"]
        assert_equal(len(cb(0xc0, info8, l8)), 289)
        self.check(5, "control_block_289_invalid", "Spend a leaf at depth 8 (289-byte control block, >257)",
                   [(bytes(info8.scriptPubKey), a)],
                   self.spend(o, a, [l8.script, cb(0xc0, info8, l8)]), False, "post-activation")

        self.log.info("=== Rule 6: OP_SUCCESS* in tapscript ===")
        info_os = taproot_construct(pub, [("os", bytes([0xfe]))])  # OP_SUCCESS254
        o, a = self.fund(info_os.scriptPubKey)[0:2]
        los = info_os.leaves["os"]
        self.check(6, "op_success_invalid", "Spend a tapscript containing OP_SUCCESS254 (0xfe)",
                   [(bytes(info_os.scriptPubKey), a)],
                   self.spend(o, a, [los.script, cb(0xc0, info_os, los)]), False, "post-activation")

        self.log.info("=== Rule 7: OP_IF / OP_NOTIF in tapscript ===")
        if_leaf = CScript([OP_1, OP_IF, OP_1, OP_ENDIF])
        info_if = taproot_construct(pub, [("if", if_leaf)])
        o, a = self.fund(info_if.scriptPubKey)[0:2]
        lif = info_if.leaves["if"]
        self.check(7, "tapscript_op_if_invalid", "Spend a tapscript executing OP_IF",
                   [(bytes(info_if.scriptPubKey), a)],
                   self.spend(o, a, [lif.script, cb(0xc0, info_if, lif)]), False, "post-activation")
        # contrast: OP_IF in a witness v0 (non-tapscript) script is unaffected
        wsh_if = CScript([OP_1, OP_IF, OP_1, OP_ENDIF])
        wsh_if_spk = script_to_p2wsh_script(wsh_if)
        o, a = self.fund(wsh_if_spk)[0:2]
        self.check(7, "witness_v0_op_if_valid", "OP_IF in a witness v0 script is valid (rule is tapscript-only)",
                   [(wsh_if_spk, a)], self.spend(o, a, [bytes(wsh_if)]), True, "post-activation")

        self.log.info("=== Grandfathering: pre-activation UTXOs ===")
        # An input spending a pre-activation UTXO is exempt from the per-input
        # script rules: a 257-byte witness item is accepted here (cf. rule 2).
        self.check(2, "grandfathered_witness_item_257_valid",
                   "Spend a PRE-activation UTXO with a 257-byte witness item (grandfathered, exempt)",
                   [(wsh_drop_spk, old_drop_a)],
                   self.spend(old_drop_o, old_drop_a, [b'\x42' * 257, bytes(wsh_drop)]),
                   True, "pre-activation")
        # But the per-output rule 1 still applies even when spending an old UTXO:
        # creating an oversized output is rejected regardless of input age.
        self.check(1, "grandfathered_input_oversized_output_invalid",
                   "Spend a PRE-activation UTXO but create a 35-byte output (rule 1 not grandfathered)",
                   [(wsh_true_spk, old_true_a)],
                   self.spend(old_true_o, old_true_a, [bytes(wsh_true)],
                              outputs=[CTxOut(old_true_a - FEE, CScript(bytes([OP_1]) + b'\x00' * 34))]),
                   False, "pre-activation")

        self.write_vectors()

    def write_vectors(self):
        out = os.environ.get("TEST_VECTOR_OUT")
        if not out:
            self.log.info("TEST_VECTOR_OUT not set; not writing vector file")
            return
        doc = {
            "comment": ("BIP-110 (REDUCED_DATA) consensus test vectors, generated and "
                        "verified against the reference implementation. Each vector gives the "
                        "spent output(s), the spending/creating transaction, and whether a block "
                        "containing it is valid while REDUCED_DATA is active. 'rule' refers to the "
                        "numbered rules in the BIP Specification. Hex values are byte arrays. "
                        "'reject_reason' is informational and normalized to be implementation-agnostic."),
            "vectors": self.vectors,
        }
        with open(out, "w") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
        self.log.info(f"Wrote {len(self.vectors)} vectors to {out}")


if __name__ == '__main__':
    ReducedDataTestVectors(__file__).main()
