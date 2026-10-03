from tree import Node, print_tree
import secrets

from pathlib import Path
import sys
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent.parent

sys.path.insert(0, str(PROJECT_ROOT))

from reference import *

def key_gen_tree(node: Node):
    if node.is_leaf():
        node.sk = secrets.token_bytes(32)
        node.pk = individual_pk(node.sk)
    else:
        for w in node.children:
            key_gen_tree(w)
        child_pks =  key_sort([w.pk for w in node.children])
        node.keyagg_ctx = key_agg(child_pks)
        node.pk = PlainPk(cbytes(node.keyagg_ctx.Q))


def round1(node: Node, aggpk: XonlyPk = None, msg: bytes = None, extra_in = None):
    if node.is_leaf():
        (secnonce, pubnonce) = nonce_gen(node.sk, node.pk, aggpk, msg, extra_in)
        node.out = pubnonce
        node.state = secnonce
    else:
        for w in node.children:
            round1(w, aggpk, msg, extra_in)
        node.out_internal = nonce_agg([w.out for w in node.children])
        if not node.is_root:
            node.out = nonce_agg_ext(node.out_internal, node.keyagg_ctx.Q)

def round2(node: Node, session_ctx: SessionContext, rand:bytes = None):
    if node.is_leaf():
        final_nonce, psig = sign(node.state, node.sk, session_ctx)
        node.out_ = psig
        node.state_ = final_nonce
    else:
        nonce_path, pk_tree, tweaks, is_xonly, msg = session_ctx
        for child_index, w in enumerate(node.children):
            siblings = [u.pk for sibling_index, u in enumerate(node.children) if sibling_index != child_index]
            session_ctx_ = SessionContext(nonce_path + [node.out_internal], pk_tree + [siblings], tweaks, is_xonly, msg)
            round2(w, session_ctx_, rand)

        node.state_ = node.children[0].state_ # same for every node
        psigs = [w.out_ for w in node.children]

        # Aggregating signatures of the children
        if node.is_root:
            s = partial_sig_agg(psigs, node.state_, session_ctx, node.keyagg_ctx)
        else:
            s = partial_sig_agg(psigs, node.state_)
        node.out_ = s


def simulate_sign_test(node):
    msg = secrets.token_bytes(32)
    # Setup
    key_gen_tree(node)

    aggx = get_xonly_pk(node.keyagg_ctx)
    round1(node, aggx, msg)

    tweaks = [secrets.token_bytes(32) for _ in range(4)]
    is_xonly = [secrets.choice([False, True]) for _ in range(4)]
    session_ctx = SessionContext(
        nonce_path=[],
        pk_tree=[],
        tweaks = tweaks,
        is_xonly = is_xonly,
        msg=msg,
    )
    round2(node, session_ctx)

    R = node.state_
    assert(verify_r(node, R))
    tweaked_pubkey_ctx = apply_tweaks(node.keyagg_ctx, tweaks, is_xonly)
    assert(schnorr_verify(msg, get_xonly_pk(tweaked_pubkey_ctx), R + node.out_))

def verify_r(node: Node, R: bytes):
    if node.is_leaf():
        if R != node.state_:
            print(node.value + " failed to verify R")
            print(node.state_.hex().upper())
            return False
        else:
            return True
    else:
        for w in node.children:
            if not verify_r(w, R):
                return False
        return True
