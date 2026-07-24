from typing import List

from frost_ref import (
    SessionContext,
    SignersContext,
    nonce_agg,
    partial_sig_verify,
    sign,
)

from generators.common import (
    COMMON_MSGS,
    CONFIGS,
    SharedGroupInputs,
    assign_tc_ids,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    get_subset,
    set_group_config,
    write_test_vectors,
)

# an invalid 33-byte tweak value, kept local to this generator rather than in common.py
INVALID_33_BYTE_TWEAK = bytes.fromhex(
    "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BBFF"
)


class TweakGroupBuilder:
    """Builds one (t, n) test group for tweak_vectors.json. Shared inputs and
    subsets live on self. Each add_* method appends its category to self.group.

    Index convention: valid cases use secshare_index == secnonce_index == my_id (a
    signer signs with its own material at pool position my_id)."""

    def __init__(self, cfg):
        self.inputs = SharedGroupInputs(cfg)
        self.t = self.inputs.t
        self.n = self.inputs.n
        self.thresh_pk = self.inputs.thresh_pk

        self.min_s = get_subset(cfg, "min")
        self.full = get_subset(cfg, "full")
        self.aggnonce_min = self._agg(self.min_s)

        # Build the tweaks pool: self.inputs.tweaks_pool has 6 entries (indices 0-5).
        # Append INVALID_33_BYTE_TWEAK at the next slot (len of the shared pool).
        self.tweaks_pool = list(self.inputs.tweaks_pool) + [INVALID_33_BYTE_TWEAK]

        self.group = {}
        set_group_config(self.group, cfg, self.inputs)
        # Tweak error cases fault only the tweak value, so the group serializes the
        # real (non-pool) pubshares, pubnonces, secshares, and secnonces. The tweaks
        # array is the extended pool with the invalid 33-byte entry appended. Invalid
        # pubshare, nonce, and secret-share faults are covered in
        # sign_verify_vectors.json, not here.
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pubshares)
        self.group["pubnonces"] = bytes_list_to_hex(self.inputs.pubnonces)
        self.group["secshares"] = bytes_list_to_hex(self.inputs.secshares)
        self.group["secnonces"] = bytes_list_to_hex(self.inputs.secnonces)
        self.group["tweaks"] = bytes_list_to_hex(self.tweaks_pool)
        self.group["valid_tests"] = []
        self.group["error_tests"] = []

    def _agg(self, pubnonce_indices: List[int]) -> bytes:
        return nonce_agg([self.inputs.pubnonces[i] for i in pubnonce_indices])

    def _append_valid(
        self,
        my_id: int,
        ids: List[int],
        pubshare_indices: List[int],
        pubnonce_indices: List[int],
        aggnonce: bytes,
        msg: bytes,
        tweak_indices: List[int],
        is_xonly: List[bool],
        comment: str,
    ) -> None:
        pubshares = [self.inputs.pubshares[i] for i in pubshare_indices]
        tweaks = [self.tweaks_pool[i] for i in tweak_indices]
        secnonce = bytearray(self.inputs.secnonces[my_id])
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(aggnonce, signers, tweaks, is_xonly, msg)
        psig = sign(secnonce, self.inputs.secshares[my_id], my_id, session)
        assert partial_sig_verify(
            psig,
            [self.inputs.pubnonces[i] for i in pubnonce_indices],
            signers,
            tweaks,
            is_xonly,
            msg,
            ids.index(my_id),
        )
        self.group["valid_tests"].append(
            {
                "comment": comment,
                "my_id": my_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "pubnonce_indices": pubnonce_indices,
                "secshare_index": my_id,
                "secnonce_index": my_id,
                "aggnonce": bytes_to_hex(aggnonce),
                "msg": bytes_to_hex(msg),
                "tweak_indices": tweak_indices,
                "is_xonly": is_xonly,
                "expected": bytes_to_hex(psig),
            }
        )

    def _append_error(
        self,
        my_id: int,
        ids: List[int],
        pubshare_indices: List[int],
        secshare_index: int,
        secnonce_index: int,
        aggnonce: bytes,
        msg: bytes,
        tweak_indices: List[int],
        is_xonly: List[bool],
        comment: str,
    ) -> None:
        pubshares = [self.inputs.pubshares[i] for i in pubshare_indices]
        tweaks = [self.tweaks_pool[i] for i in tweak_indices]
        secnonce = bytearray(self.inputs.secnonces[secnonce_index])
        secshare = self.inputs.secshares[secshare_index]
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(aggnonce, signers, tweaks, is_xonly, msg)
        err = expect_exception(
            lambda: sign(secnonce, secshare, my_id, session), ValueError
        )
        self.group["error_tests"].append(
            {
                "comment": comment,
                "my_id": my_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "secshare_index": secshare_index,
                "secnonce_index": secnonce_index,
                "aggnonce": bytes_to_hex(aggnonce),
                "msg": bytes_to_hex(msg),
                "tweak_indices": tweak_indices,
                "is_xonly": is_xonly,
                "error": err,
            }
        )

    # --- Array A: valid_tests ---

    def add_valid_tests(self) -> None:
        msg = COMMON_MSGS[0]
        aggnonce_full = self._agg(self.full)

        # No tweaks applied
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            msg,
            [],
            [],
            "No tweaks applied",
        )
        # Single x-only tweak
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            msg,
            [0],
            [True],
            "Single x-only tweak (used for BIP341 Taproot)",
        )
        # Single plain tweak
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            msg,
            [0],
            [False],
            "Single plain tweak (used for BIP32 derivation)",
        )
        # Plain then x-only tweak
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            msg,
            [0, 1],
            [False, True],
            "A plain tweak followed by an x-only tweak",
        )
        # Four tweaks alternating x-only and plain
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            msg,
            [0, 1, 2, 3],
            [True, False, True, False],
            "Four tweaks alternating x-only and plain",
        )
        # Four tweaks: two plain then two x-only
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            msg,
            [0, 1, 2, 3],
            [False, False, True, True],
            "Four tweaks: two plain followed by two x-only",
        )
        # Same tweaks as the previous case but all n signers, signed by non-first member
        self._append_valid(
            1,
            self.full,
            self.full,
            self.full,
            aggnonce_full,
            msg,
            [0, 1, 2, 3],
            [False, False, True, True],
            "Same tweaks as the previous case but with all signers participating, signed by a non-first member of the signer set",
        )

    # --- Array B: error_tests ---

    def add_error_tests(self) -> None:
        msg = COMMON_MSGS[0]
        my_id = 0

        # Tweak exceeds the group order
        self._append_error(
            my_id,
            self.min_s,
            self.min_s,
            0,
            0,
            self.aggnonce_min,
            msg,
            [self.inputs.OUT_OF_RANGE_TWEAK_IDX],
            [False],
            "Tweak exceeds the group order",
        )
        # Infinity tweak
        self._append_error(
            my_id,
            self.min_s,
            self.min_s,
            0,
            0,
            self.aggnonce_min,
            msg,
            [self.inputs.INFINITY_TWEAK_IDX],
            [False],
            "Plain tweak drives the tweaked threshold public key to the point at infinity",
        )
        # Length mismatch between tweaks and is_xonly
        self._append_error(
            my_id,
            self.min_s,
            self.min_s,
            0,
            0,
            self.aggnonce_min,
            msg,
            [0],
            [],
            "Number of tweaks does not match the number of tweak modes",
        )
        # Invalid 33-byte tweak
        self._append_error(
            my_id,
            self.min_s,
            self.min_s,
            0,
            0,
            self.aggnonce_min,
            msg,
            # index of the appended invalid 33-byte tweak (last slot of the pool)
            [len(self.inputs.tweaks_pool)],
            [False],
            "Tweak is not a 32-byte array",
        )

    def build(self) -> dict:
        self.add_valid_tests()
        self.add_error_tests()
        return self.group


def generate_tweak_vectors() -> None:
    groups = [TweakGroupBuilder(cfg).build() for cfg in CONFIGS]
    assign_tc_ids(groups)
    write_test_vectors("tweak_vectors.json", {"test_groups": groups})
