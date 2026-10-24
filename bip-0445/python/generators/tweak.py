from typing import List

from frost_ref import (
    SessionContext,
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


class TweakGroupBuilder:
    """Builds one (t, n) test group for tweak_vectors.json.

    Index convention: valid cases use secshare_index == secnonce_index == signer_id."""

    def __init__(self, cfg):
        self.inputs = SharedGroupInputs(cfg)
        self.t = self.inputs.t
        self.n = self.inputs.n
        self.thresh_pk = self.inputs.thresh_pk

        self.min_s = get_subset(cfg, "min")
        self.min2 = get_subset(cfg, "min2")
        self.aggnonce_min = self._agg(self.min_s)

        # Shared tweaks pool with an invalid 33-byte tweak appended as the last entry. It is a
        # zero byte followed by a valid tweak, so only the length check can reject it.
        invalid_33_byte_tweak = b"\x00" + self.inputs.tweaks_pool[0]
        self.tweaks_pool = list(self.inputs.tweaks_pool) + [invalid_33_byte_tweak]

        self.group = {}
        set_group_config(self.group, cfg, self.inputs)
        # Error cases fault only the tweak, so the other arrays are the real (non-pool) ones.
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
        signer_id: int,
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
        secnonce = bytearray(self.inputs.secnonces[signer_id])
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(*signer_set, aggnonce, tweaks, is_xonly, msg)
        psig = sign(secnonce, self.inputs.secshares[signer_id], signer_id, session)
        assert partial_sig_verify(
            psig,
            [self.inputs.pubnonces[i] for i in pubnonce_indices],
            *signer_set,
            tweaks,
            is_xonly,
            msg,
            ids.index(signer_id),
        )
        self.group["valid_tests"].append(
            {
                "comment": comment,
                "signer_id": signer_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "pubnonce_indices": pubnonce_indices,
                "secshare_index": signer_id,
                "secnonce_index": signer_id,
                "aggnonce": bytes_to_hex(aggnonce),
                "msg": bytes_to_hex(msg),
                "tweak_indices": tweak_indices,
                "is_xonly": is_xonly,
                "expected": bytes_to_hex(psig),
            }
        )

    def _append_error(
        self,
        signer_id: int,
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
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(*signer_set, aggnonce, tweaks, is_xonly, msg)
        err = expect_exception(
            lambda: sign(secnonce, secshare, signer_id, session), ValueError
        )
        self.group["error_tests"].append(
            {
                "comment": comment,
                "signer_id": signer_id,
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

    def add_valid_tests(self) -> None:
        msg = COMMON_MSGS[0]
        aggnonce_min2 = self._agg(self.min2)

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
        self._append_valid(
            1,
            self.min2,
            self.min2,
            self.min2,
            aggnonce_min2,
            msg,
            [0, 1, 2, 3],
            [False, False, True, True],
            "Four tweaks: two plain followed by two x-only",
        )

    def add_error_tests(self) -> None:
        msg = COMMON_MSGS[0]
        signer_id = 0

        self._append_error(
            signer_id,
            self.min_s,
            self.min_s,
            0,
            0,
            self.aggnonce_min,
            msg,
            [self.inputs.OUT_OF_RANGE_TWEAK_IDX],
            [False],
            "Tweak equals the group order, which is out of range",
        )
        self._append_error(
            signer_id,
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
        self._append_error(
            signer_id,
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
        self._append_error(
            signer_id,
            self.min_s,
            self.min_s,
            0,
            0,
            self.aggnonce_min,
            msg,
            # last pool entry, the appended invalid tweak
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
