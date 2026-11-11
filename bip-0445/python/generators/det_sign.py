from typing import List, Optional, Tuple

from frost_ref import (
    InvalidContributionError,
    deterministic_sign,
    nonce_agg,
)
from frost_ref.signing import nonce_gen_internal

from generators.common import (
    COMMON_MSGS,
    COMMON_TWEAKS,
    INVALID_CONFIG_2OF129,
    CONFIGS,
    AGGNONCE_WRONG_TAG,
    OUT_OF_RANGE_TWEAK,
    SharedGroupInputs,
    assign_tc_ids,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    get_subset,
    set_group_config,
    swap_last_two,
    write_test_vectors,
)

# Aux-randomness pool: all-zeros, None (omitted), arbitrary non-zero.
RANDS = [
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    None,
    bytes.fromhex("B664640DA62E96ACAF94BDD3C892B1C1952304E7C98103EA9729891155BA99EF"),
]

AGGOTHERNONCE_FIRST_HALF_ZERO = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000000287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
)
AGGOTHERNONCE_BAD_POINT = bytes.fromhex(
    "0353BC2314D46C813AF81317AF1BDF99816B6444E416BB8D3DC04ACB2F5388D1AC020000000000000000000000000000000000000000000000000000000000000009"
)
AGGOTHERNONCE_EXCEEDS_FIELD = bytes.fromhex(
    "0353BC2314D46C813AF81317AF1BDF99816B6444E416BB8D3DC04ACB2F5388D1AC02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
)


class DetSignGroupBuilder:
    """Builds one (t, n) test group for det_sign_vectors.json.

    Index convention: valid cases use secshare_index == signer_id."""

    def __init__(self, cfg):
        self.inputs = SharedGroupInputs(cfg)
        self.t = self.inputs.t
        self.n = self.inputs.n
        self.thresh_pk = self.inputs.thresh_pk

        self.cfg = cfg
        self.min_s = get_subset(cfg, "min")
        self.alt = get_subset(cfg, "alt")
        self.min2 = get_subset(cfg, "min2")
        self.tplus1 = get_subset(cfg, "tplus1")

        self.group = {}
        set_group_config(self.group, cfg, self.inputs)
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pool_pubshares)
        self.group["secshares"] = bytes_list_to_hex(self.inputs.pool_secshares)
        self.group["valid_tests"] = []
        self.group["error_tests"] = []

    def _derive_aggothernonce(
        self,
        ids_set: List[int],
        signer_id: int,
        msg: bytes,
        aux_rand: Optional[bytes],
    ) -> Optional[bytes]:
        """Return None when u <= 1 (aggothernonce is omitted iff u = 1), else the
        aggregate of the other signers' public nonces. Keying on u rather than on
        signer_id's membership keeps the u = 1 error cases reaching the check they test."""
        if len(ids_set) <= 1:
            return None
        tmp = b"" if aux_rand is None else aux_rand
        other_pubnonces = []
        for id_k in ids_set:
            if id_k == signer_id:
                continue
            _, pub = nonce_gen_internal(
                tmp,
                self.inputs.pool_secshares[id_k],
                id_k,
                self.inputs.pool_pubshares[id_k],
                self.inputs.xonly_thresh_pk,
                msg,
                None,
            )
            other_pubnonces.append(pub)
        return nonce_agg(other_pubnonces)

    def _append_valid(
        self,
        signer_id: int,
        ids: List[int],
        pubshare_indices: Optional[List[int]],
        aux_rand: Optional[bytes],
        msg: bytes,
        tweaks: List[bytes],
        is_xonly: List[bool],
        comment: str,
    ) -> Tuple[bytes, bytes]:
        curr_aggothernonce = self._derive_aggothernonce(ids, signer_id, msg, aux_rand)
        # A null pubshare_indices is a session whose public share list is absent.
        pubshares = (
            None
            if pubshare_indices is None
            else [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        )
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        secshare = self.inputs.pool_secshares[signer_id]
        result = deterministic_sign(
            secshare,
            signer_id,
            curr_aggothernonce,
            *signer_set,
            tweaks,
            is_xonly,
            msg,
            aux_rand,
        )
        self.group["valid_tests"].append(
            {
                "comment": comment,
                "signer_id": signer_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "secshare_index": signer_id,
                "aggothernonce": bytes_to_hex(curr_aggothernonce)
                if curr_aggothernonce is not None
                else None,
                "aux_rand": bytes_to_hex(aux_rand) if aux_rand is not None else None,
                "msg": bytes_to_hex(msg),
                "tweaks": bytes_list_to_hex(tweaks),
                "is_xonly": is_xonly,
                "expected": bytes_list_to_hex(list(result)),
            }
        )
        return result

    def _append_error(
        self,
        signer_id: int,
        ids: List[int],
        pubshare_indices: Optional[List[int]],
        secshare_index: int,
        aux_rand: Optional[bytes],
        msg: bytes,
        tweaks: List[bytes],
        is_xonly: List[bool],
        error: str,
        comment: str,
        aggothernonce: Optional[bytes] = None,
        omit_aggothernonce: bool = False,
    ) -> None:
        curr_aggothernonce: Optional[bytes]
        if omit_aggothernonce:
            curr_aggothernonce = None
        elif aggothernonce is not None:
            curr_aggothernonce = aggothernonce
        else:
            curr_aggothernonce = self._derive_aggothernonce(
                ids, signer_id, msg, aux_rand
            )
        pubshares = (
            None
            if pubshare_indices is None
            else [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        )
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        secshare = self.inputs.pool_secshares[secshare_index]
        expected_exc = ValueError if error == "value" else InvalidContributionError
        err = expect_exception(
            lambda: deterministic_sign(
                secshare,
                signer_id,
                curr_aggothernonce,
                *signer_set,
                tweaks,
                is_xonly,
                msg,
                aux_rand,
            ),
            expected_exc,
        )
        self.group["error_tests"].append(
            {
                "comment": comment,
                "signer_id": signer_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "secshare_index": secshare_index,
                "aggothernonce": bytes_to_hex(curr_aggothernonce)
                if curr_aggothernonce is not None
                else None,
                "aux_rand": bytes_to_hex(aux_rand) if aux_rand is not None else None,
                "msg": bytes_to_hex(msg),
                "tweaks": bytes_list_to_hex(tweaks),
                "is_xonly": is_xonly,
                "error": err,
            }
        )

    def add_valid_tests(self) -> None:
        t, n = self.t, self.n
        result_min = self._append_valid(
            0,
            self.min_s,
            self.min_s,
            RANDS[2],
            COMMON_MSGS[0],
            [],
            [],
            "Minimum threshold subset of signers",
        )
        result_no_pubshares = self._append_valid(
            0,
            self.min_s,
            None,
            RANDS[2],
            COMMON_MSGS[0],
            [],
            [],
            "Signing without the public share list",
        )
        assert result_no_pubshares == result_min
        # u = min(t+1, n) signers, excluding id 0 where possible.
        shifted = get_subset(self.cfg, "tplus1_shifted")
        rev = list(reversed(shifted))
        self._append_valid(
            shifted[1],
            rev,
            rev,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "Signer set in descending order, so the identifiers must be sorted before hashing",
        )
        # Needs t >= 2 and t < n, else the alt set is a lone id or repeats id 1.
        if t >= 2 and t < n:
            self._append_valid(
                1,
                self.alt,
                self.alt,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "A different threshold subset gives a different deterministic nonce, since the signer set is bound into the nonce derivation",
            )
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            RANDS[1],
            COMMON_MSGS[0],
            [],
            [],
            "Auxiliary randomness omitted (null), which is not equivalent to all-zeros randomness",
        )
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            RANDS[0],
            COMMON_MSGS[1],
            [],
            [],
            "Empty message",
        )
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            RANDS[0],
            COMMON_MSGS[2],
            [],
            [],
            "Non-standard message length (38 bytes)",
        )
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            RANDS[0],
            COMMON_MSGS[0],
            [COMMON_TWEAKS[0]],
            [True],
            "Single x-only tweak applied",
        )

    def add_error_tests(self) -> None:
        t, n = self.t, self.n
        # Shares absent, so only the id membership check can reject it.
        if t < n:
            self._append_error(
                t,
                self.min_s,
                None,
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Signer's id is absent from the signer set",
            )
        self._append_error(
            0,
            [0, 1, 1],
            [0, 1, 1],
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "value",
            "Signer set contains a duplicate id",
        )
        # Share 0 is listed at position 0, not at signer 1's position, so a whole-list lookup misses it.
        if t >= 2:
            self._append_error(
                1,
                self.min_s,
                self.min_s,
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Signer's public share does not match the public share listed at its index",
            )
        # Position 1 needs at least two signers, hence min2.
        pubshare_indices_offcurve = [
            self.min2[0],
            self.inputs.INVALID_PUBSHARE_IDX,
        ] + self.min2[2:]
        self._append_error(
            0,
            self.min2,
            pubshare_indices_offcurve,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "value",
            "A public share is not a valid point",
        )
        # Shares absent, so only the id range check can reject it.
        if t >= 2:
            ids_out_of_range = [self.inputs.OUT_OF_RANGE_ID] + list(range(1, t))
            self._append_error(
                1,
                ids_out_of_range,
                None,
                1,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "A signer id is outside the valid range [0, n-1]",
            )
        elif t == 1:
            self._append_error(
                0,
                [self.inputs.OUT_OF_RANGE_ID],
                [0],
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "A signer id is outside the valid range [0, n-1]",
            )
        # Signer 0's own share stays in place, so only the key check fires.
        if t >= 2:
            self._append_error(
                0,
                self.tplus1,
                swap_last_two(self.tplus1),
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Signer set's public shares do not match the threshold public key",
            )
        # First t shares honest, last one wrong, so a check interpolating only the first t accepts it.
        if t < n:
            self._append_error(
                0,
                self.tplus1,
                self.tplus1[:-1] + [self.inputs.WRONG_PUBSHARE_IDX],
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Public share beyond the first t signers is inconsistent with the threshold public key",
            )
        # Invalid aggregate nonces are passed directly instead of derived from the other signers' public nonces.
        self._append_error(
            0,
            self.min2,
            self.min2,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "invalid_contrib",
            "Aggregate of the other signers' nonces is invalid: first half has an unknown tag 0x04",
            aggothernonce=AGGNONCE_WRONG_TAG,
        )
        self._append_error(
            0,
            self.min2,
            self.min2,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "invalid_contrib",
            "Aggregate of the other signers' nonces is invalid: first half is all zeros",
            aggothernonce=AGGOTHERNONCE_FIRST_HALF_ZERO,
        )
        self._append_error(
            0,
            self.min2,
            self.min2,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "invalid_contrib",
            "Aggregate of the other signers' nonces is invalid: second half is not a point on the curve",
            aggothernonce=AGGOTHERNONCE_BAD_POINT,
        )
        self._append_error(
            0,
            self.min2,
            self.min2,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "invalid_contrib",
            "Aggregate of the other signers' nonces is invalid: second half's x-coordinate exceeds the field size",
            aggothernonce=AGGOTHERNONCE_EXCEEDS_FIELD,
        )
        self._append_error(
            0,
            self.min2,
            self.min2,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "value",
            "Aggregate of the other signers' nonces is absent although there are multiple signers",
            omit_aggothernonce=True,
        )
        # Only reachable at t = 1, since u = 1 < t fails the signer-count check first.
        if t == 1:
            self._append_error(
                0,
                [0],
                [0],
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Aggregate of the other signers' nonces is present although the signer is the only signer",
                aggothernonce=self._derive_aggothernonce(
                    self.min2, 0, COMMON_MSGS[0], RANDS[0]
                ),
            )
        self._append_error(
            0,
            self.min_s,
            self.min_s,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [OUT_OF_RANGE_TWEAK],
            [False],
            "value",
            "Tweak equals the group order, which is out of range",
        )
        # Shares absent for t >= 2, so the key check cannot mask a missing size check.
        below = list(range(t - 1))
        self._append_error(
            0,
            below,
            None if t >= 2 else below,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "value",
            "Fewer signers than the threshold t",
        )
        self._append_error(
            0,
            self.min_s,
            self.min_s,
            self.inputs.SECSHARE_ZERO_IDX,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "value",
            "Secret share is out of range (zero)",
        )

    def build(self) -> dict:
        self.add_valid_tests()
        self.add_error_tests()
        return self.group

    def build_n_bound(self) -> dict:
        # n = 129 is over the limit, so only the n-bound error case is built.
        self._append_error(
            0,
            [0, 1],
            [0, 1],
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "value",
            "Number of participants n exceeds the maximum of 128",
        )
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pubshares[:2])
        self.group["secshares"] = bytes_list_to_hex(self.inputs.secshares[:2])
        return self.group


def generate_det_sign_vectors() -> None:
    groups = [DetSignGroupBuilder(cfg).build() for cfg in CONFIGS]
    groups.append(DetSignGroupBuilder(INVALID_CONFIG_2OF129).build_n_bound())
    assign_tc_ids(groups)
    write_test_vectors("det_sign_vectors.json", {"test_groups": groups})
