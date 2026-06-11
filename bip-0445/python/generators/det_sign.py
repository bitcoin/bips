from typing import List, Optional

from frost_ref import (
    InvalidContributionError,
    SignersContext,
    deterministic_sign,
    nonce_agg,
)
from frost_ref.signing import nonce_gen_internal

from generators.common import (
    COMMON_MSGS,
    COMMON_TWEAKS,
    CONFIGS,
    AGGNONCE_WRONG_TAG,
    OUT_OF_RANGE_TWEAK,
    SharedGroupInputs,
    assign_tc_ids,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    get_subset,
    has_excl0_subset,
    set_group_config,
    swap_last_two,
    write_test_vectors,
)

# Aux-randomness pool: all-zeros, None (omitted), all-ones.
RANDS = [
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),
    None,
    bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
]

# Fault literals that are case payloads rather than pool material (config-independent,
# never indexed from a pool), so they stay local to this generator.
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
    """Builds one (t, n) test group for det_sign_vectors.json. Shared inputs and
    subsets live on self. Each add_* method appends its category to self.group.

    Index convention: valid cases use secshare_index == my_id (a signer signs with
    its own share at pool position my_id)."""

    def __init__(self, cfg):
        self.inputs = SharedGroupInputs(cfg)
        self.t = self.inputs.t
        self.n = self.inputs.n
        self.thresh_pk = self.inputs.thresh_pk

        self.cfg = cfg
        self.min_s = get_subset(cfg, "min")
        self.full = get_subset(cfg, "full")
        self.alt = get_subset(cfg, "alt")
        self.min2 = get_subset(cfg, "min2")

        self.group = {}
        set_group_config(self.group, cfg, self.inputs)
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pool_pubshares)
        self.group["secshares"] = bytes_list_to_hex(self.inputs.pool_secshares)
        self.group["valid_tests"] = []
        self.group["error_tests"] = []

    def _derive_aggothernonce(
        self,
        ids_set: List[int],
        my_id: int,
        msg: bytes,
        rand: Optional[bytes],
    ) -> Optional[bytes]:
        """Return None when the signer is the sole participant (the set is exactly
        [my_id]). Otherwise aggregate the other signers' public nonces."""
        if ids_set == [my_id]:
            return None
        tmp = b"" if rand is None else rand
        other_pubnonces = []
        for pid in ids_set:
            if pid == my_id:
                continue
            _, pub = nonce_gen_internal(
                tmp,
                self.inputs.pool_secshares[pid],
                self.inputs.pool_pubshares[pid],
                self.inputs.xonly_thresh_pk,
                msg,
                None,
            )
            other_pubnonces.append(pub)
        return nonce_agg(other_pubnonces)

    def _append_valid(
        self,
        my_id: int,
        ids: List[int],
        pubshare_indices: List[int],
        rand: Optional[bytes],
        msg: bytes,
        tweaks: List[bytes],
        is_xonly: List[bool],
        comment: str,
    ) -> None:
        curr_aggothernonce = self._derive_aggothernonce(ids, my_id, msg, rand)
        pubshares = [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        secshare = self.inputs.pool_secshares[my_id]
        result = deterministic_sign(
            secshare, my_id, curr_aggothernonce, signers, tweaks, is_xonly, msg, rand
        )
        self.group["valid_tests"].append(
            {
                "comment": comment,
                "my_id": my_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "secshare_index": my_id,
                "aggothernonce": bytes_to_hex(curr_aggothernonce)
                if curr_aggothernonce is not None
                else None,
                "rand": bytes_to_hex(rand) if rand is not None else None,
                "msg": bytes_to_hex(msg),
                "tweaks": bytes_list_to_hex(tweaks),
                "is_xonly": is_xonly,
                "expected": bytes_list_to_hex(list(result)),
            }
        )

    def _append_error(
        self,
        my_id: int,
        ids: List[int],
        pubshare_indices: List[int],
        secshare_index: int,
        rand: Optional[bytes],
        msg: bytes,
        tweaks: List[bytes],
        is_xonly: List[bool],
        error: str,
        comment: str,
        aggothernonce: Optional[bytes] = None,
    ) -> None:
        # A caller may supply a crafted aggothernonce to exercise an error path.
        curr_aggothernonce: Optional[bytes]
        if aggothernonce is not None:
            curr_aggothernonce = aggothernonce
        else:
            curr_aggothernonce = self._derive_aggothernonce(ids, my_id, msg, rand)
        pubshares = [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        secshare = self.inputs.pool_secshares[secshare_index]
        expected_exc = ValueError if error == "value" else InvalidContributionError
        err = expect_exception(
            lambda: deterministic_sign(
                secshare,
                my_id,
                curr_aggothernonce,
                signers,
                tweaks,
                is_xonly,
                msg,
                rand,
            ),
            expected_exc,
        )
        self.group["error_tests"].append(
            {
                "comment": comment,
                "my_id": my_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "secshare_index": secshare_index,
                "aggothernonce": bytes_to_hex(curr_aggothernonce)
                if curr_aggothernonce is not None
                else None,
                "rand": bytes_to_hex(rand) if rand is not None else None,
                "msg": bytes_to_hex(msg),
                "tweaks": bytes_list_to_hex(tweaks),
                "is_xonly": is_xonly,
                "error": err,
            }
        )

    # --- Array A: valid_tests ---

    def add_valid_tests(self) -> None:
        t, n = self.t, self.n
        # minimum threshold subset.
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "Minimum threshold subset of signers",
        )
        # reordering (needs a set of size >= 2 to be meaningful, matching sign_verify).
        if t >= 2:
            rev = list(reversed(self.min_s))
            self._append_valid(
                0,
                rev,
                rev,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "Reordering the signer set leaves the deterministic output unchanged, because the identifiers are sorted before they are bound into the nonce derivation and the binding value",
            )
        # a different threshold subset (needs t >= 2; at t=1 alt collapses to the
        # minimum set, matching sign_verify).
        if t >= 2 and t < n:
            self._append_valid(
                0,
                self.alt,
                self.alt,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "A different threshold subset gives a different deterministic nonce, since the signer set is bound into the nonce derivation",
            )
        # null randomness.
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
        # all-ones randomness.
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            RANDS[2],
            COMMON_MSGS[0],
            [],
            [],
            "Auxiliary randomness is all ones, distinct from the all-zeros and omitted cases",
        )
        # all signers, non-first member signs.
        self._append_valid(
            1,
            self.full,
            self.full,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "All signers participate, signed by a non-first member of the signer set",
        )
        # empty message.
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
        # non-standard message length.
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
        # single x-only tweak.
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

    # --- Array B: error_tests ---

    def add_error_tests(self) -> None:
        t, n = self.t, self.n
        # my_id is absent from the signer set (only when t < n).
        if t < n:
            self._append_error(
                t,
                self.min_s,
                self.min_s,
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Signer's identifier is absent from the signer set",
            )
        # duplicate id in the signer set.
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
        # signer loads share 0 but the set excludes id 0 (needs t >= 2 and t < n).
        if has_excl0_subset(t, n):
            excl0 = get_subset(self.cfg, "excl0")
            self._append_error(
                1,
                excl0,
                excl0,
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Signer's public share is not in the public share list",
            )
        # off-curve pubshare at position 1 (min2 forces size >= 2).
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
        # A signer id equals n, outside the valid range. For t >= 2 an in-range
        # member signs. At t=1 the lone id is out of range and the check fires
        # first, so the self fields are inert. This assumes signer-id range
        # validation runs before the pubshare/threshold-key checks; a different
        # order would surface a different error.
        if t >= 2:
            ids_out_of_range = [self.inputs.OUT_OF_RANGE_ID] + list(range(1, t))
            self._append_error(
                1,
                ids_out_of_range,
                list(range(t)),
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
        # pubshares don't match the threshold public key. Needs t >= 2: at t=1 the lone
        # pubshare must equal the threshold key, so there is no last-two pair to swap. The
        # 1of3 config intentionally omits this case, matching sign_verify.
        if t >= 2:
            self._append_error(
                0,
                self.min_s,
                swap_last_two(self.min_s),
                0,
                RANDS[0],
                COMMON_MSGS[0],
                [],
                [],
                "value",
                "Signer set's public shares do not match the threshold public key",
            )
        # Bad aggothernonce literals passed directly to bypass the helper.
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
        # tweak exceeds the group order.
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
            "Tweak exceeds the group order",
        )
        # Fewer signers than the threshold (empty set at t=1).
        below = list(range(t - 1))
        self._append_error(
            0,
            below,
            below,
            0,
            RANDS[0],
            COMMON_MSGS[0],
            [],
            [],
            "value",
            "Fewer signers than the threshold t",
        )
        # signing with a zero secret share
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


def generate_det_sign_vectors() -> None:
    groups = [DetSignGroupBuilder(cfg).build() for cfg in CONFIGS]
    assign_tc_ids(groups)
    write_test_vectors("det_sign_vectors.json", {"test_groups": groups})
