from typing import List

from frost_ref import (
    InvalidContributionError,
    SessionContext,
    SignersContext,
    nonce_agg,
    partial_sig_verify,
    sign,
)
from secp256k1lab.secp256k1 import Scalar

from generators.common import (
    COMMON_MSGS,
    CONFIGS,
    GROUP_ORDER,
    AGGNONCE_WRONG_TAG,
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

# Fault literals that are case payloads rather than pool material (config-independent,
# never indexed from a pool), so they stay local to this generator.
AGGNONCE_BAD_XCOORD = bytes.fromhex(
    "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009"
)
AGGNONCE_EXCEEDS_FIELD = bytes.fromhex(
    "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
)


class SignVerifyGroupBuilder:
    """Builds one (t, n) test group for sign_verify_vectors.json. Shared inputs and
    subsets live on self. Each add_* method appends its category to self.group.

    Index convention: valid cases use secshare_index == secnonce_index == my_id (a
    signer signs with its own material at pool position my_id), and verify-side cases
    use signer 0's material as the base partial signature."""

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
        self.aggnonce_min = self._agg(self.min_s)

        self.group = {}
        set_group_config(self.group, cfg, self.inputs)
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pool_pubshares)
        self.group["pubnonces"] = bytes_list_to_hex(self.inputs.pool_pubnonces)
        self.group["secshares"] = bytes_list_to_hex(self.inputs.pool_secshares)
        self.group["secnonces"] = bytes_list_to_hex(self.inputs.pool_secnonces)
        self.group["valid_tests"] = []
        self.group["sign_error_tests"] = []
        self.group["verify_fail_tests"] = []
        self.group["verify_error_tests"] = []

    def _agg(self, pubnonce_indices: List[int]) -> bytes:
        return nonce_agg([self.inputs.pool_pubnonces[i] for i in pubnonce_indices])

    def _append_valid(
        self,
        my_id: int,
        ids: List[int],
        pubshare_indices: List[int],
        pubnonce_indices: List[int],
        aggnonce: bytes,
        msg: bytes,
        comment: str,
    ) -> None:
        pubshares = [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        pubnonces = [self.inputs.pool_pubnonces[i] for i in pubnonce_indices]
        secnonce = bytearray(self.inputs.pool_secnonces[my_id])
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(aggnonce, signers, [], [], msg)
        psig = sign(secnonce, self.inputs.pool_secshares[my_id], my_id, session)
        assert partial_sig_verify(
            psig, pubnonces, signers, [], [], msg, ids.index(my_id)
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
                "expected": bytes_to_hex(psig),
            }
        )

    def _append_sign_error(
        self,
        my_id: int,
        ids: List[int],
        pubshare_indices: List[int],
        secshare_idx: int,
        secnonce_idx: int,
        aggnonce: bytes,
        msg: bytes,
        error: str,
        comment: str,
    ) -> None:
        pubshares = [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        secshare = self.inputs.pool_secshares[secshare_idx]
        secnonce = bytearray(self.inputs.pool_secnonces[secnonce_idx])
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(aggnonce, signers, [], [], msg)
        expected_exc = ValueError if error == "value" else InvalidContributionError
        err = expect_exception(
            lambda: sign(secnonce, secshare, my_id, session), expected_exc
        )
        self.group["sign_error_tests"].append(
            {
                "comment": comment,
                "my_id": my_id,
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "secshare_index": secshare_idx,
                "secnonce_index": secnonce_idx,
                "aggnonce": bytes_to_hex(aggnonce),
                "msg": bytes_to_hex(msg),
                "error": err,
            }
        )

    def _append_verify_error(
        self,
        ids: List[int],
        pubshare_indices: List[int],
        pubnonce_indices: List[int],
        signer_index: int,
        psig: bytes,
        error: str,
        comment: str,
    ) -> None:
        pubshares = [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        pubnonces = [self.inputs.pool_pubnonces[i] for i in pubnonce_indices]
        msg = COMMON_MSGS[0]
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        expected_exc = ValueError if error == "value" else InvalidContributionError
        err = expect_exception(
            lambda: partial_sig_verify(
                psig, pubnonces, signers, [], [], msg, signer_index
            ),
            expected_exc,
        )
        self.group["verify_error_tests"].append(
            {
                "comment": comment,
                "psig": bytes_to_hex(psig),
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "pubnonce_indices": pubnonce_indices,
                "signer_index": signer_index,
                "msg": bytes_to_hex(msg),
                "error": err,
            }
        )

    def _append_verify_fail(
        self,
        ids: List[int],
        pubshare_indices: List[int],
        pubnonce_indices: List[int],
        signer_index: int,
        psig: bytes,
        comment: str,
    ) -> None:
        pubshares = [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        pubnonces = [self.inputs.pool_pubnonces[i] for i in pubnonce_indices]
        msg = COMMON_MSGS[0]
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        assert not partial_sig_verify(
            psig, pubnonces, signers, [], [], msg, signer_index
        )
        self.group["verify_fail_tests"].append(
            {
                "comment": comment,
                "psig": bytes_to_hex(psig),
                "ids": ids,
                "pubshare_indices": pubshare_indices,
                "pubnonce_indices": pubnonce_indices,
                "signer_index": signer_index,
                "msg": bytes_to_hex(msg),
            }
        )

    # --- Array A: valid_tests ---

    def add_valid_tests(self) -> None:
        t, n = self.t, self.n
        # Minimum threshold subset.
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "Minimum threshold subset of signers",
        )
        # Order-invariance (needs a set of size >= 2 to be meaningful).
        if t >= 2:
            rev = list(reversed(self.min_s))
            self._append_valid(
                0,
                rev,
                rev,
                rev,
                self._agg(rev),
                COMMON_MSGS[0],
                "Reordering the signer set leaves the partial signature unchanged, because the identifiers are sorted before they are bound into the binding value",
            )
        # A different threshold subset (needs t >= 2 and t < n, else the alt set
        # collapses to the minimum set or is the only valid set).
        if t >= 2 and t < n:
            self._append_valid(
                0,
                self.alt,
                self.alt,
                self.alt,
                self._agg(self.alt),
                COMMON_MSGS[0],
                "A different threshold subset gives a different partial signature, since the Lagrange coefficients depend on the signer set",
            )
        # All n signers, signed by a non-first member.
        self._append_valid(
            1,
            self.full,
            self.full,
            self.full,
            self._agg(self.full),
            COMMON_MSGS[0],
            "All signers participate, signed by a non-first member of the signer set",
        )
        # Aggregate nonce is the point at infinity. The inverse pubnonce cancels
        # the first n-1 real pubnonces, so the aggregate over them is infinity.
        inf_pubnonce_indices = list(range(n - 1)) + [self.inputs.INVERSE_PUBNONCE_IDX]
        self._append_valid(
            0,
            self.full,
            self.full,
            inf_pubnonce_indices,
            self._agg(inf_pubnonce_indices),
            COMMON_MSGS[0],
            "Aggregate nonce is the point at infinity, so the final nonce point falls back to the generator G",
        )
        # Message variations over the minimum set.
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            COMMON_MSGS[1],
            "Empty message",
        )
        self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            COMMON_MSGS[2],
            "Non-standard message length (38 bytes)",
        )

    # --- Array B: sign_error_tests ---

    def add_sign_error_tests(self) -> None:
        t, n = self.t, self.n
        # my_id is a valid participant absent from the set (needs t < n so a valid
        # participant can sit outside the only valid set).
        if t < n:
            self._append_sign_error(
                t,
                self.min_s,
                self.min_s,
                0,
                0,
                self.aggnonce_min,
                COMMON_MSGS[0],
                "value",
                "Signer's identifier is absent from the signer set",
            )
        # Duplicate id in the set (fixed [0, 1, 1], valid for every config).
        self._append_sign_error(
            0,
            [0, 1, 1],
            [0, 1, 1],
            0,
            0,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "value",
            "Signer set contains a duplicate id",
        )
        # Signer loads share 0 but the set excludes id 0, so its derived pubshare
        # is absent (needs t >= 2 for distinct shares and t < n for a participant
        # outside the set).
        if has_excl0_subset(t, n):
            excl0 = get_subset(self.cfg, "excl0")
            self._append_sign_error(
                1,
                excl0,
                excl0,
                0,
                0,
                self._agg(excl0),
                COMMON_MSGS[0],
                "value",
                "Signer's public share is not in the public share list",
            )
        # A listed public share is off-curve (at position 1, so min2 forces size 2).
        pubshare_indices_offcurve = [
            self.min2[0],
            self.inputs.INVALID_PUBSHARE_IDX,
        ] + self.min2[2:]
        self._append_sign_error(
            0,
            self.min2,
            pubshare_indices_offcurve,
            0,
            0,
            self._agg(self.min2),
            COMMON_MSGS[0],
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
            self._append_sign_error(
                1,
                ids_out_of_range,
                list(range(t)),
                1,
                1,
                self.aggnonce_min,
                COMMON_MSGS[0],
                "value",
                "A signer id is outside the valid range [0, n-1]",
            )
        else:
            self._append_sign_error(
                0,
                [self.inputs.OUT_OF_RANGE_ID],
                [0],
                0,
                0,
                self._agg([0]),
                COMMON_MSGS[0],
                "value",
                "A signer id is outside the valid range [0, n-1]",
            )
        # Public shares won't interpolate to the correct threshold key, since we're
        # swapping the last two positions (needs t >= 2 for distinct shares).
        if t >= 2:
            self._append_sign_error(
                0,
                self.min_s,
                swap_last_two(self.min_s),
                0,
                0,
                self.aggnonce_min,
                COMMON_MSGS[0],
                "value",
                "Signer set's public shares do not match the threshold public key",
            )
        # Invalid aggregate nonce literals.
        self._append_sign_error(
            0,
            self.min_s,
            self.min_s,
            0,
            0,
            AGGNONCE_WRONG_TAG,
            COMMON_MSGS[0],
            "invalid_contrib",
            "Aggregate nonce is invalid: first half has an unknown tag 0x04",
        )
        self._append_sign_error(
            0,
            self.min_s,
            self.min_s,
            0,
            0,
            AGGNONCE_BAD_XCOORD,
            COMMON_MSGS[0],
            "invalid_contrib",
            "Aggregate nonce is invalid: second half is not a point on the curve",
        )
        self._append_sign_error(
            0,
            self.min_s,
            self.min_s,
            0,
            0,
            AGGNONCE_EXCEEDS_FIELD,
            COMMON_MSGS[0],
            "invalid_contrib",
            "Aggregate nonce is invalid: second half's x-coordinate exceeds the field size",
        )
        # All-zero secret nonce (first scalar out of range).
        self._append_sign_error(
            0,
            self.min_s,
            self.min_s,
            0,
            self.inputs.SECNONCE_ZERO_IDX,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "value",
            "Secret nonce's first half is out of range (all-zero nonce, which may indicate nonce reuse)",
        )
        # Secret nonce with a zero second scalar.
        self._append_sign_error(
            0,
            self.min_s,
            self.min_s,
            0,
            self.inputs.SECNONCE_ZERO_SECOND_IDX,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "value",
            "Secret nonce's second half is out of range (zero)",
        )
        # Fewer signers than the threshold (empty set at t=1). The aggnonce, secshare,
        # and secnonce fields are inert placeholders: SignersContext rejects the
        # sub-threshold set before sign() reads them.
        below = list(range(t - 1))
        self._append_sign_error(
            0,
            below,
            below,
            0,
            0,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "value",
            "Fewer signers than the threshold t",
        )
        # Zero secret share.
        self._append_sign_error(
            0,
            self.min_s,
            self.min_s,
            self.inputs.SECSHARE_ZERO_IDX,
            0,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "value",
            "Secret share is out of range (zero)",
        )

    # --- Array C: verify_fail_tests ---

    def add_verify_fail_tests(self) -> None:
        # Base partial signature: signer 0 over min2, the size-at-least-2 baseline set.
        # min2 (not min_s) because the wrong-signer-index fail case below verifies at
        # signer_index 1, which needs a 2-signer set. min2 == min_s for t >= 2, so this
        # only differs at t=1.
        secnonce = bytearray(self.inputs.pool_secnonces[0])
        signers = SignersContext(
            self.n,
            self.t,
            self.min2,
            [self.inputs.pool_pubshares[i] for i in self.min2],
            self.thresh_pk,
        )
        session = SessionContext(self._agg(self.min2), signers, [], [], COMMON_MSGS[0])
        psig = sign(secnonce, self.inputs.pool_secshares[0], 0, session)
        neg_psig = (-Scalar.from_bytes_checked(psig)).to_bytes()

        self._append_verify_fail(
            self.min2,
            self.min2,
            self.min2,
            0,
            neg_psig,
            "Negated partial signature fails the verification equation",
        )
        self._append_verify_fail(
            self.min2,
            self.min2,
            self.min2,
            1,
            psig,
            "A valid partial signature checked against the wrong signer fails the verification equation",
        )
        self._append_verify_fail(
            self.min2,
            self.min2,
            self.min2,
            0,
            GROUP_ORDER,
            "Partial signature equals the group order, which is out of range",
        )

    # --- Array D: verify_error_tests ---

    def add_verify_error_tests(self) -> None:
        # Base partial signature: signer 0 over the minimum set.
        secnonce = bytearray(self.inputs.pool_secnonces[0])
        signers = SignersContext(
            self.n,
            self.t,
            self.min_s,
            [self.inputs.pool_pubshares[i] for i in self.min_s],
            self.thresh_pk,
        )
        session = SessionContext(self.aggnonce_min, signers, [], [], COMMON_MSGS[0])
        psig_min = sign(secnonce, self.inputs.pool_secshares[0], 0, session)

        # Off-curve public nonce at position 0.
        pubnonce_indices_offcurve = [self.inputs.INVALID_PUBNONCE_IDX] + self.min_s[1:]
        self._append_verify_error(
            self.min_s,
            self.min_s,
            pubnonce_indices_offcurve,
            0,
            psig_min,
            "invalid_contrib",
            "Verification rejects an invalid public nonce, blaming the malicious signer",
        )
        # Off-curve public share at position 0.
        pubshare_indices_offcurve = [self.inputs.INVALID_PUBSHARE_IDX] + self.min_s[1:]
        self._append_verify_error(
            self.min_s,
            pubshare_indices_offcurve,
            self.min_s,
            0,
            psig_min,
            "value",
            "A public share is not a valid point",
        )

    def build(self) -> dict:
        self.add_valid_tests()
        self.add_sign_error_tests()
        self.add_verify_fail_tests()
        self.add_verify_error_tests()
        return self.group


def generate_sign_verify_vectors() -> None:
    groups = [SignVerifyGroupBuilder(cfg).build() for cfg in CONFIGS]
    assign_tc_ids(groups)
    write_test_vectors("sign_verify_vectors.json", {"test_groups": groups})
