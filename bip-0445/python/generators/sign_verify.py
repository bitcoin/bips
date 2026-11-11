from typing import List, Optional

from frost_ref import (
    InvalidContributionError,
    SessionContext,
    nonce_agg,
    partial_sig_verify,
    sign,
)
from frost_ref.signing import MAX_PARTICIPANTS
from secp256k1lab.secp256k1 import Scalar

from generators.common import (
    COMMON_MSGS,
    INVALID_CONFIG_2OF129,
    CONFIGS,
    GROUP_ORDER,
    AGGNONCE_WRONG_TAG,
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

AGGNONCE_BAD_XCOORD = bytes.fromhex(
    "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009"
)
AGGNONCE_EXCEEDS_FIELD = bytes.fromhex(
    "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
)


class SignVerifyGroupBuilder:
    """Builds one (t, n) test group for sign_verify_vectors.json.

    Index convention: valid cases use secshare_index == secnonce_index == signer_id, and
    verify-side cases use signer 0's material as the base partial signature."""

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
        self.blame_s = swap_last_two(self.min2)
        self.tplus1 = get_subset(cfg, "tplus1")
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
        signer_id: int,
        ids: List[int],
        pubshare_indices: Optional[List[int]],
        pubnonce_indices: List[int],
        aggnonce: bytes,
        msg: bytes,
        comment: str,
    ) -> bytes:
        # A null pubshare_indices is a session whose public share list is absent.
        pubshares = (
            None
            if pubshare_indices is None
            else [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        )
        pubnonces = [self.inputs.pool_pubnonces[i] for i in pubnonce_indices]
        secnonce = bytearray(self.inputs.pool_secnonces[signer_id])
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(*signer_set, aggnonce, [], [], msg)
        psig = sign(secnonce, self.inputs.pool_secshares[signer_id], signer_id, session)
        if pubshares is not None:
            verify_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
            assert partial_sig_verify(
                psig, pubnonces, *verify_set, [], [], msg, ids.index(signer_id)
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
                "expected": bytes_to_hex(psig),
            }
        )
        return psig

    def _append_sign_error(
        self,
        signer_id: int,
        ids: List[int],
        pubshare_indices: Optional[List[int]],
        secshare_idx: int,
        secnonce_idx: int,
        aggnonce: bytes,
        msg: bytes,
        error: str,
        comment: str,
    ) -> None:
        # A null pubshare_indices is a session whose public share list is absent.
        pubshares = (
            None
            if pubshare_indices is None
            else [self.inputs.pool_pubshares[i] for i in pubshare_indices]
        )
        secshare = self.inputs.pool_secshares[secshare_idx]
        secnonce = bytearray(self.inputs.pool_secnonces[secnonce_idx])
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(*signer_set, aggnonce, [], [], msg)
        expected_exc = ValueError if error == "value" else InvalidContributionError
        err = expect_exception(
            lambda: sign(secnonce, secshare, signer_id, session), expected_exc
        )
        self.group["sign_error_tests"].append(
            {
                "comment": comment,
                "signer_id": signer_id,
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
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        expected_exc = ValueError if error == "value" else InvalidContributionError
        err = expect_exception(
            lambda: partial_sig_verify(
                psig, pubnonces, *signer_set, [], [], msg, signer_index
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
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        assert not partial_sig_verify(
            psig, pubnonces, *signer_set, [], [], msg, signer_index
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

    def add_valid_tests(self) -> None:
        t, n = self.t, self.n
        psig_min = self._append_valid(
            0,
            self.min_s,
            self.min_s,
            self.min_s,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "Minimum threshold subset of signers",
        )
        psig_no_pubshares = self._append_valid(
            0,
            self.min_s,
            None,
            self.min_s,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "Signing without the public share list",
        )
        assert psig_no_pubshares == psig_min
        # u = min(t+1, n) signers, excluding id 0 where possible.
        shifted = get_subset(self.cfg, "tplus1_shifted")
        rev = list(reversed(shifted))
        self._append_valid(
            shifted[1],
            rev,
            rev,
            rev,
            self._agg(rev),
            COMMON_MSGS[0],
            "Signer set in descending order, so the identifiers must be sorted before hashing",
        )
        # Needs t >= 2 and t < n, else the alt set is a lone id or repeats id 1.
        if t >= 2 and t < n:
            self._append_valid(
                1,
                self.alt,
                self.alt,
                self.alt,
                self._agg(self.alt),
                COMMON_MSGS[0],
                "A different threshold subset gives a different partial signature, since the Lagrange coefficients depend on the signer set",
            )
        # The inverse pubnonce cancels the first n-1 real pubnonces.
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

    def add_sign_error_tests(self) -> None:
        t, n = self.t, self.n
        # Shares absent, so only the id membership check can reject it.
        if t < n:
            self._append_sign_error(
                t,
                self.min_s,
                None,
                0,
                0,
                self.aggnonce_min,
                COMMON_MSGS[0],
                "value",
                "Signer's id is absent from the signer set",
            )
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
        # Share 0 is listed at position 0, not at signer 1's position, so a whole-list lookup misses it.
        if t >= 2:
            self._append_sign_error(
                1,
                self.min_s,
                self.min_s,
                0,
                0,
                self.aggnonce_min,
                COMMON_MSGS[0],
                "value",
                "Signer's public share does not match the public share listed at its index",
            )
        # Position 1 needs at least two signers, hence min2.
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
        # The crafted pool slot replaces the min2 set's last share, cancelling the interpolation.
        pubshare_indices_infinity = self.min2[:-1] + [self.inputs.INFINITY_PUBSHARE_IDX]
        self._append_sign_error(
            0,
            self.min2,
            pubshare_indices_infinity,
            0,
            0,
            self._agg(self.min2),
            COMMON_MSGS[0],
            "value",
            "Public shares of the signer set interpolate to the point at infinity",
        )
        # Shares absent, so only the id range check can reject it.
        if t >= 2:
            ids_out_of_range = [self.inputs.OUT_OF_RANGE_ID] + list(range(1, t))
            self._append_sign_error(
                1,
                ids_out_of_range,
                None,
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
        # Signer 0's own share stays in place, so only the key check fires.
        if t >= 2:
            self._append_sign_error(
                0,
                self.tplus1,
                swap_last_two(self.tplus1),
                0,
                0,
                self._agg(self.tplus1),
                COMMON_MSGS[0],
                "value",
                "Signer set's public shares do not match the threshold public key",
            )
        # First t shares honest, last one wrong, so a check interpolating only the first t accepts it.
        if t < n:
            self._append_sign_error(
                0,
                self.tplus1,
                self.tplus1[:-1] + [self.inputs.WRONG_PUBSHARE_IDX],
                0,
                0,
                self._agg(self.tplus1),
                COMMON_MSGS[0],
                "value",
                "Public share beyond the first t signers is inconsistent with the threshold public key",
            )
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
        self._append_sign_error(
            0,
            self.min_s,
            self.min_s,
            0,
            self.inputs.SECNONCE_ZERO_FIRST_IDX,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "value",
            "Secret nonce's first half is out of range (zero)",
        )
        # Shares absent for t >= 2, so the key check cannot mask a missing size check.
        below = list(range(t - 1))
        self._append_sign_error(
            0,
            below,
            None if t >= 2 else below,
            0,
            0,
            self.aggnonce_min,
            COMMON_MSGS[0],
            "value",
            "Fewer signers than the threshold t",
        )
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

    def add_verify_fail_tests(self) -> None:
        # Base partial signature: signer 0 over min2 (not min_s), since the wrong-signer case verifies at signer_index 1.
        secnonce = bytearray(self.inputs.pool_secnonces[0])
        signer_set = (
            self.n,
            self.t,
            self.min2,
            [self.inputs.pool_pubshares[i] for i in self.min2],
            self.thresh_pk,
        )
        session = SessionContext(
            *signer_set, self._agg(self.min2), [], [], COMMON_MSGS[0]
        )
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

    def add_verify_error_tests(self) -> None:
        # Base partial signature from position 0. Faults below sit at position 1.
        secnonce = bytearray(self.inputs.pool_secnonces[self.blame_s[0]])
        signer_set = (
            self.n,
            self.t,
            self.blame_s,
            [self.inputs.pool_pubshares[i] for i in self.blame_s],
            self.thresh_pk,
        )
        session = SessionContext(
            *signer_set, self._agg(self.blame_s), [], [], COMMON_MSGS[0]
        )
        psig = sign(
            secnonce,
            self.inputs.pool_secshares[self.blame_s[0]],
            self.blame_s[0],
            session,
        )

        pubnonce_indices_offcurve = [
            self.blame_s[0],
            self.inputs.INVALID_PUBNONCE_IDX,
        ] + self.blame_s[2:]
        self._append_verify_error(
            self.blame_s,
            self.blame_s,
            pubnonce_indices_offcurve,
            0,
            psig,
            "invalid_contrib",
            "Another signer's public nonce is invalid, so verification blames that signer, not the one being verified",
        )
        pubshare_indices_offcurve = [
            self.blame_s[0],
            self.inputs.INVALID_PUBSHARE_IDX,
        ] + self.blame_s[2:]
        self._append_verify_error(
            self.blame_s,
            pubshare_indices_offcurve,
            self.blame_s,
            0,
            psig,
            "value",
            "A public share is not a valid point",
        )

    def build(self) -> dict:
        self.add_valid_tests()
        self.add_sign_error_tests()
        self.add_verify_fail_tests()
        self.add_verify_error_tests()
        return self.group

    def build_n_bound(self) -> dict:
        # n = 129 is over the limit, so only the n-bound error case is built.
        s = [0, 1]
        self._append_sign_error(
            0,
            s,
            s,
            0,
            0,
            self._agg(s),
            COMMON_MSGS[0],
            "value",
            "Number of participants n exceeds the maximum of 128",
        )
        # A genuine partial signature at n = 128.
        pubshares = [self.inputs.pubshares[i] for i in s]
        session = SessionContext(
            MAX_PARTICIPANTS,
            self.t,
            s,
            pubshares,
            self.thresh_pk,
            self._agg(s),
            [],
            [],
            COMMON_MSGS[0],
        )
        psig = sign(
            bytearray(self.inputs.secnonces[0]), self.inputs.secshares[0], 0, session
        )
        self._append_verify_error(
            s,
            s,
            s,
            0,
            psig,
            "value",
            "Number of participants n exceeds the maximum of 128",
        )
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pubshares[:2])
        self.group["pubnonces"] = bytes_list_to_hex(self.inputs.pubnonces[:2])
        self.group["secshares"] = bytes_list_to_hex(self.inputs.secshares[:2])
        self.group["secnonces"] = bytes_list_to_hex(self.inputs.secnonces[:2])
        return self.group


def generate_sign_verify_vectors() -> None:
    groups = [SignVerifyGroupBuilder(cfg).build() for cfg in CONFIGS]
    groups.append(SignVerifyGroupBuilder(INVALID_CONFIG_2OF129).build_n_bound())
    assign_tc_ids(groups)
    write_test_vectors("sign_verify_vectors.json", {"test_groups": groups})
