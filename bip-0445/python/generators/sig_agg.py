from typing import List

from frost_ref import (
    InvalidContributionError,
    SessionContext,
    SignersContext,
    nonce_agg,
    partial_sig_agg,
    partial_sig_verify,
    sign,
)

from generators.common import (
    COMMON_MSGS,
    COMMON_TWEAKS,
    CONFIGS,
    GROUP_ORDER,
    SharedGroupInputs,
    assign_tc_ids,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    get_subset,
    set_group_config,
    write_test_vectors,
)


class SigAggGroupBuilder:
    """Builds one (t, n) test group for sig_agg_vectors.json. Shared inputs and
    subsets live on self. Each add_* method appends its category to self.group.

    Index convention: set_indices selects the signing subset from the pool (sig_agg
    has no per-signer my_id material convention and no appended fault slots)."""

    def __init__(self, cfg):
        self.inputs = SharedGroupInputs(cfg)
        self.t = self.inputs.t
        self.n = self.inputs.n
        self.thresh_pk = self.inputs.thresh_pk

        self.min_s = get_subset(cfg, "min")
        self.full = get_subset(cfg, "full")

        self.group = {}
        set_group_config(self.group, cfg, self.inputs)
        # sig_agg has no appended fault slots in any pool (both error faults are
        # injected inline), so the group serializes and reads the plain n-length
        # pubshares and the 4 common tweaks, not the SharedGroupInputs pool_* arrays.
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pubshares)
        self.group["tweaks"] = bytes_list_to_hex(COMMON_TWEAKS)
        self.group["valid_tests"] = []
        self.group["error_tests"] = []

    def _append_valid(
        self,
        set_indices: List[int],
        tweak_indices: List[int],
        is_xonly: List[bool],
        msg: bytes,
        comment: str,
    ) -> None:
        pubshares = [self.inputs.pubshares[i] for i in set_indices]
        pubnonces = [self.inputs.pubnonces[i] for i in set_indices]
        ids = list(set_indices)
        aggnonce = nonce_agg(pubnonces)
        tweaks = [COMMON_TWEAKS[i] for i in tweak_indices]
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(aggnonce, signers, tweaks, is_xonly, msg)
        psigs = []
        for signer_index, my_id in enumerate(set_indices):
            psig = sign(
                bytearray(self.inputs.secnonces[my_id]),
                self.inputs.secshares[my_id],
                my_id,
                session,
            )
            psigs.append(psig)
            assert partial_sig_verify(
                psig, pubnonces, signers, tweaks, is_xonly, msg, signer_index
            )
        expected = partial_sig_agg(psigs, session)
        self.group["valid_tests"].append(
            {
                "comment": comment,
                "ids": ids,
                "pubshare_indices": list(set_indices),
                "aggnonce": bytes_to_hex(aggnonce),
                "tweak_indices": tweak_indices,
                "is_xonly": is_xonly,
                "psigs": bytes_list_to_hex(psigs),
                "msg": bytes_to_hex(msg),
                "expected": bytes_to_hex(expected),
            }
        )

    def _append_error(
        self, set_indices: List[int], fault: str, error: str, comment: str
    ) -> None:
        pubshares = [self.inputs.pubshares[i] for i in set_indices]
        pubnonces = [self.inputs.pubnonces[i] for i in set_indices]
        ids = list(set_indices)
        aggnonce = nonce_agg(pubnonces)
        msg = COMMON_MSGS[0]
        signers = SignersContext(self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(aggnonce, signers, [], [], msg)
        psigs = []
        for signer_index, my_id in enumerate(set_indices):
            psig = sign(
                bytearray(self.inputs.secnonces[my_id]),
                self.inputs.secshares[my_id],
                my_id,
                session,
            )
            psigs.append(psig)
            assert partial_sig_verify(
                psig, pubnonces, signers, [], [], msg, signer_index
            )

        if fault == "psig_out_of_range":
            psigs[-1] = GROUP_ORDER
        elif fault == "psig_count_mismatch":
            psigs = psigs[:-1]

        expected_exc = ValueError if error == "value" else InvalidContributionError
        err = expect_exception(lambda: partial_sig_agg(psigs, session), expected_exc)
        self.group["error_tests"].append(
            {
                "comment": comment,
                "ids": ids,
                "pubshare_indices": list(set_indices),
                "aggnonce": bytes_to_hex(aggnonce),
                "tweak_indices": [],
                "is_xonly": [],
                "psigs": bytes_list_to_hex(psigs),
                "msg": bytes_to_hex(msg),
                "error": err,
            }
        )

    # --- Array A: valid_tests ---

    def add_valid_tests(self) -> None:
        t, n = self.t, self.n
        # Minimum threshold subset.
        self._append_valid(
            self.min_s,
            [],
            [],
            COMMON_MSGS[0],
            "Minimum threshold subset of signers, no tweaks",
        )
        # Order-invariance (needs a set of size >= 2 to be meaningful).
        if t >= 2:
            rev = list(reversed(self.min_s))
            self._append_valid(
                rev,
                [],
                [],
                COMMON_MSGS[0],
                "Reordering the signer set leaves the aggregate signature unchanged, because the partial signatures are summed and the identifiers are sorted before they are bound into the binding value",
            )
        # Three tweaks applied (one x-only, two plain).
        self._append_valid(
            self.min_s,
            [0, 1, 2],
            [True, False, False],
            COMMON_MSGS[0],
            "Aggregation with three tweaks applied (one x-only, two plain)",
        )
        # All n signers participate (dropped when t == n, as the all-n set
        # equals the minimum set and partial_sig_agg has no my_id field, so the
        # aggregate signature would be byte-identical to the minimum-subset case).
        if t < n:
            self._append_valid(
                self.full,
                [],
                [],
                COMMON_MSGS[0],
                "All signers participate, no tweaks",
            )

    # --- Array B: error_tests ---

    def add_error_tests(self) -> None:
        # Partial signature equals the group order (out-of-range scalar).
        self._append_error(
            self.min_s,
            "psig_out_of_range",
            "invalid_contrib",
            "Partial signature equals the group order, which is out of range",
        )
        # Number of partial signatures does not match the number of signers.
        self._append_error(
            self.min_s,
            "psig_count_mismatch",
            "value",
            "Number of partial signatures does not match the number of signers",
        )

    def build(self) -> dict:
        self.add_valid_tests()
        self.add_error_tests()
        return self.group


def generate_sig_agg_vectors() -> None:
    groups = [SigAggGroupBuilder(cfg).build() for cfg in CONFIGS]
    assign_tc_ids(groups)
    write_test_vectors("sig_agg_vectors.json", {"test_groups": groups})
