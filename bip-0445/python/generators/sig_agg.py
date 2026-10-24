from typing import List

from frost_ref import (
    InvalidContributionError,
    SessionContext,
    nonce_agg,
    partial_sig_agg,
    partial_sig_verify,
    sign,
)

from generators.common import (
    COMMON_MSGS,
    COMMON_TWEAKS,
    INVALID_CONFIG_2OF129,
    CONFIGS,
    GROUP_ORDER,
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


class SigAggGroupBuilder:
    """Builds one (t, n) test group for sig_agg_vectors.json.

    Index convention: set_indices selects the signing subset from the pool."""

    def __init__(self, cfg):
        self.inputs = SharedGroupInputs(cfg)
        self.t = self.inputs.t
        self.n = self.inputs.n
        self.thresh_pk = self.inputs.thresh_pk

        self.min_s = get_subset(cfg, "min")
        self.blame_s = swap_last_two(get_subset(cfg, "min2"))
        self.full = get_subset(cfg, "full")
        self.shifted = get_subset(cfg, "tplus1_shifted")

        self.group = {}
        set_group_config(self.group, cfg, self.inputs)
        # Faults are injected inline, so pools have no appended slots: plain n-length
        # pubshares and the 4 common tweaks.
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
        pubshares_absent: bool = False,
    ) -> bytes:
        # Absent pubshares drop every check that needs them: partial signature
        # verification, the session's key material check, and Sign's own secshare check.
        pubshares = (
            None
            if pubshares_absent
            else [self.inputs.pubshares[i] for i in set_indices]
        )
        pubnonces = [self.inputs.pubnonces[i] for i in set_indices]
        ids = list(set_indices)
        aggnonce = nonce_agg(pubnonces)
        tweaks = [COMMON_TWEAKS[i] for i in tweak_indices]
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(*signer_set, aggnonce, tweaks, is_xonly, msg)
        psigs = []
        for signer_index, signer_id in enumerate(set_indices):
            psig = sign(
                bytearray(self.inputs.secnonces[signer_id]),
                self.inputs.secshares[signer_id],
                signer_id,
                session,
            )
            psigs.append(psig)
            if pubshares is not None:
                verify_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
                assert partial_sig_verify(
                    psig, pubnonces, *verify_set, tweaks, is_xonly, msg, signer_index
                )
        expected = partial_sig_agg(psigs, session)
        self.group["valid_tests"].append(
            {
                "comment": comment,
                "ids": ids,
                "pubshare_indices": None if pubshares_absent else list(set_indices),
                "aggnonce": bytes_to_hex(aggnonce),
                "tweak_indices": tweak_indices,
                "is_xonly": is_xonly,
                "psigs": bytes_list_to_hex(psigs),
                "msg": bytes_to_hex(msg),
                "expected": bytes_to_hex(expected),
            }
        )
        return expected

    def _append_error(
        self, set_indices: List[int], fault: str, error: str, comment: str
    ) -> None:
        pubshares = [self.inputs.pubshares[i] for i in set_indices]
        pubnonces = [self.inputs.pubnonces[i] for i in set_indices]
        ids = list(set_indices)
        aggnonce = nonce_agg(pubnonces)
        msg = COMMON_MSGS[0]
        signer_set = (self.n, self.t, ids, pubshares, self.thresh_pk)
        session = SessionContext(*signer_set, aggnonce, [], [], msg)
        psigs = []
        for signer_index, signer_id in enumerate(set_indices):
            psig = sign(
                bytearray(self.inputs.secnonces[signer_id]),
                self.inputs.secshares[signer_id],
                signer_id,
                session,
            )
            psigs.append(psig)
            assert partial_sig_verify(
                psig, pubnonces, *signer_set, [], [], msg, signer_index
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

    def add_valid_tests(self) -> None:
        t, n = self.t, self.n
        sig_min = self._append_valid(
            self.min_s,
            [],
            [],
            COMMON_MSGS[0],
            "Minimum threshold subset of signers, no tweaks",
        )
        sig_no_pubshares = self._append_valid(
            self.min_s,
            [],
            [],
            COMMON_MSGS[0],
            "Aggregating without the public share list",
            pubshares_absent=True,
        )
        assert sig_no_pubshares == sig_min
        # Shifted subset, which excludes id 0 where possible.
        rev = list(reversed(self.shifted))
        self._append_valid(
            rev,
            [],
            [],
            COMMON_MSGS[0],
            "Signer set in descending order, so the identifiers must be sorted before hashing",
        )
        # The plain tweak makes tacc non-zero before the x-only steps.
        self._append_valid(
            self.min_s,
            [0, 1, 2],
            [False, True, True],
            COMMON_MSGS[0],
            "Aggregation with three tweaks applied (one plain, two x-only)",
        )
        # Dropped when t == n: the full set equals the minimum set, so the signature is identical.
        if t < n:
            self._append_valid(
                self.full,
                [],
                [],
                COMMON_MSGS[0],
                "All signers participate, no tweaks",
            )

    def add_error_tests(self) -> None:
        self._append_error(
            self.blame_s,
            "psig_out_of_range",
            "invalid_contrib",
            "Partial signature equals the group order, which is out of range",
        )
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

    def build_n_bound(self) -> dict:
        # n = 129 is over the limit, so only the n-bound error case is built.
        ids = [0, 1]
        pubshares = [self.inputs.pubshares[i] for i in ids]
        aggnonce = nonce_agg([self.inputs.pubnonces[i] for i in ids])
        msg = COMMON_MSGS[0]
        # Arbitrary psigs
        psigs = [
            bytes.fromhex(
                "DB7FA01593B00696E76E443A3EE6CDB11D4DC5E323A22589EFE23E01CAAB3673"
            ),
            bytes.fromhex(
                "2087409A1338F4821D24DAE225BD24D71BF0B8E6F6802379FAE72B78A1F9D73B"
            ),
        ]
        session = SessionContext(
            self.n, self.t, ids, pubshares, self.thresh_pk, aggnonce, [], [], msg
        )
        err = expect_exception(lambda: partial_sig_agg(psigs, session), ValueError)
        self.group["pubshares"] = bytes_list_to_hex(pubshares)
        self.group["tweaks"] = []
        self.group["error_tests"].append(
            {
                "comment": "Number of participants n exceeds the maximum of 128",
                "ids": ids,
                "pubshare_indices": ids,
                "aggnonce": bytes_to_hex(aggnonce),
                "tweak_indices": [],
                "is_xonly": [],
                "psigs": bytes_list_to_hex(psigs),
                "msg": bytes_to_hex(msg),
                "error": err,
            }
        )
        return self.group


def generate_sig_agg_vectors() -> None:
    groups = [SigAggGroupBuilder(cfg).build() for cfg in CONFIGS]
    groups.append(SigAggGroupBuilder(INVALID_CONFIG_2OF129).build_n_bound())
    assign_tc_ids(groups)
    write_test_vectors("sig_agg_vectors.json", {"test_groups": groups})
