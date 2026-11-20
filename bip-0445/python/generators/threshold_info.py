from typing import List, Optional

from frost_ref import PlainPk, ThresholdInfo, validate_threshold_info
from frost_ref.signing import (
    derive_interpolating_value,
    derive_thresh_pubkey,
)
from secp256k1lab.secp256k1 import G, GE

from generators.common import (
    INVALID_CONFIG_2OF129,
    CONFIGS,
    SharedGroupInputs,
    assign_tc_ids,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    get_subset,
    write_test_vectors,
)

# 33 zero bytes: an invalid encoding, not the point at infinity.
ZERO33 = b"\x00" * 33
# x = p + 1. A decoder reducing x mod p would lift x = 1 to a valid point.
X_GE_P = bytes.fromhex(
    "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
)


class ThresholdInfoGroupBuilder:
    """Builds one (t, n) test group for threshold_info_vectors.json."""

    def __init__(self, cfg):
        self.inputs = SharedGroupInputs(cfg)
        self.t = self.inputs.t
        self.n = self.inputs.n
        self.thresh_pk = self.inputs.thresh_pk
        self.full = get_subset(cfg, "full")
        self.points = [GE.from_bytes_compressed(p) for p in self.inputs.pubshares]

        # Shared pubshares pool with the two extra invalid encodings appended.
        self.pool_pubshares = list(self.inputs.pool_pubshares) + [ZERO33, X_GE_P]
        self.ZERO33_IDX = len(self.inputs.pool_pubshares)
        self.X_GE_P_IDX = self.ZERO33_IDX + 1
        # Two wrong shares for the last two ids whose errors cancel in the full set.
        if self.n - self.t >= 2:
            lam_a = derive_interpolating_value(self.full, self.n - 2)
            lam_b = derive_interpolating_value(self.full, self.n - 1)
            ca = self.points[-2] + G
            cb = self.points[-1] + (-(lam_a / lam_b)) * G
            cancel = self.points[:-2] + [ca, cb]
            assert derive_thresh_pubkey(self.full, cancel) == self.thresh_pk
            self.CANCEL_IDX = len(self.pool_pubshares)
            self.pool_pubshares += [ca.to_bytes_compressed(), cb.to_bytes_compressed()]

        self.group = {
            "tg_id": cfg.tg_id,
            "pubshares": bytes_list_to_hex(self.pool_pubshares),
            "valid_tests": [],
            "error_tests": [],
        }

    def _threshold_info(
        self, t: int, thresh_pk: bytes, pubshare_indices: List[Optional[int]]
    ) -> ThresholdInfo:
        pubshares = [
            None if i is None else PlainPk(self.pool_pubshares[i])
            for i in pubshare_indices
        ]
        return ThresholdInfo(t, PlainPk(thresh_pk), pubshares)

    def _append_valid(
        self, pubshare_indices: List[Optional[int]], comment: str
    ) -> None:
        validate_threshold_info(
            self._threshold_info(self.t, self.thresh_pk, pubshare_indices)
        )
        self.group["valid_tests"].append(
            {
                "comment": comment,
                "t": self.t,
                "thresh_pk": bytes_to_hex(self.thresh_pk),
                "pubshare_indices": pubshare_indices,
            }
        )

    def _append_error(
        self,
        t: int,
        thresh_pk: bytes,
        pubshare_indices: List[Optional[int]],
        comment: str,
    ) -> None:
        info = self._threshold_info(t, thresh_pk, pubshare_indices)
        err = expect_exception(lambda: validate_threshold_info(info), ValueError)
        self.group["error_tests"].append(
            {
                "comment": comment,
                "t": t,
                "thresh_pk": bytes_to_hex(thresh_pk),
                "pubshare_indices": pubshare_indices,
                "error": err,
            }
        )

    def add_valid_tests(self) -> None:
        t, n = self.t, self.n
        self._append_valid(self.full, "All public shares present")
        if t < n:
            absent: List[Optional[int]] = list(self.full)
            absent[t - 1] = None
            self._append_valid(absent, "One public share is absent")
        if n - t >= 2:
            self._append_valid(
                [None] + self.full[1 : t + 1] + [None] * (n - t - 1),
                "Exactly t public shares present, the first and last absent",
            )

    def add_error_tests(self) -> None:
        t, n = self.t, self.n
        pk = self.thresh_pk
        full = self.full

        # Parameter and encoding cases do not depend on (t, n), so only 2of3 has them.
        if t == 2 and n == 3:
            self._append_error(0, pk, full, "Threshold t is zero")
            self._append_error(
                n + 1, pk, full, "Threshold t exceeds the number of participants n"
            )
            self._append_error(
                t,
                pk,
                [],
                "Public share list is empty, so n = 0 and no threshold t can satisfy t <= n",
            )
            invalid_encodings = [
                (self.inputs.INVALID_PUBSHARE_IDX, "not a point on the curve"),
                (self.ZERO33_IDX, "all zeros"),
                (self.X_GE_P_IDX, "x-coordinate exceeds the field size"),
            ]
            for idx, name in invalid_encodings:
                self._append_error(
                    t,
                    self.pool_pubshares[idx],
                    full,
                    f"Threshold public key is invalid: {name}",
                )
            for idx, name in invalid_encodings:
                self._append_error(
                    t, pk, [0, 1, idx], f"A public share is invalid: {name}"
                )

        if n - t >= 2:
            self._append_error(
                t,
                pk,
                full[: t - 1] + [None] * (n - t + 1),
                "Fewer public shares present than the threshold t",
            )

        # The wrong share sits after the first t present shares.
        if t < n:
            self._append_error(
                t,
                pk,
                full[:t] + [self.inputs.WRONG_PUBSHARE_IDX] + full[t + 1 :],
                "Public share beyond the first t is not on the polynomial",
            )
        if n - t >= 2:
            self._append_error(
                t,
                pk,
                full[:-1] + [self.inputs.WRONG_PUBSHARE_IDX],
                "Last public share is not on the polynomial, so every share beyond the first t must be checked",
            )
            self._append_error(
                t,
                pk,
                full[:-2] + [self.CANCEL_IDX, self.CANCEL_IDX + 1],
                "Two wrong public shares cancel, so the full set still interpolates to the threshold public key",
            )

        # Exactly t shares present: a surplus share would fail the polynomial check first.
        if t >= 2:
            self._append_error(
                t,
                pk,
                full[: t - 1] + [self.inputs.INFINITY_PUBSHARE_IDX] + [None] * (n - t),
                "Public shares interpolate to the point at infinity",
            )

        neg = (-GE.from_bytes_compressed(pk)).to_bytes_compressed()
        self._append_error(
            t,
            neg,
            full,
            "Threshold public key is negated",
        )
        if t >= 2 and t < n:
            # A 1-based keygen's share at x lands at id x, one slot right of its 0-based id.
            assert derive_thresh_pubkey(full[1 : t + 1], self.points[:t]) != pk
            self._append_error(
                t,
                pk,
                [None] + full[:-1],
                "Public shares from a 1-based key generation, each shifted one id up",
            )
        if t >= 2:
            self._append_error(
                t,
                self.inputs.pubshares[0],
                full,
                "Threshold public key equals participant 0's public share",
            )

    def build(self) -> dict:
        self.add_valid_tests()
        self.add_error_tests()
        return self.group

    def build_n_bound(self) -> dict:
        # Only participants 0..2 are stored, the list length still gives n = 129.
        self._append_error(
            self.t,
            self.thresh_pk,
            [0, 1, 2] + [None] * (self.n - 3),
            "Number of participants n exceeds the maximum of 128",
        )
        self.group["pubshares"] = bytes_list_to_hex(self.inputs.pubshares[:3])
        return self.group


def generate_threshold_info_vectors() -> None:
    groups = [ThresholdInfoGroupBuilder(cfg).build() for cfg in CONFIGS]
    groups.append(ThresholdInfoGroupBuilder(INVALID_CONFIG_2OF129).build_n_bound())
    assign_tc_ids(groups)
    write_test_vectors("threshold_info_vectors.json", {"test_groups": groups})
