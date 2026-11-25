from pathlib import Path
import sys

# Add the vendored copy of secp256k1lab to path.
sys.path.append(str(Path(__file__).parent / "../secp256k1lab/src"))

from .signing import (
    # Functions
    validate_threshold_info,
    nonce_gen,
    nonce_agg,
    sign,
    deterministic_sign,
    partial_sig_verify,
    partial_sig_agg,
    tweak_ctx_init,
    apply_tweak,
    get_xonly_pk,
    get_plain_pk,
    # Constants
    MAX_PARTICIPANTS,
    # Exceptions
    InvalidContributionError,
    # Types
    PlainPk,
    XonlyPk,
    ThresholdInfo,
    TweakContext,
    SessionContext,
)

__all__ = [
    # Functions
    "validate_threshold_info",
    "nonce_gen",
    "nonce_agg",
    "sign",
    "deterministic_sign",
    "partial_sig_verify",
    "partial_sig_agg",
    "tweak_ctx_init",
    "apply_tweak",
    "get_xonly_pk",
    "get_plain_pk",
    # Constants
    "MAX_PARTICIPANTS",
    # Exceptions
    "InvalidContributionError",
    # Types
    "PlainPk",
    "XonlyPk",
    "ThresholdInfo",
    "TweakContext",
    "SessionContext",
]
