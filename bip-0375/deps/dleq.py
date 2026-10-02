#!/usr/bin/env python3
"""
Import/re-export BIP-374 DLEQ functions from bip-0374/reference.py
for proof generation and verification.

Used by the BIP-375 validator for PSBT_GLOBAL_SP_DLEQ / PSBT_IN_SP_DLEQ.
"""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

_REFERENCE = Path(__file__).resolve().parents[2] / "bip-0374" / "reference.py"
if not _REFERENCE.is_file():
    raise ImportError(
        f"BIP-374 reference not found at {_REFERENCE}. "
        "Run the BIP-375 tests from a full bips checkout."
    )

_spec = spec_from_file_location("bip0374_reference", _REFERENCE)
_mod = module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_mod)

dleq_challenge = _mod.dleq_challenge
dleq_generate_proof = _mod.dleq_generate_proof
dleq_verify_proof = _mod.dleq_verify_proof

__all__ = [
    "dleq_challenge",
    "dleq_generate_proof",
    "dleq_verify_proof",
]
