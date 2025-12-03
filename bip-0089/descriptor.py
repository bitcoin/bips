"""Helpers for working with minimal SortedMulti descriptor templates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Mapping


@dataclass(frozen=True)
class SortedMultiDescriptorTemplate:
    """Minimal representation of a ``wsh(sortedmulti(m, ...))`` descriptor."""

    threshold: int

    def witness_script(self, tweaked_keys: Sequence[bytes]) -> bytes:
        """Return the witness script for ``wsh(sortedmulti(threshold, tweaked_keys))``."""

        if not tweaked_keys:
            raise ValueError("sortedmulti requires at least one key")
        if not 1 <= self.threshold <= len(tweaked_keys):
            raise ValueError("threshold must satisfy 1 <= m <= n")

        for key in tweaked_keys:
            if len(key) != 33:
                raise ValueError("sortedmulti keys must be 33-byte compressed pubkeys")

        sorted_keys = sorted(tweaked_keys)
        script = bytearray()
        script.append(_op_n(self.threshold))
        for key in sorted_keys:
            script.append(len(key))
            script.extend(key)
        script.append(_op_n(len(sorted_keys)))
        script.append(0xAE)  # OP_CHECKMULTISIG
        return bytes(script)

def _op_n(value: int) -> int:
    if not 0 <= value <= 16:
        raise ValueError("OP_N value out of range")
    if value == 0:
        return 0x00
    return 0x50 + value
