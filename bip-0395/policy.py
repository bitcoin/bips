#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Validate the construction grammar and collect its key references and internal path.

This parser does not validate Miniscript types or safety. Deep nesting may
exceed Python's recursion limit.
"""

from dataclasses import dataclass
import re

from bip32 import child_number


# An internal path contains child indexes, multipath tuples, and a final wildcard (None).
DerivationPath = tuple[int | tuple[int, ...] | None, ...]


@dataclass(frozen=True)
class ParsedPolicy:
    internal_path: DerivationPath
    key_indexes: frozenset[int]


class Parser:
    """Recursive-descent parser for the construction grammar only."""

    def __init__(self, text: str):
        if not text.isascii() or any(c.isspace() for c in text):
            raise ValueError("Templates must be ASCII without whitespace")
        self.text = text
        self.pos = 0
        self.key_indexes: set[int] = set()
        self.expansion_count: int | None = None

    def take(self, token: str) -> bool:
        if self.text.startswith(token, self.pos):
            self.pos += len(token)
            return True
        return False

    def expect(self, token: str) -> None:
        if not self.take(token):
            raise ValueError(f"Expected {token!r} at position {self.pos}")

    def match(self, pattern: str) -> str:
        match = re.match(pattern, self.text[self.pos:])
        if match is None:
            raise ValueError(f"Unexpected token at position {self.pos}")
        self.pos += match.end()
        return match[0]

    def index(self) -> None:
        self.expect("@")
        text = self.match(r"[0-9]+")
        if len(text) > 1 and text[0] == "0":
            raise ValueError("Key indexes must not have leading zeros")
        self.key_indexes.add(int(text))

    def child_index(self) -> int:
        return child_number(self.match(r"[0-9]+[h']?"))

    def path(self, internal: bool = False) -> DerivationPath:
        """Validate a suffix, retaining its steps when it belongs to the internal key."""
        steps = []
        while self.take("/"):
            if self.take("**"):
                steps.extend(((0, 1), None))
                break
            if self.take("*"):
                hardened = self.take("h") or self.take("'")
                if internal and hardened:
                    raise ValueError("The internal wildcard must be unhardened")
                steps.append(None)
                break
            if self.take("<"):
                values = [self.child_index()]
                self.expect(";")
                values.append(self.child_index())
                while self.take(";"):
                    values.append(self.child_index())
                self.expect(">")
                if len(set(values)) != len(values):
                    raise ValueError("Duplicate multipath alternative")
                steps.append(tuple(values))
            else:
                index = self.child_index()
                if internal and index >= 2**31:
                    raise ValueError("The internal path must be unhardened")
                steps.append(index)
        tuples = [step for step in steps if isinstance(step, tuple)]
        if len(tuples) > 1:
            raise ValueError("At most one multipath tuple per key")
        if tuples:
            count = len(tuples[0])
            if self.expansion_count is not None and self.expansion_count != count:
                raise ValueError("Multipath tuples must have equal lengths")
            self.expansion_count = count
        if internal:
            if not steps or steps[-1] is not None:
                raise ValueError("The internal path must end in /*")
            if tuples and tuples[0] != tuple(range(len(tuples[0]))):
                raise ValueError("The internal tuple must be <0;...;m-1>")
            return tuple(steps)
        return ()

    def key(self) -> None:
        if self.take("musig("):
            self.index()
            while self.take(","):
                self.index()
            self.expect(")")
        else:
            self.index()
        self.path()

    def fragment(self, whole_leaf: bool = False) -> None:
        wrapper = re.match(r"[ascdvjntlu]+:", self.text[self.pos:])
        if wrapper is not None:
            self.pos += wrapper.end()
            self.fragment()
            return
        if self.take("0") or self.take("1"):
            return
        op = self.match(r"[a-z][a-z0-9_]*")
        self.expect("(")
        if op in ("pk", "pkh", "pk_k", "pk_h"):
            self.key()
        elif op in ("older", "after"):
            self.match(r"[0-9]+")
        elif op in ("sha256", "hash256", "ripemd160", "hash160"):
            value = self.match(r"[0-9a-fA-F]+")
            if len(value) != (64 if op in ("sha256", "hash256") else 40):
                raise ValueError("Invalid hash length")
        elif op in ("multi_a", "sortedmulti_a", "thresh"):
            if op == "sortedmulti_a" and not whole_leaf:
                raise ValueError("sortedmulti_a must form a whole leaf")
            self.match(r"[0-9]+")
            self.expect(",")
            parse_arg = self.fragment if op == "thresh" else self.key
            parse_arg()
            while self.take(","):
                parse_arg()
        elif op in ("andor", "and_v", "and_b", "and_n", "or_b", "or_c", "or_d", "or_i"):
            self.fragment()
            for _ in range(2 if op == "andor" else 1):
                self.expect(",")
                self.fragment()
        else:
            raise ValueError(f"Unsupported fragment {op}")
        self.expect(")")

    def tree(self) -> None:
        if self.take("{"):
            self.tree()
            self.expect(",")
            self.tree()
            self.expect("}")
        else:
            self.fragment(whole_leaf=True)

    def parse(self) -> ParsedPolicy:
        self.expect("tr(_")
        internal_path = self.path(internal=True)
        self.expect(",")
        self.tree()
        self.expect(")")
        if self.pos != len(self.text):
            raise ValueError("Trailing template data")
        if self.expansion_count is not None and not any(isinstance(step, tuple) for step in internal_path):
            raise ValueError("The internal path must contain a multipath tuple")
        return ParsedPolicy(internal_path, frozenset(self.key_indexes))
