#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Syntax trees, parsing, and printing for the construction grammar.

This parser does not validate Miniscript types or safety. Deep nesting may
exceed Python's recursion limit.
"""

from dataclasses import dataclass
import re
from typing import Callable

from bip32 import child_number


@dataclass(frozen=True)
class Step:
    kind: str
    values: tuple[str, ...]

    def render(self) -> str:
        if self.kind == "tuple":
            return "/<" + ";".join(self.values) + ">"
        return "/" + self.values[0]


@dataclass(frozen=True)
class Key:
    kind: str
    indexes: tuple[int, ...]
    path: tuple[Step, ...]

    def render(self, reference: Callable[[int], str]) -> str:
        if self.kind == "nums":
            text = "_"
        elif self.kind == "musig":
            text = "musig(" + ",".join(reference(i) for i in self.indexes) + ")"
        else:
            text = reference(self.indexes[0])
        suffix = "".join(step.render() for step in self.path)
        if suffix.endswith("/<0;1>/*"):
            suffix = suffix[:-len("/<0;1>/*")] + "/**"
        return text + suffix


@dataclass(frozen=True)
class Node:
    op: str
    args: tuple


class Parser:
    """Recursive-descent parser for the construction grammar only."""

    def __init__(self, text: str):
        if not text.isascii() or any(c.isspace() for c in text):
            raise ValueError("Templates must be ASCII without whitespace")
        self.text = text
        self.pos = 0

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

    def number(self) -> int:
        return int(self.match(r"[0-9]+"))

    def index(self) -> int:
        self.expect("@")
        text = self.match(r"[0-9]+")
        if len(text) > 1 and text[0] == "0":
            raise ValueError("Key indexes must not have leading zeros")
        return int(text)

    def step_value(self) -> str:
        text = self.match(r"[0-9]+[h']?")
        child_number(text)
        return str(int(text.rstrip("h'"))) + (text[-1] if text[-1] in "h'" else "")

    def path(self) -> tuple[Step, ...]:
        steps = []
        while self.take("/"):
            if self.take("**"):
                steps.extend((Step("tuple", ("0", "1")), Step("wildcard", ("*",))))
                break
            if self.take("*"):
                marker = self.match(r"[h']") if self.text[self.pos:self.pos+1] in ("h", "'") else ""
                steps.append(Step("wildcard", ("*" + marker,)))
                break
            if self.take("<"):
                values = [self.step_value()]
                self.expect(";")
                values.append(self.step_value())
                while self.take(";"):
                    values.append(self.step_value())
                self.expect(">")
                if len(set(map(child_number, values))) != len(values):
                    raise ValueError("Duplicate multipath alternative")
                steps.append(Step("tuple", tuple(values)))
            else:
                steps.append(Step("fixed", (self.step_value(),)))
        if sum(step.kind == "tuple" for step in steps) > 1:
            raise ValueError("At most one multipath tuple per key")
        return tuple(steps)

    def key(self, internal: bool = False) -> Key:
        if internal:
            self.expect("_")
            return Key("nums", (), self.path())
        if self.take("musig("):
            indexes = [self.index()]
            while self.take(","):
                indexes.append(self.index())
            self.expect(")")
            return Key("musig", tuple(indexes), self.path())
        return Key("single", (self.index(),), self.path())

    def fragment(self, whole_leaf: bool = False) -> Node:
        wrapper = re.match(r"[ascdvjntlu]+:", self.text[self.pos:])
        if wrapper is not None:
            self.pos += wrapper.end()
            node = self.fragment()
            for char in reversed(wrapper[0][:-1]):
                node = Node(char + ":", (node,))
            return node
        if self.take("0"):
            return Node("0", ())
        if self.take("1"):
            return Node("1", ())
        op = self.match(r"[a-z][a-z0-9_]*")
        self.expect("(")
        if op in ("pk", "pkh", "pk_k", "pk_h"):
            args = (self.key(),)
        elif op in ("older", "after"):
            args = (self.number(),)
        elif op in ("sha256", "hash256", "ripemd160", "hash160"):
            value = self.match(r"[0-9a-fA-F]+")
            if len(value) != (64 if op in ("sha256", "hash256") else 40):
                raise ValueError("Invalid hash length")
            args = (value.lower(),)
        elif op in ("multi_a", "sortedmulti_a", "thresh"):
            if op == "sortedmulti_a" and not whole_leaf:
                raise ValueError("sortedmulti_a must form a whole leaf")
            args_list = [self.number()]
            self.expect(",")
            parse_arg = self.fragment if op == "thresh" else self.key
            args_list.append(parse_arg())
            while self.take(","):
                args_list.append(parse_arg())
            args = tuple(args_list)
        elif op in ("andor", "and_v", "and_b", "and_n", "or_b", "or_c", "or_d", "or_i"):
            args_list = [self.fragment()]
            for _ in range(2 if op == "andor" else 1):
                self.expect(",")
                args_list.append(self.fragment())
            args = tuple(args_list)
        else:
            raise ValueError(f"Unsupported fragment {op}")
        self.expect(")")
        return Node(op, args)

    def tree(self) -> Node:
        if self.take("{"):
            left = self.tree()
            self.expect(",")
            right = self.tree()
            self.expect("}")
            return Node("branch", (left, right))
        return self.fragment(whole_leaf=True)

    def parse(self) -> Node:
        self.expect("tr(")
        internal = self.key(internal=True)
        self.expect(",")
        tree = self.tree()
        self.expect(")")
        if self.pos != len(self.text):
            raise ValueError("Trailing template data")
        root = Node("tr", (internal, tree))
        return root


def keys(node: Node | Key):
    if isinstance(node, Key):
        yield node
    elif isinstance(node, Node):
        for arg in node.args:
            yield from keys(arg)


def render(node, reference: Callable[[int], str]) -> str:
    if isinstance(node, Key):
        return node.render(reference)
    if not isinstance(node, Node):
        return str(node)
    if node.op.endswith(":"):
        wrappers = ""
        while isinstance(node, Node) and node.op.endswith(":"):
            wrappers += node.op[0]
            node = node.args[0]
        return wrappers + ":" + render(node, reference)
    if node.op in ("0", "1"):
        return node.op
    contents = ",".join(render(arg, reference) for arg in node.args)
    return "{" + contents + "}" if node.op == "branch" else node.op + "(" + contents + ")"
