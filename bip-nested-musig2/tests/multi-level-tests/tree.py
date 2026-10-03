from dataclasses import dataclass, field, fields

import sys
from pathlib import Path
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent.parent

sys.path.insert(0, str(PROJECT_ROOT))
from reference import KeyAggContext, PlainPk


@dataclass
class Node:
    value: str
    is_root: bool = False
    children: list["Node"] = field(default_factory=list)
    sk: bytes = None # leaf secret key
    pk: PlainPk = None # leaf pub key
    keyagg_ctx: KeyAggContext = None # aggregate key incase the node is an aggregator
    out: bytes = None # leaf pubnonce or aggnonce_ext
    state: bytearray = None # leaf secnonce
    out_internal: bytes = None # aggnonce
    out_: bytes = None # partial signature
    state_: bytes = None # final nonce R

    def is_leaf(self) -> bool:
        return len(self.children) == 0

    def walk(self, path: str = "root"):
        """Yield (occurrence path, node) in preorder, including this node.

        Sibling labels must be unique; repeated keys can use labels A1, A2, etc.
        """
        yield path, self
        labels = [child.value for child in self.children]
        if len(set(labels)) != len(labels) or any('/' in label for label in labels):
            raise ValueError('Tree paths require unique sibling labels without slashes')
        for child in self.children:
            yield from child.walk(f"{path}/{child.value}")


def parse_forest(dsl: str, root_name: str = "ROOT") -> Node:
    """
    Examples:
      A,B,C
      A(B,C),D,E(F)
    """
    s = "".join(dsl.split())
    i = 0

    def parse_node() -> Node:
        nonlocal i

        start = i
        while i < len(s) and s[i] not in "(),":
            i += 1

        if start == i:
            raise ValueError(f"Expected node value at position {i}")

        node = Node(s[start:i])

        if i < len(s) and s[i] == "(":
            i += 1

            while True:
                node.children.append(parse_node())

                if i >= len(s):
                    raise ValueError("Missing closing ')'")

                if s[i] == ",":
                    i += 1
                elif s[i] == ")":
                    i += 1
                    break
                else:
                    raise ValueError(f"Unexpected character {s[i]!r} at {i}")

        return node

    root = Node(root_name)
    root.is_root = True

    while i < len(s):
        root.children.append(parse_node())

        if i < len(s):
            if s[i] == ",":
                i += 1
            else:
                raise ValueError(f"Unexpected character {s[i]!r} at {i}")

    return root


def print_tree(node: Node, prefix: str = "", is_last: bool = True) -> None:
    connector = "└── " if is_last else "├── "
    # print(prefix + connector + node.pk.hex().upper())
    print(prefix + connector + node.value)

    child_prefix = prefix + ("    " if is_last else "│   ")

    for index, child in enumerate(node.children):
        print_tree(child, child_prefix, index == len(node.children) - 1)

def print_tree_detailed(self, prefix: str = "", is_last: bool = True) -> None:
        """Pretty-print the tree structure with all fields of each node."""
        branch = "└── " if is_last else "├── "
        print(prefix + branch + f"Node(value={self.value!r})")

        # Print all fields except children
        field_prefix = prefix + ("    " if is_last else "│   ")
        for f in fields(self):
            if f.name == "children":
                continue
            val = getattr(self, f.name)
            print(f"{field_prefix}{f.name}: {val!r}")

        # Print children
        for i, child in enumerate(self.children):
            print_tree_detailed(
                child,
                prefix=field_prefix,
                is_last=(i == len(self.children) - 1),
            )

# # Example
# root = parse_forest("A(B(D,E),C),X,Y(Z)")
# print_tree(root)
# root = parse_forest("Abby(Alice,Bob),Carol", root_name="Alberic") # Example in the paper
# print_tree(root)
