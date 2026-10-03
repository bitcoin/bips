from tree import *
from nested_musig2_exec import *
import random
import heapq

import sys
from pathlib import Path
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent.parent

sys.path.insert(0, str(PROJECT_ROOT))
from reference import *

MIN_NODES = 6
MAX_NODES = 15
EPOCHS = 3

def gen_tree(num_nodes: int) -> Node:
    if num_nodes <= 0:
        raise ValueError("num_nodes must be positive")

    if num_nodes == 1:
        return Node()

    # A labeled tree with n vertices corresponds to a Prüfer
    # sequence of length n - 2.
    prufer = [
        random.randrange(num_nodes)
        for _ in range(num_nodes - 2)
    ]

    root = random.choice(prufer) # select a node of degree greater than 1 as root

    # Initially every vertex has degree 1.
    degree = [1] * num_nodes

    for v in prufer:
        degree[v] += 1

    # Vertices of degree 1.
    leaves = [
        v for v in range(num_nodes)
        if degree[v] == 1
    ]
    heapq.heapify(leaves)

    # Undirected adjacency list.
    adj = [[] for _ in range(num_nodes)]

    # Decode the Prüfer sequence.
    for v in prufer:
        leaf = heapq.heappop(leaves)

        adj[leaf].append(v)
        adj[v].append(leaf)

        degree[leaf] -= 1
        degree[v] -= 1

        if degree[v] == 1:
            heapq.heappush(leaves, v)

    # Two vertices remain.
    u = heapq.heappop(leaves)
    v = heapq.heappop(leaves)

    adj[u].append(v)
    adj[v].append(u)

    def build_tree(node: Node, parent: Node = None) -> Node:
        node.children = [build_tree(Node(str(child)), node) for child in adj[int(node.value)] if parent == None or str(child) != parent.value]
        return node

    root = Node(str(root))
    root.is_root = True
    return build_tree(root)

for epoch in range(EPOCHS):
    num_nodes = random.randint(MIN_NODES, MAX_NODES)
    root = gen_tree(num_nodes)
    simulate_sign_test(root)
