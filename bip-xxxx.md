BIP: XXXX
Layer: Peer Services
Title: Optimal Batch Proofs for Utreexo
Author: Lucas Mateo Ruiz <ruizlucas2606@gmail.com>
Discussions-To: https://github.com/bitcoin/bips/issues/XXXX
Status: Draft
Type: Standards Track
Created: 2026-01-09
License: BSD-2-Clause
---

## Abstract

This BIP specifies a deterministic, canonical, and bandwidth-optimal batch proof format for Utreexo accumulator forests. By combining Merkle proof aggregation, canonical ordering, and bitmap-guided verification, the scheme minimizes proof size while preserving full verifiability, non-malleability, and deterministic encoding. The format applies to single trees as well as full Utreexo forests and is suitable for wallets, light clients, and constrained environments.

---

This proposal specifies a deterministic, canonical, and bandwidth-optimal batch proof format for Utreexo accumulator forests. By combining Merkle proof aggregation, canonical ordering, and bitmap-guided verification, the scheme minimizes proof size while preserving full verifiability and non-malleability. The format is applicable to single trees as well as full Utreexo forests and is suitable for wallets, light clients, and constrained environments.

## Motivation

Utreexo reduces the memory footprint of Bitcoin nodes by replacing the UTXO set with a Merkle accumulator. However, verifying multiple UTXO inclusions efficiently requires batching proofs without introducing ambiguity, malleability, or redundant bandwidth usage.

Naive batching of Merkle proofs duplicates sibling hashes and lacks canonical encoding, leading to unnecessary bandwidth overhead and multiple valid encodings for the same logical proof. Such ambiguity is undesirable for peer-to-peer protocols and light clients.

This BIP defines a batch proof construction with the following properties:

* **Deterministic:** identical inputs always produce identical proofs
* **Canonical:** there exists a single valid encoding per proof
* **Bandwidth-optimal:** no redundant hashes are transmitted
* **Streamable:** proofs can be verified sequentially

These properties make the scheme suitable for use in Utreexo-based systems without modifying Bitcoin consensus rules.

---

Utreexo reduces the memory footprint of Bitcoin nodes by replacing the UTXO set with a Merkle accumulator. However, naive inclusion proofs for multiple leaves incur redundant hashes and excessive bandwidth. Existing Merkle batching techniques lack either determinism, canonical encoding, or efficient streamability, making them unsuitable for consensus-adjacent use.

This BIP addresses these limitations by defining:

* A canonical ordering of proof elements
* Deduplication of shared Merkle paths
* A bitmap-driven hash-composition stream
* Independent batching per tree in a Utreexo forest

The result is a proof format that is minimal, deterministic, and resistant to malleability or adversarial reordering.

## Specification

### Notation

* `H(x)`: cryptographic hash function
* `||`: byte concatenation
* `bitmap[i]`: i-th bit of bitmap stream
* `hashes[j]`: j-th hash in canonical hash list

All integers are unsigned. All lists are consumed sequentially.

---

### Overview

For each Merkle tree in the Utreexo forest, a batch proof consists of:

* A list of target leaves
* A canonical list of sibling hashes
* A bitmap guiding hash combination order

Each tree is verified independently against its known root.

### Canonical Ordering

Sibling hashes are sorted by:

1. Tree height (ascending)
2. Position within the tree (left before right)

This ordering is deterministic and identical for all honest nodes.

### Bitmap Semantics

The bitmap is a bitstream consumed sequentially during verification:

* Bit = 0: H(current || next_hash)
* Bit = 1: H(next_hash || current)

The bitmap length equals the number of hash-composition steps required to reconstruct the root.

### Verification Algorithm (per tree)

1. Initialize a stack with the target leaves
2. Consume hashes and bitmap bits sequentially
3. Combine hashes according to bitmap direction
4. Repeat until a single root remains
5. Accept if the computed root equals the known tree root

Failure at any step invalidates the proof.

### Forest Verification

For a forest with k trees:

* Repeat the above procedure independently for each tree
* Proof elements MUST NOT be shared across trees

### Failure Modes

Verification MUST fail if:

* Bitmap bits are exhausted prematurely or remain unused
* Hashes are exhausted prematurely or remain unused
* The final root does not match the expected root

## Pseudocode

The following pseudocode is **normative**. All implementations MUST behave equivalently.

### VerifySingleTreeProof

```
function VerifySingleTreeProof(leaves, hashes, bitmap, expected_root):
    if leaves.length == 0:
        return FAIL

    stack ← copy(leaves)
    hash_index ← 0
    bit_index ← 0

    while stack.length > 1:
        if hash_index >= hashes.length or bit_index >= bitmap.length:
            return FAIL

        a ← pop_left(stack)
        b ← hashes[hash_index]

        if bitmap[bit_index] == 0:
            c ← H(a || b)
        else:
            c ← H(b || a)

        push_right(stack, c)

        hash_index ← hash_index + 1
        bit_index ← bit_index + 1

    if hash_index != hashes.length or bit_index != bitmap.length:
        return FAIL

    return stack[0] == expected_root
```

### VerifyForestBatchProof

```
function VerifyForestBatchProof(forest_proofs):
    for each tree_proof in forest_proofs:
        if VerifySingleTreeProof(
            tree_proof.leaves,
            tree_proof.hashes,
            tree_proof.bitmap,
            tree_proof.expected_root
        ) == FAIL:
            return FAIL

    return PASSED
```

---

## Security Considerations

* **Non-malleability:** Canonical ordering and bitmap-guided consumption prevent proof reordering.
* **Replay resistance:** Proof elements are scoped per tree.
* **DoS resistance:** Verification is linear in proof size with no adversarial backtracking.

## Reference Test Vectors

The following test vectors are normative. Implementations MUST reproduce the stated results exactly.

### Test Vector 1: Single Tree, Minimal Batch

* Tree height: 1
* Leaves: [5, 11]
* Canonical hashes: 3
* Bitmap: 101
* Expected result: PASSED

This vector validates basic batching, canonical ordering, and bitmap-guided verification.

### Test Vector 2: Single Tree, Deduplicated Paths

* Tree height: 3
* Leaves: [2, 5, 6]
* Canonical hashes: 5
* Bitmap length: 5
* Expected result: PASSED

This vector validates sibling deduplication and deterministic hash ordering.

### Test Vector 3: Edge Case — Single Leaf

* Tree height: arbitrary
* Leaves: [42]
* Canonical hashes: 0
* Bitmap length: 0
* Root = leaf hash
* Expected result: PASSED

This vector validates the degenerate case with no hash composition.

### Test Vector 4: Failure — Reordered Bitmap

* Same parameters as Test Vector 2
* Bitmap bits permuted
* Expected result: FAILED

This vector validates non-malleability and strict bitmap consumption.

### Test Vector 5: Forest Batch

* Forest size: 2 trees

Tree 0:

* Leaves: [3, 7]
* Canonical hashes: 4
* Bitmap length: 4
* Expected result: PASSED

Tree 1:

* Leaves: [1, 4, 6]
* Canonical hashes: 4
* Bitmap length: 4
* Expected result: PASSED

This vector validates independent batching and verification per tree in a Utreexo forest.

### Test Vector 6: Failure — Cross-Tree Replay

* Reuse one hash from Tree 0 proof in Tree 1
* Expected result: FAILED

This vector validates proof element scoping and replay resistance.

---

Implementations SHOULD include automated tests covering all vectors above.
