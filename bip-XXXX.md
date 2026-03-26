```
  BIP: ?
  Layer: Peer Services
  Title: P2P UTXO Set Sharing
  Authors: Fabian Jahr <fjahr@protonmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  Discussion: ?
  License: BSD-2-Clause
```

## Abstract

This BIP defines a P2P protocol extension for sharing full UTXO sets between peers. It introduces
a new service bit `NODE_UTXO_SET`, four new P2P messages (`getutxosetinfo`, `utxosetinfo`, `getutxoset`,
`utxoset`), and a Merkle-tree-based integrity scheme that enables per-chunk verification. This allows
nodes to bootstrap from a recent height by obtaining the required UTXO set directly from the P2P network
via mechanisms such as assumeutxo.

## Motivation

The assumeutxo feature (implemented in Bitcoin Core) allows nodes to begin operating from a serialized
UTXO set while validating
historical blocks in the background. However, there is currently no canonical source for obtaining this
data. Users must either generate one themselves from a fully synced node (using `dumptxoutset` in 
Bitcoin Core), or download one from a third party.

By enabling UTXO set sharing over the P2P network, new nodes can obtain the data directly from
peers, removing the dependency on external infrastructure.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be
interpreted as described in RFC 2119.

### Service Bit

| Name | Bit | Description |
|------|-----|-------------|
| `NODE_UTXO_SET` | 12 (0x1000) | The node can serve complete UTXO set data for at least one height. |

A node MUST NOT set this bit unless it has at least one full UTXO set available to serve.
A node signaling `NODE_UTXO_SET` MUST respond to `getutxosetinfo` messages and MUST be capable of
serving all UTXO sets it advertises in its `utxosetinfo` response. A node that fails to meet these
obligations SHOULD be disconnected.

### Data Structures

#### Serialized UTXO Set

The serialized UTXO set uses the format established by the Bitcoin Core RPC `dumptxoutset` (as of PR #29612).

**Header (55 bytes):**

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `magic` | `bytes` | 5 | `0x7574786fff` (ASCII `utxo` + `0xff`). |
| `version` | `uint16_t` | 2 | Format version. |
| `network_magic` | `bytes` | 4 | Network message start bytes. |
| `base_height` | `uint32_t` | 4 | Block height of the UTXO set. |
| `base_blockhash` | `uint256` | 32 | Block hash of the UTXO set. |
| `coins_count` | `uint64_t` | 8 | Total number of coins (UTXOs) in the set. |

**Body (coin data):**

Coins are grouped by transaction hash. For each group:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `txid` | `uint256` | 32 | Transaction hash. |
| `num_coins` | `compact_size` | 1–9 | Number of outputs for this txid. |

For each coin in the group:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `vout_index` | `compact_size` | 1–9 | Output index. |
| `coin` | `Coin` | variable | Serialized coin (varint-encoded code for height/coinbase, then compressed txout). |

Coins are ordered lexicographically by outpoint (txid, then vout index), matching the LevelDB iteration
order of the coins database.

#### Chunk Merkle Tree

The serialized UTXO set (header + body) is split into chunks of exactly 3,900,000 bytes (3.9 MB). The
last chunk contains the remaining bytes and may be smaller.

The leaf hash for each chunk is `SHA256d(chunk_data)`. The tree is built as a balanced binary tree. When
the number of nodes at a level is odd, the last node is duplicated before hashing the next level.
Interior nodes are computed as `SHA256d(left_child || right_child)`.

The Merkle proof for chunk `i` consists of sibling hashes along the path from leaf to root. The
verifier derives the path direction from the chunk index: at each level, if the current index is even
the proof hash is the right sibling; if odd, the left sibling.

`SHA256d` denotes double-SHA256: `SHA256d(x) = SHA256(SHA256(x))`.

#### Serialized Hash

The serialized hash is the value that must match with a know value hash of the UTXO set at the respecitve
height. In Bitcoin Core, for example, the `hash_serialized` field is in the assumeutxo
parameters. It is computed by iterating over every coin in the set in lexicographic outpoint order and
feeding a serialized representation of each coin into a SHA256d hasher. The per-coin serialization is:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `outpoint` | `COutPoint` | 36 | Transaction hash (32 bytes) + output index (4 bytes, little-endian). |
| `code` | `uint32_t` | 4 | `(height << 1) \| coinbase_flag`, little-endian. `height` is the block height at which the coin was created. `coinbase_flag` is 1 if the coin originates from a coinbase transaction, 0 otherwise. |
| `txout` | `CTxOut` | variable | The transaction output: amount as `int64_t` (8 bytes, little-endian) followed by the scriptPubKey serialized with its `compact_size` length prefix. |

All coin serializations are fed sequentially into a single SHA256d hasher. The resulting 32-byte digest
is the serialized hash.

### Messages

#### `getutxosetinfo`

Sent to discover which UTXO sets a peer can serve. This message has an empty payload.

A node that has advertised `NODE_UTXO_SET` MUST respond with `utxosetinfo`. A node that has not
advertised the service bit SHOULD ignore this message.

#### `utxosetinfo`

Sent in response to `getutxosetinfo`. Lists available UTXO sets.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `count` | `compact_size` | 1–9 | Number of available UTXO sets. |

For each available UTXO set:

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `height` | `uint32_t` | 4 | Block height. |
| `block_hash` | `uint256` | 32 | Block hash at that height. |
| `serialized_hash` | `uint256` | 32 | The UTXO set serialized hash. |
| `data_length` | `uint64_t` | 8 | Total size of the serialized UTXO set in bytes (header + body). |
| `merkle_root` | `uint256` | 32 | Root of the Merkle tree computed over chunk hashes. |

A requesting node MUST ignore entries whose `serialized_hash` does not match a known
utxo set hash for the corresponding height.

#### `getutxoset`

Sent to request a single chunk of UTXO set data. The requesting node MUST have completed header sync
before sending this message.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `height` | `uint32_t` | 4 | Block height of the requested UTXO set. |
| `block_hash` | `uint256` | 32 | Block hash at the requested height. |
| `chunk_index` | `uint32_t` | 4 | Zero-based index of the requested chunk. |

If the serving node cannot fulfill the request, it MUST NOT respond. The requesting node SHOULD apply
a reasonable timeout and disconnect peers that fail to respond.

#### `utxoset`

Sent in response to `getutxoset`, delivering one chunk with its Merkle proof.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `height` | `uint32_t` | 4 | Block height this data corresponds to. |
| `block_hash` | `uint256` | 32 | Block hash this data corresponds to. |
| `chunk_index` | `uint32_t` | 4 | Zero-based index of this chunk. |
| `proof_length` | `compact_size` | 1–9 | Number of hashes in the Merkle proof. |
| `proof_hashes` | `uint256[]` | 32 × `proof_length` | Sibling hashes from leaf to root. |
| `data` | `bytes` | variable | Chunk payload, exactly 3.9 MB except for the last chunk. |

The transfer is receiver-driven: the requesting node sends one `getutxoset` per chunk. Chunks MAY be
requested in any order and from different peers, provided those peers advertised the same `merkle_root`
for the same height and block hash.

Upon receiving a `utxoset` message, the node MUST compute `SHA256d(data)` and verify it against the
`merkle_root` using the provided proof. If verification fails, the node MUST discard the chunk and
disconnect the peer. A node SHOULD also disconnect a peer that sends a `utxoset` message with fields
(`chunk_index`, `height`, `block_hash`) that do not match the outstanding request.

After all chunks have been received, the node MUST compute the serialized hash and compare it against a
known UTXO set hash. If this check fails, the node MUST discard all data and
SHOULD disconnect all peers that advertised the corresponding Merkle root.

### Protocol Flow

1. The requesting node identifies peers advertising `NODE_UTXO_SET`.
2. The requesting node sends `getutxosetinfo` to one or more of these peers.
3. Each peer responds with `utxosetinfo`. The requesting node verifies that the advertised
   `serialized_hash` matches a known UTXO set hash, compares `merkle_root` values across peers,
   and selects a UTXO set whose Merkle root has agreement among multiple peers.
4. The requesting node downloads chunks via `getutxoset`/`utxoset` exchanges, verifying each chunk
   against the Merkle root on receipt. On verification failure the peer is disconnected and download
   continues from another peer without losing already-verified chunks.
5. After all chunks are received, the node computes the full serialized hash and verifies it against
   the known UTXO set hash.

Serving nodes are free to limit the number of concurrent and repeated transfers per peer at their own
discretion to manage resource consumption.

## Rationale

**Usage of service bit 12:** Service bits allow selective peer discovery through
DNS seeds and addr relay. Bit 12 is chosen as the next unassigned bit after `NODE_P2P_V2` (bit 11, BIP 324).

**Serialized hash in `utxosetinfo`:** The requesting node should have access to a known UTXO set hash
before initiating the process. Including the serialized hash in the advertisement lets the requester
immediately filter out peers claiming a different UTXO set state before downloading any data.

**Discovery before download:** The `getutxosetinfo`/`utxosetinfo` exchange lets the requesting node
confirm availability, verify the serialized hash, and learn the Merkle root before committing to a large
transfer.

**Per-chunk Merkle verification:** In the Bitcoin P2P protocol, every larger piece of data received during
normal operation (blocks, transactions, compact block filters) can be verified independently before
requesting more. Without per-chunk verification, a UTXO set transfer would be an anomaly: ~10 GB (as of early 2026)
of data verifiable only after complete receipt. The Merkle tree enables incremental verifiability, allowing for
immediate detection of corrupt data, peer switching without data loss, and parallel download from
multiple peers. The overhead is minimal (~384 bytes of proof per 3.9 MB chunk). The specified
serialization is deterministic, so all honest nodes produce byte-identical output, guaranteeing Merkle
root agreement.

**3.9 MB chunk size:** The number balances round trips (~2,560 for a ~10 GB set) against memory usage
for buffering and verifying a single chunk. Smaller chunks would increase protocol overhead; larger
chunks would increase memory pressure on constrained devices commonly used to run Bitcoin nodes.
Together with the additional message overhead, the `utxoset` message including the chunk data also
sits just below the theoretical maximum block size which means any implementation should be able to
handle messages of this size.

**Reusing the `dumptxoutset` format:** Avoids introducing a new serialization format and ensures
compatibility with UTXO sets already being generated and shared.

**Relationship to BIP 64:** BIP 64 defined a protocol for querying individual UTXOs by outpoint and is
now closed. This BIP addresses a different use case: bulk transfer of the entire UTXO set for node
bootstrapping.

## Reference Implementation

[Bitcoin Core implementation pull request](https://github.com/bitcoin/bitcoin/pull/35054)

## Copyright

This BIP is made available under the terms of the 2-clause BSD license. See
https://opensource.org/license/BSD-2-Clause for more information.
