```
  BIP: ?
  Layer: Peer Services
  Title: P2P UTXO Set Sharing
  Authors: Fabian Jahr <fjahr@protonmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  Discussion: 2026-05-06: https://groups.google.com/g/bitcoindev/c/rThmyI8ZN3Q
  Version: 0.2.0
  License: BSD-2-Clause
```

## Abstract

This BIP defines a P2P protocol extension for sharing full UTXO sets between peers. It introduces
a new service bit `NODE_UTXO_SET`, four new P2P messages (`getutxotree`, `utxotree`, `getutxoset`,
`utxoset`), and a chunk-hash list anchored to a Merkle root known to the requesting node, enabling
per-chunk verification. This allows nodes to bootstrap from a recent height by obtaining the
required UTXO set directly from the P2P network via mechanisms such as assumeutxo.

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
A node signaling `NODE_UTXO_SET` MUST be capable of responding to `getutxotree` and `getutxoset`
requests for every UTXO set it is willing to serve, including the full chunk-hash list and every
chunk of those sets.

### Data Structures

#### Serialized UTXO Set

The serialized UTXO set uses the format established by the Bitcoin Core RPC `dumptxoutset` (as of Bitcoin Core v31).

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

The leaves are delivered to the node in a single `utxotree` response. A node that knows
the Merkle root for a given UTXO set checks a received list of leaves by recomputing the root and
comparing. The Merkle root is the sole trust input required to verify the integrity of the received UTXO set.

`SHA256d` denotes double-SHA256: `SHA256d(x) = SHA256(SHA256(x))`.

### Messages

#### `getutxotree`

Sent to request the chunk-hash list for a specific UTXO set.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `block_hash` | `uint256` | 32 | Block hash identifying the requested UTXO set. |

A node that has advertised `NODE_UTXO_SET` and can serve the requested UTXO set MUST respond with
`utxotree`. If the serving node cannot fulfill the request, it MUST NOT respond. The requesting
node SHOULD apply a reasonable timeout and try another peer.

#### `utxotree`

Sent in response to `getutxotree`, delivering the full chunk-hash list along with per-snapshot
metadata.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `block_hash` | `uint256` | 32 | Block hash this data corresponds to. |
| `version` | `uint16_t` | 2 | Format version of the serialized UTXO set. |
| `data_length` | `uint64_t` | 8 | Total size of the serialized UTXO set in bytes (header + body). |
| `num_chunks` | `compact_size` | 1–9 | Number of chunks the serialized UTXO set is split into. |
| `chunk_hashes` | `uint256[]` | 32 × `num_chunks` | The ordered list of chunk hashes. |

Upon receiving a `utxotree` message, the node MUST recompute the Merkle root from
`chunk_hashes` and compare it against the Merkle root it knows for the corresponding UTXO set. If
the roots do not match, the node MUST discard the response and MUST disconnect the peer.

#### `getutxoset`

Sent to request a single chunk of UTXO set data. The requesting node MUST have received a `utxotree`
for the corresponding UTXO set before sending this message.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `block_hash` | `uint256` | 32 | Block hash identifying the requested UTXO set. |
| `chunk_index` | `uint32_t` | 4 | Zero-based index of the requested chunk. |

If the serving node cannot fulfill the request, it MUST NOT respond. The requesting node SHOULD apply
a reasonable timeout and try another peer.

#### `utxoset`

Sent in response to `getutxoset`, delivering one chunk.

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `block_hash` | `uint256` | 32 | Block hash this data corresponds to. |
| `chunk_index` | `uint32_t` | 4 | Zero-based index of this chunk. |
| `data` | `bytes` | variable | Chunk payload, exactly 3.9 MB except for the last chunk. |

The transfer is receiver-driven: the requesting node sends one `getutxoset` per chunk. Chunks MAY be
requested in any order and from different peers.

Upon receiving a `utxoset` message, the node MUST compute `SHA256d(data)` and compare it against
`chunk_hashes[chunk_index]` from the `utxotree` it accepted for this UTXO set. If the hashes do not
match, the node MUST discard the chunk and MUST disconnect the peer. A node SHOULD also disconnect
a peer that sends a `utxoset` message with fields (`chunk_index`, `block_hash`) that do not match
the outstanding request.

After all chunks have been received, the node SHOULD parse the reassembled UTXO set against the
serialized UTXO set format to confirm it is well-formed.

### Protocol Flow

1. The requesting node identifies peers advertising `NODE_UTXO_SET`.
2. The requesting node sends `getutxotree` for the desired block hash to one or more of these peers.
3. Each peer responds with `utxotree`. The requesting node verifies the response by recomputing
   the Merkle root against a value it knows for the given UTXO set, either from a trusted source
   or by selecting a root with agreement among multiple peers.
4. The requesting node downloads chunks via `getutxoset`/`utxoset` exchanges, verifying each chunk
   against its entry in the accepted `utxotree` on receipt. On verification failure the peer is
   disconnected and download continues from another peer without losing already-verified chunks.
5. After all chunks are received, the node parses the reassembled UTXO set against the serialized
   UTXO set format to confirm that it is well-formed.

Serving nodes are free to limit the number of concurrent and repeated transfers per peer at their own
discretion to manage resource consumption.

## Rationale

**Usage of service bit 12:** Service bits allow selective peer discovery through
DNS seeds and addr relay. Bit 12 is chosen as the next unassigned bit after `NODE_P2P_V2` (bit 11, BIP 324).

**Direct request model:** Peers signal availability of UTXO sets via the `NODE_UTXO_SET`
service bit; the requesting node identifies the desired UTXO set by block hash when sending
`getutxotree`. The serving node responds only if it can serve that specific UTXO set.

**Per-chunk verification:** The chunk-hash list returned in `utxotree` enables each chunk to be verified
by direct lookup against the accepted list as it arrives, allowing immediate detection of corrupt data,
peer switching without data loss, and parallel download from multiple peers. The list itself is small
(~80 KB for a ~10 GB set). The specified serialization is deterministic, so all honest nodes produce
byte-identical output, guaranteeing Merkle root agreement.

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

## Changelog

* __0.2.0__ (2026-05-04):
    * Dropped discovery before download approach, instead request the chunk-hash list via `getutxotree`/`utxotree`
    * Dropped per-chunk Merkle proofs; chunks verified directly against the chunk-hash list
    * Dropped `height` from requests (`block_hash` is the sole identifier); added format `version` to `utxotree`
    * Dropped references to the serialized hash; the Merkle root is the sole integrity check
* __0.1.0__ (2026-04-10):
    * Initial draft
