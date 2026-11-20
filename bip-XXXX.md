```
  BIP: ?
  Layer: Peer Services
  Title: P2P UTXO Set Sharing
  Authors: Fabian Jahr <fjahr@protonmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Discussion: 2026-05-06: https://groups.google.com/g/bitcoindev/c/rThmyI8ZN3Q
  Version: 0.5.0
  Requires: 434
```

## Abstract

This BIP defines a P2P protocol extension for sharing full UTXO sets between peers. It introduces
a new service bit `NODE_UTXO_SET` advertising a deterministic schedule of served heights, four new
P2P messages (`getutxotree`, `utxotree`, `getutxoset`, `utxoset`) negotiated via a BIP 434 feature,
and a chunk-hash list anchored to a Merkle root known to the requesting node, enabling per-chunk
verification. This allows bootstrapping nodes to leapfrog to a recent height by obtaining the
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
| `NODE_UTXO_SET` | 14 (0x4000) | The node serves complete UTXO set data for the scheduled heights (see [Scheduled UTXO Set Heights](#scheduled-utxo-set-heights)). |

A node MUST NOT set this bit unless it can serve the UTXO sets at the scheduled heights defined below.
A node signaling `NODE_UTXO_SET` MUST be capable of responding to `getutxotree` and `getutxoset`
requests for the scheduled heights `H1` and `H2`, including the full chunk-hash list and every chunk of
those sets. It MAY additionally serve UTXO sets at other heights.

### Scheduled UTXO Set Heights

To make the `NODE_UTXO_SET` service bit meaningful for peer discovery, advertising nodes serve UTXO
sets at a deterministic schedule of block heights derived from the current tip. All heights refer to
blocks on the active most-work chain.

Let:

* `N` = height of the current chain tip
* `M = N - 2016` (the height as of approximately two weeks ago)
* `K = 14112` (7 difficulty adjustment periods, approximately three months)
* `H1 = M - (M mod K)` (the most recent multiple of `K` that is buried by at least 2016 blocks)
* `H2 = H1 - K` (the preceding multiple of `K`)

A node advertising `NODE_UTXO_SET` MUST be able to serve the UTXO sets at heights `H1` and `H2` as
computed from the current tip. Serving two consecutive scheduled heights guarantees an overlap
window: when a new height becomes `H1`, the previous one remains available as `H2`, so an in-progress
download is not interrupted.

The 2016-block offset ensures a height becomes scheduled only once it is buried by approximately two
weeks, which should make it safe from reorganization and gives serving nodes time to produce the
snapshot before it is requested.

### Feature Negotiation

Support for the messages in this document is negotiated per connection via the BIP 434 `feature`
message, using `featureid` `BIPXXXX` (TODO) and empty `featuredata`. A node implementing these
messages advertises this feature and MUST NOT send any of them to a peer that has not.

Advertising the feature indicates only that a node implements the protocol while `NODE_UTXO_SET`
indicates it additionally serves the scheduled heights. A node setting `NODE_UTXO_SET` MUST also
advertise the feature.

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
last chunk contains the remaining bytes and may be smaller. The chunks form the leaves of a binary
Merkle tree whose root commits to the entire UTXO set.

The leaf hash for each chunk is `SHA256d(chunk_data)`. The tree is built as a balanced binary tree. When
the number of nodes at a level is odd, the last node is promoted unchanged to the next level.
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
| `chunk_hashes` | `uint256[]` | 32 × N | The ordered list of N chunk hashes, where N = `ceil(data_length / 3,900,000)`. |

Upon receiving a `utxotree` message, the requesting node MUST recompute the Merkle root from
`chunk_hashes` and compare it against the Merkle root it knows for the corresponding UTXO set. If
the roots do not match, the node MUST discard the response and MUST disconnect the peer.

#### `getutxoset`

Sent to request a single chunk of UTXO set data. The requesting node MUST have received a `utxotree`
for the corresponding UTXO set (from any peer) before sending this message.

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
2. The requesting node sends `getutxotree` for the desired block hash to one of these peers, or to
   several peers to corroborate the Merkle root by agreement if no trusted root is available.
3. The peer or peers respond with `utxotree`. The requesting node verifies each response by
   recomputing the Merkle root and comparing it against a value it knows for the given UTXO set,
   either from a trusted source or from agreement among multiple peers. A single accepted `utxotree`
   can be used as the basis for all subsequent chunk requests for this UTXO set, regardless of
   which peer those chunks are fetched from.
4. The requesting node downloads chunks via `getutxoset`/`utxoset` exchanges, verifying each chunk
   against its entry in the accepted `utxotree` on receipt. On verification failure the peer is
   disconnected and download continues from another peer without losing already-verified chunks.
5. After all chunks are received, the node parses the reassembled UTXO set against the serialized
   UTXO set format to confirm that it is well-formed.

Serving nodes are free to limit the number of concurrent and repeated transfers per peer at their own
discretion to manage resource consumption.

## Rationale

**Usage of service bit 14:** Service bits allow selective peer discovery through
DNS seeds and addr relay. Bit 14 is chosen because bits 12 and 13 are reserved by the
Utreexo proposal (BIP 183 draft).

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

## Backwards Compatibility

This proposal is backward compatible. Peers that do not implement it ignore the new service bit
and never issue the new messages. Feature negotiation follows BIP 434, so peers that do not
recognize the feature ignore it.

## Reference Implementation

[Bitcoin Core implementation pull request](https://github.com/bitcoin/bitcoin/pull/35054)

## Acknowledgements

Thanks to Anthony Towns for suggesting that the requesting node fetch the full chunk-hash list up front
via the `getutxotree`/`utxotree` exchange rather than per-chunk Merkle proofs, using the Merkle root as
the sole trust anchor in place of a separate serialized hash, dropping the redundant `num_chunks` field,
and the deterministic schedule of served heights.

Thanks also to Murch for catching the service-bit collision with the Utreexo proposal, raising
the Merkle tree malleability concern behind promoting odd nodes unchanged rather than duplicating them,
and prompting the Backwards Compatibility section; stickies-v for raising the data-availability concern
that motivated a fixed schedule of served heights; Luke Dashjr for arguing against a separate discovery
step on privacy grounds and suggesting the serialization format version be carried; and Daniela Brozzoni
for helping make the peer-disconnection rules consistent.

## Copyright

This BIP is made available under the terms of the 2-clause BSD license. See
https://opensource.org/license/BSD-2-Clause for more information.

## Changelog

* __0.5.0__ (2026-06-03):
    * Defined a deterministic schedule of served heights for the `NODE_UTXO_SET` service bit
    * Added BIP 434 feature negotiation to signal support for the protocol messages
    * Added Acknowledgements section
* __0.4.0__ (2026-05-18):
    * Removed `num_chunks` from `utxotree`
* __0.3.0__ (2026-05-17):
    * Moved service bit from 12 to 14 to avoid collision with the Utreexo proposal (BIP 183 draft)
    * Changed Merkle tree construction: odd nodes are promoted unchanged rather than duplicated
* __0.2.0__ (2026-05-04):
    * Dropped discovery before download approach, instead request the chunk-hash list via `getutxotree`/`utxotree`
    * Dropped per-chunk Merkle proofs; chunks verified directly against the chunk-hash list
    * Dropped `height` from requests (`block_hash` is the sole identifier); added format `version` to `utxotree`
    * Dropped references to the serialized hash; the Merkle root is the sole integrity check
* __0.1.0__ (2026-04-10):
    * Initial draft
