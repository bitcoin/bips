```
  BIP: ?
  Layer: Peer Services
  Title: Segregated Data (Peer Services)
  Authors: Mr Hash <hashamadeus@gmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: CC-BY-4.0
  Discussion: 2026-06-23: https://delvingbitcoin.org/t/bip-draft-segregated-data-a-prunable-script-isolated-block-region-for-data-carriage/2641
  Version: 0.1.1
  Requires: 144, 152, 339, ? (Segregated Data, Consensus layer)
```

## Abstract

This BIP defines how **Segregated Data (SegData)** *entries* propagate between *peers*. The consensus BIP places entries in a block-level `segdata` *region* committed via the coinbase and validates every block from its base serialisation alone, so no node needs the region to validate, at the tip or at any depth. Entry presence, integrity, and retention are therefore relay policy. This BIP specifies how entries travel bundled with their referencing transactions, how a block's region is reconstructed from held entries, how nodes serve recent entries and advertise deeper retention, and how a node opts out in part or in full.

## Glossary

The structural terms entry, reference, region, and commitment are used as defined in the companion consensus BIP. The terms below are specific to peer services.

**Coverage tier**: A coarse band of retention depth beyond the recent-block floor, configuring a peer to serve entries within that range.

**Entry-bearing relay**: Relay that carries SegData entries, bundled with their transactions and regions, as opposed to entry-stripped relay, which carries only the standard base serialisation.

**Recent-block floor**: The most recent 288 blocks, within which a SegData peer MUST retain and serve every **available** entry.

**Retention policy**: A node's local choice of how much history to keep and which entries to exclude, above the mandatory recent-block floor. It determines what the node can serve, and its depth is what the coverage tier advertises. The amount and exclusion controls are defined in the consensus BIP ([Prunability](bip-segdata.md#prunability), [Reference Implementation](bip-segdata.md#reference-implementation)), and this BIP standardises only the coverage signal, not their format.

**SegData peer**: A peer advertising either SegData service bit, and so able to relay and serve entries.

## Motivation

To enable prunability of SegData entries, a SegData *reference* output carries only a 4-byte marker and 32-byte hash of the entry. The transaction alone does not carry the bytes a block builder needs to populate `segdata`. Consensus never requires the region, but the network must move entries from originator to miners, and on to any node that opts to receive them.

SegData entries are deliberately outside transaction identity (see D2 below), which enables deduplication and per-entry retention but means the bytes do not travel with the transaction by construction.

## Key design decisions

### D1. Bundled delivery, not on-demand fetch

Entries MUST be relayed together with their referencing transaction in one message (`txent`, [Entry-bearing transaction relay](#entry-bearing-transaction-relay-txent)), not fetched separately after the fact.

*Rationale*: bundling means entries are held with their mempool transactions, so the `segdata` region can be reconstructed locally when a block arrives (see D6), as the mempool pre-populates compact-block transaction reconstruction. It also avoids any scenario where a reference arrives without its entry.

### D2. Entries are content-addressed and outside transaction identity

An entry is not in the preimage of the transaction's `txid` or `wtxid`. The consensus transaction contains only the reference hash, while the entry bytes are carried as a companion section keyed by the entry hash. A transaction's identity is identical whether or not its entries are attached.

*Rationale*: keeping entries out of identity preserves cross-transaction deduplication, enabling a single entry to be referenced by many transactions, matches the block-level aggregation model, avoids malleability, and makes stripping trivial.

### D3. Service bits

SegData capability is advertised with a service-bit pair mirroring [BIP-159](bip-0159.mediawiki) ([Service bits and negotiation](#service-bits-and-negotiation)). A peer advertising either is a SegData peer, and the bits are a discovery hint carried in `addr` gossip.

Entry-bearing relay is active only between two peers that have also exchanged the `sendsegdata` handshake ([Service bits and negotiation](#service-bits-and-negotiation)). Any other connection, to a peer advertising neither bit, or one where the handshake did not complete, carries entry-stripped relay, the standard base serialisation only.

A reference-bearing transaction SHOULD NOT be announced to a peer that has not negotiated entry relay, since that peer cannot accept it:

- An upgraded peer that has not negotiated rejects it for the stripped entry (D5).
- A legacy peer rejects the value-zero reference output as dust. Even with dust relaxed it would receive only an entry-less reference, which no node can mine without the entry (D5).

Every node validates every block from the base serialisation, so no node needs a SegData peer to stay in consensus. A node that wants to receive and relay the region maintains connectivity to SegData peers.

### D4. Receiving the region is default-on, never mandatory

The default policy is to receive and relay the region, so that data stays available and the node can serve and retain it. A node MAY decline mempool entry relay while still relaying ordinary transactions, MAY take new blocks base-only rather than extended, and MAY skip or prune historical entries per its retention policy, whose depth its coverage tier then advertises (D8). A node that receives no entries anywhere still tracks consensus exactly, differing only in what it can serve. Entry-stripped relay is the rule for pre-activation and non-negotiated peers, and the explicit choice for any peer.

The full opt-out is a single participation switch (for concreteness, a Bitcoin Core `permitsegdata=0`). In this case the node advertises neither service bit, negotiates no entry relay, takes base-only blocks, and retains nothing, so it holds and serves no entries while validating fully. This is independent of `blocksonly`, which governs mempool transaction relay in general. A node running `blocksonly` with SegData still permitted continues to take and serve block regions.

### D5. Mempool acceptance ties entry to reference

A node MUST hold and validate every referenced entry, each hashing to its reference, before accepting a transaction as minable, because a block builder needs every entry to assemble the complete region its commitment implies. A reference-bearing transaction arriving without its entries, from a non-negotiated peer or a deficient `txent`, is rejected rather than buffered (D1).

### D6. Block relay reconstructs `segdata` from held entries

The `segdata` region is not carried in a compact block. A node that takes the region reconstructs it locally from the entries held with its mempool transactions. Because entries are bundled with transactions (D5), a missing entry is a missing transaction, and the existing `getblocktxn` / `blocktxn` round trip returns both together in `txent` framing, so reconstruction needs no separate entry fetch. The `getsegdata` / `segdata` pair serves entries requested directly, for a node repopulating its region after a reorg or catching up its retained range, not for tip reconstruction.

### D7. Recent-block serving convention

For efficient propagation a SegData peer MUST retain and serve every *available* entry of every block within the most recent 288, the `NODE_SEGDATA_LIMITED` floor, keeping recent entries reliably available for nodes repopulating after a reorg or catching up across the recent range.

Serving is best-effort since a node cannot serve what it never received. A miner can mine a consensus-valid block while withholding or corrupting any part of its region, a whole region or a single entry, and because a region is served only whole ([Block relay](#block-relay-reconstruction-getsegdata-segdata)), one such entry that never enters relay leaves the entire region unassemblable for every peer alike (consensus BIP [Security Considerations](bip-segdata.md#security-considerations), withheld or corrupted region). A within-floor `notfound` for such a region is that data-availability event rather than a serving violation, recognised by every honest peer answering alike rather than one peer diverging from the rest. No per-entry exclusion applies inside the floor, mirroring the `NODE_NETWORK_LIMITED` convention of serving recent blocks whole.

A node unwilling to even hold a recent entry can opt out of SegData serving rather than dropping the entry. The retention policy begins beyond the floor (D8), so what a peer serves older than 288 depends on how much it has chosen to retain.

### D8. Coarse tier coverage advertising

Coverage beyond the recent-block floor is advertised in coarse tiers. The advertisement helps only the voluntary cases above that floor, such as a node choosing to retain and serve deep history, or an application fetching old entries. It lets them find a peer that retained the range rather than guess. Retention itself stays optional, and what a peer advertises must be honest, as BIP-159 requires for pruned block serving.

*Rationale*: Tiers are used rather than an exact height because a node's exact retention depth comes from a private storage amount, making it nearly unique to that node and stable over time. Coarse tiers put each node in a large anonymity set, and a node serves only to its advertised tier, so probing recovers the tier and no more ([Retention-coverage advertising](#retention-coverage-advertising-segdatacov)). Whether a specific entry is held is answered by the request itself (a `notfound` if absent, with no reason given).

## Specification

Wire constants below are proposed values pending assignment. The message formats, service bits, and negotiation handshake are normative and must match across implementations for interop. Policy mechanisms are named in Bitcoin Core terms for concreteness only.

### Service bits and negotiation

- **`NODE_SEGDATA`** = `(1 << 12)`: the peer relays SegData entries and serves the full `segdata` archive since activation. The guarantee is one of depth, the full range since activation, not of every individual entry. Per-entry exclusions are permitted and answered with `notfound`, and only systematic failure to serve within range forfeits the claim ([Retention-coverage advertising](#retention-coverage-advertising-segdatacov)). A node not covering the full range MUST NOT set the bit, the BIP-159 rule for `NODE_NETWORK`. Service bits travel in `addr` relay, so syncing nodes discover archival coverage before connecting.
- **`NODE_SEGDATA_LIMITED`** = `(1 << 13)`: the peer relays SegData entries and guarantees serving `segdata` for the most recent 288 blocks (D7). The direct analogue of `NODE_NETWORK_LIMITED`, with the same 288-block window and the same reorg-serving rationale. Nodes setting `NODE_SEGDATA` SHOULD also set `NODE_SEGDATA_LIMITED`, as archival nodes signal both BIP-159 bits today.

Both bits imply entry-relay capability. By default a node retains SegData for the blocks it stores, so a default-configured unpruned node is archival and sets both bits. A node retaining less sets only `NODE_SEGDATA_LIMITED` and advertises any intermediate coverage ([Retention-coverage advertising](#retention-coverage-advertising-segdatacov)). If a connection's advertised coverage states a tier lower than the bits imply, that coverage governs for the connection. Bits are discovery hints in `addr` gossip and may be stale, and the advertised coverage is the per-connection commitment.

- **`sendsegdata`**: an empty negotiation message sent between `version` and `verack`, following the [BIP-339](bip-0339.mediawiki) (`wtxidrelay`) pattern. A node sends it only to SegData peers (either bit) at a protocol version of 70017 or higher (proposed, pending assignment). Entry-bearing relay is active on a connection only when both sides have sent it. Otherwise the connection carries entry-stripped relay (D3). Sending `sendsegdata` after `verack` is a protocol violation.

### Inventory types

Following the [BIP-144](bip-0144.mediawiki) pattern of a witness flag bit on an existing inventory type, this BIP defines `MSG_SEGDATA_FLAG` = `(1 << 29)`:

- **`MSG_SEGDATA_TX`** = `MSG_WTX | MSG_SEGDATA_FLAG`: requests a transaction together with its entries.

On negotiated connections, a node requests all transactions with `MSG_SEGDATA_TX`. A `wtxid` announcement does not reveal whether the transaction carries references, and for a transaction without references the `txent` count is zero, costing one byte.

A node fetches a block's region separately from its base, for blocks whose region it wants, by default the recent-block floor and any deeper range it retains. The base comes from the existing `MSG_BLOCK` / `MSG_WITNESS_BLOCK` and the region from a whole-region `getsegdata` (`count` zero), the two issued in parallel and assembled locally. There is no combined extended-block message, so a peer that lacks the region never withholds the base, and a block whose extended serialisation exceeds the message limit needs no special path, since base and region always travel as separate messages each within the limit. The requester verifies any region it receives against the committed manifest ([Region validation](#region-validation)) and refetches on mismatch ([Retention-coverage advertising](#retention-coverage-advertising-segdatacov)).

### Region validation

A node that receives or reconstructs a block's `segdata` region validates it before relaying the region or building on the block. These are the relay-policy checks the consensus BIP defers to this document (consensus BIP [Validation rules](bip-segdata.md#validation-rules-consensus)). A region is accepted only if all hold:

1. Every entry referenced by the block's reference outputs is present, and each hashes under `tagged_hash("SegData/entry", ...)` to its committed leaf.
2. The region carries no entry that no reference output names.
3. The region is canonically ordered (consensus BIP [Canonical ordering](bip-segdata.md#canonical-ordering)) and canonically encoded, meaning each entry appears once, the `count` and every entry `length` use the minimal varint encoding, and no padding is present.
4. The region's serialised byte length equals the region length committed in the coinbase. The length is measured exactly as the consensus weight input (consensus BIP [Weight accounting](bip-segdata.md#weight-accounting)).

A region failing any check is rejected and not propagated, and the receiver refetches from another peer. None of these are consensus checks. A block whose region is absent or fails them stays valid from its base serialisation (consensus BIP [Uniform validation](bip-segdata.md#uniform-validation)), so a mismatch is a data-availability event on that connection, not a fork.

### Entry-bearing transaction relay: `txent`

Transactions are announced by `wtxid` exactly as today, and the entry bundle changes only the download. A `getdata(MSG_SEGDATA_TX)` is answered with a **`txent`** message:

```
txent = [tx][count: varint][entry_1]...[entry_n]
tx    = BIP-144 serialised transaction
entry = [length: varint][bytes: length]
```

Entries appear in reference-output order, deduplicated. `count` MUST equal the number of distinct entry hashes in the transaction's reference outputs, and each entry MUST hash (tagged) to one of them. A `txent` violating either is discarded, and the sending peer is misbehaving and MAY be disconnected. Per D2 the bundle does not alter `txid` or `wtxid`.

### Mempool acceptance

A node holds a reference-bearing transaction's entries bundled with it in the mempool, as `txent` delivers them, and MUST hold and validate every one, each against its reference hash, to accept the transaction as minable (D5). The entries count against `maxmempool` and are evicted with the transaction, so they add no resource beyond the mempool and no separate per-entry lifecycle.

In the mempool a node MAY hold a shared entry once or once per referencing transaction, the latter matching the full-attribution feerate below. Maximum entry size is relay policy. A node rejects a zero-length entry as nonstandard, since an empty entry carries no data yet still costs a reference output. This is relay policy rather than consensus because per-entry length lives in the region, not the base serialisation, so an empty entry a miner includes anyway is harmless and simply not relayed onward in the mempool.

For feerate, a transaction's weight includes the full `segdata` weight of every entry it references, even one shared with another mempool transaction. This over-estimates a shared entry (consensus counts it once per block) but never under-estimates, so feerate sorting, eviction, and RBF stay well-defined and conservative. `minrelaytxfee` applies to that full weight including the entry. Standardness checks the same attributed weight, so a reference-bearing transaction and the entries it pulls in are bounded by `MAX_STANDARD_TX_WEIGHT` like any other standard transaction. Block builders MAY refine with package-style accounting at template construction.

**Standardness.** A SegData reference output is exempt from the dust threshold, scoped to the exact reference encoding at value zero. The exemption is needed because rule 3 forces the output's value to zero, below the dust threshold, leaving references otherwise unrelayable by default. Rules 3 and 4 make the output unspendable, valueless, and never added to the UTXO set. Only the minimum-value check is waived. Fee gating is unchanged, and full-weight attribution keeps the transaction paying the relay floor on every byte it causes.

**Admission.** SegData adds no new mempool admission or exclusion policy. A reference-bearing transaction is relayed and mined under the discretion a node already applies to any transaction, and is admitted whole with all its entries held (D5) or rejected, never with individual entries excluded. Per-entry retention is a block-store choice made after validation (D8), not a mempool one.

A node accepts entry bytes from exactly three sources:

- a `txent` bundle passing mempool acceptance,
- a `blocktxn` response returning missing transactions in `txent` framing, and
- a `segdata` response to an outstanding `getsegdata`.

Unsolicited entries are discarded. Because entries arrive only bundled with or keyed to known references, no orphan-entry state exists, and the reference-without-entry state is likewise excluded by D1.

### Block relay: reconstruction, getsegdata, segdata

Compact blocks are unchanged on the wire and never carry entries. On SegData-negotiated connections, the `blocktxn` response to `getblocktxn` returns each missing transaction in `txent` framing (transaction plus its entries), the same per-negotiation serialisation variance [BIP-152](bip-0152.mediawiki) v2 already applies for witness.

This covers reconstruction because D5 ties entries to transactions. A node missing an entry is (aside from local eviction) missing the transaction that carries it, so one round trip resolves both with no separate entry request in the common path.

After reconstruction, the node derives the block's canonical entry list from its reference outputs and fills it from the entries held with those transactions. Reconstruction itself therefore needs no entry fetch. For entries a node needs directly, in reorg repopulation or catching up across its retained range, the **`getsegdata`** / **`segdata`** pair requests them by position:

```
getsegdata = [block_hash: 32-bytes][count: varint][index_1: varint]...[index_n: varint]
segdata    = [block_hash: 32-bytes][count: varint][entry_1]...[entry_n]
```

Indexes are positions in the block's canonical entry order, differentially encoded as in BIP-152 `getblocktxn`. A request with `count` zero carries no indexes and asks for the whole region, which the responder returns in canonical order. This is the common backfill case, so a full-region fetch is a 33-byte request rather than an enumeration of every index. The `segdata` response carries the requested entries in request order. Each received entry is verified against the entry hash at that canonical position before use.

A `segdata` response payload is the requested entries prefixed by the 32-byte block hash, so a full-region response is the block's region content plus that prefix. Consensus caps the committed region length at `MAX_BLOCK_WEIGHT` less that 32-byte prefix (consensus BIP validation rule 7), which stays within the message limit, so even a whole-region response fits one message.

Keying is by (block hash, index), not by entry hash. The requests it serves (reorg repopulation, catch-up) are anchored to a block, and hash-keyed fetching would reintroduce the speculative reference-without-entry fetch pattern D1 excludes.

A `getsegdata` response is all-or-nothing. Its entries sit positionally against the requested indexes, so an incomplete answer would misalign every entry after the first omission. A peer therefore returns the full requested set or `notfound`, according to its serving obligations, the recent-block floor (D7) and the advertised coverage tier beyond it ([Retention-coverage advertising](#retention-coverage-advertising-segdatacov)).

**Large blocks.** Base and region always travel as separate messages, each within the wire message limit. A block whose extended serialisation exceeds the limit at a sub-parity rate therefore needs no special path. Tip reconstruction from held mempool entries is unaffected, and a transaction a node lacks arrives in the existing `getblocktxn` round trip.

**Stall fallback.** A missing region never stalls the block itself. The base propagates and the tip advances from the base serialisation alone (D6), the same for negotiated and non-negotiated peers, so a stalling peer delays only a node's acquisition of the region, not its view of the chain. Region acquisition is multi-sourced, within the floor every SegData peer serves it (D7), so on a fetch timeout the node refetches from another. No single peer is ever the sole source.

Announcing a block implies being able to answer `getblocktxn` for it, which on SegData-negotiated links means `txent` framing, the transaction plus its entries, so an announcer holds the entries it received. Under BIP-152 an announcer that then refuses is misbehaving, except for an entry it never received, a region withheld or corrupted at mining, which no relaying peer can supply and every honest peer fails alike. Delay while the announcer is still validating is tolerated, as BIP-152 prescribes for high-bandwidth mode.

### Retention-coverage advertising: `segdatacov`

```
segdatacov = [tier: uint8]
```

Sent on SegData-negotiated connections after `verack`. MAY be re-sent when coverage changes, since a fixed storage amount holds a rolling, most-recent set of entries whose depth may shift as the chain grows and entry density varies:

| Tier | Coverage served |
|---|---|
| 0 | recent-block floor only (the D7 / `NODE_SEGDATA_LIMITED` guarantee, and the default) |
| 1 | most recent 4,320 blocks (~1 month) |
| 2 | most recent 52,560 blocks (~1 year) |
| 3 | full archive since activation (the `NODE_SEGDATA` guarantee) |

A tier commits the peer to answering `getsegdata` requests within its range with the data or an explicit `notfound`. Beyond the recent-block floor, per-entry exclusions answer `notfound`, and the message carries no reason, so exclusion, depth, and churn are indistinguishable on the wire. Within the floor a peer holds every entry relay delivered, so a `notfound` there is misbehaviour, aside from a brief delay while it is still validating a new block, or a region withheld or corrupted at mining that reached no peer (D7). A peer that systematically fails to serve within its advertised tier is misbehaving and MAY be disconnected, as with stalling block peers today.

Serving SHOULD align to the advertised tier. A node answers `notfound` beyond its tier even where it retains more, so the observable boundary equals the advertisement and probing recovers only the tier (D8). This is the counter-measure BIP-159 specifies for prune depth (a pruned node SHOULD NOT serve blocks deeper than its signalled threshold), applied to retention depth.

Requesters SHOULD apply a safety buffer of 144 blocks at the floor and tier boundaries, as BIP-159 prescribes for `NODE_NETWORK_LIMITED`. The boundary recedes as the chain advances and reorg handling consumes depth.

Serving beyond the recent-block floor counts against the same upload budget as historical block serving today (`maxuploadtarget`), so a node's total old-data upload stays bounded and advertising coverage gives an attacker no new way to drain its bandwidth.

### Initial block download

Headers-first sync is unchanged. A syncing node validates every block from the base serialisation, requested from any peer, at every depth, and never needs an entry or a SegData peer to complete or stay in sync. A node that wants to retain and serve the region requests each block's region (`getsegdata`) alongside its base for the range it keeps, by default the recent-block floor, from SegData peers, and that floor is exactly the range every SegData peer MUST serve (D7). Sync never depends on voluntary retention, regardless of how old the syncing software is.

A node choosing to retain deeper history SHOULD select peers whose advertised coverage spans the desired range, `NODE_SEGDATA` peers discovered via `addr` relay first, then `segdatacov` tiers sampled on connection. Retention of that range is voluntary (consensus BIP [Prunability](bip-segdata.md#prunability)), and the signal guarantees that whoever retained it is discoverable. If no peer can supply an entry, the node simply does not hold it, its validation unaffected since it never needed the region. Voluntary deeper retention never stalls sync.

### DoS bounds

- Entry weight: bounded per transaction by `MAX_STANDARD_TX_WEIGHT` on the attributed weight ([Mempool acceptance](#mempool-acceptance)) and in aggregate by `maxmempool`, with `minrelaytxfee` pricing every byte. These weight bounds cap total data and entry count together, since each entry needs a reference output, so fragmenting into smaller entries costs the same weight. A separate per-entry size limit would add no protection.
- `txent` bounds: `count` is bounded by the transaction's reference outputs, and oversized or mismatched bundles are protocol violations.
- `getsegdata` bounds: requests are answered only for known blocks. The recent-block serve obligation (D7) follows the BIP-159 precedent (a pruned node serves its most recent 288 blocks to any requester), not the announcement-gated `getblocktxn` rule, since it must answer for blocks the responder never announced (reorg repopulation, catch-up). As with recent-block serving today, the obligation coexists with per-peer rate limiting and abuse disconnection.
- Entry memory: counts against `maxmempool`, evicted with the referencing transaction ([Mempool acceptance](#mempool-acceptance)), and never accepted unsolicited.
- Coverage serving: beyond the recent-block floor, obligations are bounded by the advertised tier and by the historical-serving upload budget ([Retention-coverage advertising](#retention-coverage-advertising-segdatacov)). Within the floor, D7 applies.

## Consequences

1. **Mining.** Every miner validates blocks from the base serialisation, needing no entry to do so. To *include* a SegData-reference transaction in a block it mines, a miner must hold that transaction's entry before it confirms, which comes from the optional mempool entry-relay layer (D1). A miner not carrying that layer still mines, producing blocks without SegData transactions. Fees favour carrying it, so SegData-transaction mining concentrates negligibly among miners that do.

2. **Relay topology.** Every node relays base blocks, so chain propagation never partitions. The region, at the tip and in the mempool, flows over the SegData subgraph. That subgraph is default-on, so most upgraded nodes join it, and it must stay well-connected on its own, as the witness-relay overlay had to during the segwit rollout. A node opting out of mempool entry relay first sees reference-bearing transactions at block time. A node opting out of the region entirely still follows the chain from base blocks.

3. **Cost internalisation preserved at the layers that scale.** Tip reception of the region is the default but optional, and bounded per block. The costs that scale with data-carriage demand, long-term storage and historical IBD bandwidth, fall only on nodes that choose them. Storage beyond the recent-block floor is the operator's retention policy, and the historical archive is never pushed to a syncing node.

4. **Relay latency at parity with witness, bandwidth strictly cheaper.** SegData carries payload in a separate layer rather than witness. The common-path round-trip structure is identical to BIP-152 relay of the same payload (missing transactions return with their entries in the existing `getblocktxn` round trip), and the move is strictly cheaper on two axes. First, a block transfer carries a shared entry once however many transactions reference it, where witness embeds a copy per transaction. Second, entries a node does not retain are never downloaded during its IBD, where witness-embedded data rides every IBD permanently. The `getsegdata` path sits off this hot path, serving reorg repopulation and retained-range fetches during IBD or catch-up, where latency does not bind.

## Backward Compatibility

This BIP changes no consensus rules and breaks no existing peer behaviour:

- **Pre-activation and non-upgraded peers** never see a new message. They receive base-serialisation blocks exactly as today. Reference-bearing transactions are not announced to them (D3). Existing policy would reject the value-zero reference output as dust, and a transaction without its entries cannot be accepted onward.
- **Upgraded peers that do not negotiate** (neither service bit set, or `sendsegdata` not exchanged) likewise carry only existing message types. All new messages and inventory types are gated behind the negotiation, following the BIP-339 and BIP-152 deployment pattern.
- **Existing software** is unaffected. `txent`, `getsegdata`, and `segdata` are unknown messages only ever sent to peers that negotiated them, and the `MSG_SEGDATA_FLAG` inventory type is only used on negotiated connections.
- **Message sizes** need no change. The region is capped below the message limit (consensus BIP validation rule 7) and the base block is a separate message, so each stays within the existing 4 MB protocol message limit even when a sub-parity rate makes the extended serialisation exceed 4 MB in total.

No SegData peers are needed for consensus, since a node validates every block from the base serialisation. To receive and relay the region, which is the default, a node SHOULD maintain SegData peers, and implementations SHOULD preferentially peer with them during rollout.

## Reference Implementation

To be developed in the same implementation track as the companion consensus BIP, which also specifies the storage and RPC surface (consensus BIP [Reference Implementation](bip-segdata.md#reference-implementation)). The relay components required are:

- the negotiation handshake,
- the `txent` serialisation and its `blocktxn` framing variant,
- the `getsegdata` / `segdata` pair with the stall fallback,
- entry handling in the mempool (entries held bundled with their transactions),
- the dust-threshold exemption for reference outputs,
- coverage advertising with tier-aligned serving, and
- a single participation switch exposing the full opt-out (for concreteness, a `permitsegdata` setting, default 1), independent of `blocksonly`.

## Open questions

- **Hash-keyed entry retrieval.** Block-anchored retrieval (`getsegdata` by block hash and index, served per coverage tier) already covers sync, reorg, and application retrieval of any entry whose block the requester can locate, which is the normal case since the reference sits in a transaction in a known block. Deferred is fetching an entry by hash alone, independent of block context. It is left to a future BIP because hash-only fetching reintroduces the speculative reference-without-entry pattern D1 excludes unless separately bounded, and the protocol's own needs do not require it.

- **Coarse tier boundaries and count.** The four tiers (window, ~1 month, ~1 year, full archive) are a first cut. Finer tiers would help a node find a peer retaining the range it wants, but put fewer nodes in each tier, making retention depth easier to fingerprint. The chosen values balance discovery against that risk, and the right granularity is open.

## Copyright

This BIP is licensed under the Creative Commons Attribution 4.0 International License (CC-BY-4.0).

## Changelog

- 0.1.1 (2026-08-06): Preamble update.
- 0.1.0 (2026-07-24): Initial Draft.

## References

- [BIP-144](bip-0144.mediawiki) - Segregated Witness (Peer Services): transaction serialisation, inventory flag bit, stripped-relay model
- [BIP-152](bip-0152.mediawiki) - Compact Block Relay: reconstruction flow, `getblocktxn` / `blocktxn` precedent, differential index encoding
- [BIP-159](bip-0159.mediawiki) - NODE_NETWORK_LIMITED service bit: recent-block serving precedent for D7, and the signalling, honesty-rule, safety-buffer, and depth-fingerprinting counter-measure model for D8
- [BIP-339](bip-0339.mediawiki) - WTXID-based transaction relay: pre-`verack` negotiation pattern for `sendsegdata`
- Segregated Data (Consensus layer) - companion BIP: `segdata` region, uniform validation, weight accounting, canonical ordering
