```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: Segregated Data (Consensus layer)
  Author: Mr Hash <hashamadeus@gmail.com>
  Status: Draft
  Type: Standards Track
  Created: 2026-07-24
  License: BSD-3-Clause
           OPL
  Requires: 8, 141, 144, 340
```

## Abstract

This BIP defines a new soft-fork-activated block *region*, **Segregated Data (SegData)**, dedicated to carrying script-isolated data *entries* outside the transaction and witness structures. A coinbase output commits to a Merkle root of the entry hashes and the region's total byte length. Consensus checks only that the *commitment* matches the *references* the transactions declare, and that the block's weight, including the SegData region, is within the limit. No node needs the region itself to validate, so its presence, integrity, and availability are relay policy, and an operator may decline or discard it in part or in full at any depth while the commitment stays permanent, placing the data burden on those who choose to retain it rather than on all.

## Glossary

**Arbitrary data**: Bytes placed on-chain for their content rather than to authorise or define a transfer of value.

**Commitment**: A coinbase output which commits to the Merkle root of all entry hashes and the total length of the SegData region.

**Entry**: A payload of arbitrary bytes carried in the SegData region, identified by its tagged entry hash.

**Reference**: A transaction output which carries a specific entry hash.

**Region**: The extended serialisation region of a block which contains deduplicated SegData entries.

## Motivation

This BIP establishes a region through which a user can explicitly declare an intent to carry *arbitrary data*. Bitcoin currently carries such data through several vectors, none of them purpose-built:

1. **OP_RETURN tail bytes.** Retained by every non-pruned node at the full transaction weight.
2. **Witness fields.** Retained by every non-pruned node at the witness discount.
3. **Vanity P2PKH / P2SH addresses.** Bytes encoded in the address hash, occupying a UTXO-set entry on every node indefinitely.
4. **Bare multisig outputs.** Bytes substituted for the public keys of non-P2SH multisig, occupying a UTXO-set entry on every node indefinitely, at more bytes per output than an address hash.
5. **Script opcodes.** Bytes encoded as the opcode sequence of an executing script rather than as pushed data, retained by every non-pruned node and executed on validation.

Because it shares the same structures as monetary data, every node receives, validates, and retains arbitrary data on the same terms, so storage and IBD bandwidth scale with total data-carriage demand for all alike.

Such carriage is already well established in several forms:

- **Timestamping and commitments**, anchoring a hash to prove data existed or to commit to off-chain state. Minimal in size, long-standing, and endorsed for third-party timestamping.
- **Application-layer asset classes**, creating sustained demand for large payloads embedded in witness data that the witness discount makes economical for the payer.
- **Arbitrary content**, which raises concern over node-operator exposure that varies by jurisdiction.

Since arbitrary data defines no transfer, the ledger's validity does not depend on it at all. A node validates every block from its base serialisation, whether or not it holds the data, so receiving and retaining the data becomes an operator's choice rather than a requirement.

Therefore a carrier using SegData allows the burden it places on the network to be reduced. No existing mechanism is able to do this. Enabling `prune` mode discards block data wholesale by depth, not selectively by type. OP_RETURN still leaves its bytes retained by every node. Witness fields undercut OP_RETURN's price but are no less permanent.

Consequently, prunability enables a resource-constrained node to receive and retain a lighter but fully valid view of a block without SegData, making the case that data carriage can contribute to decentralisation rather than only burden it.

SegData is priced at witness parity or less, making it cost-competitive and economically rational, and places no restriction on the existing vectors. By offering this region, a channel is provided for data to be carried honestly (§Rationale) by Bitcoin and the operators that consent to it.

### Design lineage

SegData follows the [BIP-141](bip-0141.mediawiki) (Segregated Witness) architectural pattern of moving non-state-transition bytes into a separately committed region. Where SegWit separated signatures (validation data not needed once the containing block is buried) from transaction identity, SegData separates application payloads (arbitrary data not needed for validation at all) from both transaction and witness regions.

The pattern satisfies four architectural criteria that recur in Bitcoin's layer separations:

1. **Separation by semantic purpose.** Bytes that serve a distinct semantic purpose live in a distinct, separately-committed region rather than being encoded into a region that exists for another purpose. Transaction bytes encode state transitions, witness bytes encode validation proofs, and SegData bytes encode application payloads. Each layer can be reasoned about, validated, and retained independently.

2. **Named axioms.** Each region's purpose is declared by the consensus rules rather than inferred from incidental encoding. Today's data-carriage vectors rely on side-effects of opcodes, or on outputs being economically unspendable. SegData entries are explicitly named as data carriage by the consensus layer.

3. **No semantic overload.** A region designed for one purpose is not pressed into service for another. Transaction outputs and UTXO entries are not needed to carry payloads they were not intended for. The application-data region is defined as a parallel channel with specific semantic meaning.

4. **Bounded by weight.** SegData keeps the existing single block weight limit. The region competes for the same weight budget, and its only further constraint is a committed-length cap, set so the region never exceeds the single relay message limit (§Validation rules, rule 7).

A consensus-level prohibition on data carriage in existing vectors is not able or expected to produce these properties. Data-carriage demand would still be able to route through opcodes and outputs not designed for it. A separate region such as SegData addresses the encoding mismatch rather than the payload size, and lets node operators opt in to supporting it.

## Specification

### SegData commitment in coinbase

Each block MAY contain a SegData commitment in a new output of the coinbase transaction. The commitment output has the form:

```
OP_RETURN OP_PUSHBYTES_40 <4-byte marker> <32-byte commitment hash> <4-byte region length>
```

with the following structure:

```
 1-byte  - OP_RETURN (0x6a)
 1-byte  - Push the following 40 bytes (0x28)
 4-byte  - SegData marker (0x64617430, ASCII "dat0")
 32-byte - SegData commitment hash
 4-byte  - segdata region byte length (little-endian uint32)
```

The SegData commitment hash is computed as:

```
commitment_hash = tagged_hash("SegData/commitment", SegData Merkle root)
```

where `tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)` is the tagged hash of [BIP-340](bip-0340.mediawiki), which domain-separates SegData hashes from every other hash in the protocol (the tag strings are bound to the `dat0` suite). The SegData Merkle root is computed over the entry hashes of all SegData entries referenced by transactions in this block, in canonical order. Its construction is defined in §SegData Merkle tree.

The region length is the byte length of the `segdata` region. It is exactly the `SegData` byte-length operand of the weight formula (§Weight accounting), so with the consensus rate `r` a node holding only the base serialisation can compute and bound a block's total weight without fetching the region (§Uniform validation). The length is a visible field rather than part of the commitment hash because a node that skips the region must read it from the base serialisation. Its fixed 4-byte width keeps the commitment a constant 42-byte scriptPubKey matched by its exact form, as the BIP-141 witness commitment is.

A SegData commitment output scriptPubKey is exactly 42 bytes: `6a2864617430` followed by the 32-byte commitment hash and 4-byte region length, with no trailing data. If more than one coinbase output matches this form, the one with the highest output index is the canonical SegData commitment. The others have no consensus meaning.

If a block contains no SegData references in any transaction, the SegData commitment is optional and MAY be omitted. If present in such a block, it MUST commit to an empty Merkle root and declare region length zero.

SegData adds only this coinbase output, leaving the coinbase input witness and its BIP-141 reserved value unchanged. The SegData (40-byte) and BIP-141 witness commitments (36-byte) are distinct OP_RETURN outputs, further distinguished by their unique 4-byte markers, so each is detected and selected independently and a coinbase MAY carry both without ambiguity.

### SegData reference in transactions

A transaction MAY include one or more SegData references. A reference is encoded as a 36-byte witness-v2 program, the same 4-byte marker + 32-byte hash as encoded in the commitment:

```
scriptPubKey: OP_2 OP_PUSHBYTES_36 <4-byte marker> <32-byte SegData entry hash>
value:        0 (consensus-required)
```

with the following structure:

```
 1-byte  - OP_2 (0x52)
 1-byte  - Push the following 36 bytes (0x24)
 4-byte  - SegData marker (0x64617430, ASCII "dat0")
32-byte  - SegData entry hash = tagged_hash("SegData/entry", SegData entry bytes)
```

The matching reference and commitment pattern gives the protocol one identifying byte sequence at both layers. The marker selects the cryptographic suite defined by this BIP. A future BIP revising that suite would define a successor marker (`dat1`, `dat2`, and so on).

The reference output is unspendable by consensus, MUST have value zero, and is excluded from the UTXO set (validation rule 4), so references do not contribute to chainstate growth. Its only purpose is to anchor the entry's identity in the transaction. Because value zero falls below the dust threshold, relaying a reference output requires a standardness exemption, specified in the companion peer-services BIP.

A transaction MAY include multiple SegData reference outputs.

Witness-v2 outputs that do not match this exact encoding are not SegData references and remain anyone-can-spend per BIP-141 §Witness program.

### Script isolation

SegData is a pure-data write-only layer where entries are byte strings that exist solely to be committed and retrieved, never interpreted. The protocol's only handle on a SegData entry is its 32-byte tagged entry hash, which appears in the SegData reference scriptPubKey and in the SegData Merkle commitment. The hash itself is accessible to script like any other byte sequence in scriptPubKey, whereas the entry bytes it commits to are not.

SegData entries MUST NOT be accessible to script execution. No present or future opcode may read, inspect, branch on, or otherwise depend on the contents of a SegData entry (§Why script isolation is a permanent invariant).

Nothing in consensus depends on a SegData entry at all. The commitment binds the entry hashes carried in the reference outputs, which are base-transaction data, so it is checked without the entry (§Uniform validation). Entry content and availability are never an input to consensus, nor to spend validity, the UTXO set, or any future opcode, and their relay and retention are not guaranteed. SegData is for data that nothing needs to rely on, which is the same property that makes it prunable.

### SegData entry encoding

A SegData entry is a variable-length byte string committed by its tagged entry hash (`tagged_hash("SegData/entry", entry bytes)`). Entries are carried in a new region named `segdata`.

Following the BIP-141/BIP-144 separation of consensus structure from wire serialisation, a block has two serialisations:

```
base     = [header][tx_count: varint][tx_1]...[tx_n]
tx_i     = transaction serialised per BIP-144 (with inline witness data if any)
extended = [base][segdata]
segdata  = [count: varint][entry_1][entry_2]...[entry_m]
entry    = [length: varint][bytes: length]
```

- The **base serialisation** is identical to a pre-SegData block. The block hash and the transaction Merkle root commit only to the base serialisation. The SegData commitment as a coinbase output is carried within the base serialisation, where non-SegData nodes ignore it. Pre-activation peers, and any node that opts out, receive only the base serialisation.
- The **extended serialisation** appends the `segdata` region to the base serialisation and is transmitted only to peers that have negotiated SegData support. The negotiation service bit and the wire encoding of the region are defined in the companion peer-services BIP.

The `segdata` region is a single region carrying every distinct entry referenced in the block. It is not interleaved within transactions, and its entries are referenced by 32-byte hash from any number of transactions in the block.

### Canonical ordering

A single canonical order governs both the layout of the `segdata` region and the leaves of the commitment Merkle tree. SegData entries are ordered by:

1. Block-order of the first transaction containing a reference to the entry.
2. Within a transaction, by output index of the SegData reference.
3. If the same entry is referenced within or across transactions multiple times, it appears once at its first-referenced position.

### SegData Merkle tree

The SegData Merkle root committed by the SegData commitment is computed over the SegData entries in canonical order using a domain-separated binary Merkle tree in which leaves and internal nodes are hashed under distinct tags and nodes are never duplicated to balance the tree. This follows the construction of RFC-6962 §2.1 and removes the duplicate-node malleability of the transaction Merkle tree (CVE-2012-2459).

Let the canonical entry list be `e[0], e[1], ..., e[n-1]`, where each `e[i]` is the 32-byte entry hash `tagged_hash("SegData/entry", entry bytes)` and `n` equals the `segdata` count varint and the number of distinct entries referenced in the block. The Merkle root `MR` is defined recursively:

- `n == 0`: `MR` is the all-zero Merkle root value. This case arises only when a block with no references carries the optional commitment (§SegData commitment, validation rule 5). This is an explicit deviation from RFC-6962, which hashes the empty string.
- `n == 1`: `MR = tagged_hash("SegData/leaf", e[0])`.
- `n >= 2`: let `k` be the largest power of two strictly less than `n`; then `MR = tagged_hash("SegData/branch", MR(e[0:k]) || MR(e[k:n]))`, where each sublist root is computed by these same rules. The split places a perfect subtree of `k` leaves on the left and the remainder on the right.

The distinct leaf and branch tags mean no internal node can collide with a leaf. The deterministic split makes the tree shape a pure function of `n`, with no padding to introduce ambiguity, so every entry list of a given length has exactly one valid tree and two distinct canonical lists cannot share a Merkle root.

Each `e[i]` is exactly the 32-byte hash carried in the corresponding SegData reference output, and the canonical order is fixed by the referencing transactions. The leaf set, and therefore the Merkle root, are determined by the block's transactions alone, so a validator can compute `MR` and check the commitment (validation rule 2) without holding the `segdata` region. Confirming that entries hashing to those leaves are actually present and correctly encoded requires the region and is a relay-policy check, not consensus (§Validation rules).

### Weight accounting

BIP-141 defines block weight as `Base × 3 + Total`, where _Base_ is the block size as seen by a pre-SegWit node and _Total_ is the block size with the BIP-144 serialisation. This BIP extends that formula with a SegData term:

```
Block weight = Base × 3 + Total + (r × SegData)
```

where `SegData` is the byte length of the `segdata` region (including its `count` varint and all entry length-prefixes) and `r` is the SegData weight rate in weight units per byte. The rate satisfies `r ≤ 1`, witness parity is the ceiling, so SegData never costs more than the cheapest existing vector, and its exact value is left open (§Open Questions). Because the region length is committed in the coinbase and `r` is a consensus parameter, the SegData weight term is derivable from the base serialisation alone.

To calculate block weight with integer arithmetic at every rate, `r` is expressed as a rational `r_n / r_d`, where the numerator `r_n` and denominator `r_d` are consensus-fixed positive integers (for `r = 1/2`, `r_n = 1` and `r_d = 2`). The SegData contribution is `ceil(SegData × r_n / r_d)`, computed in integers as `(SegData × r_n + r_d − 1) / r_d`, rounding up so the bound stays conservative as `(weight + 3) / 4` does for vsize.

The block weight limit is unchanged. SegData entries therefore compete with transactions and witness data for the same 4M WU budget. SegData entry bytes contribute at `r` WU/byte, while transaction-region bytes contribute at the base rate of 4 WU/byte, including the SegData commitment output in the coinbase and the SegData reference outputs in spending transactions.

The consensus bounds on the `segdata` region are the block weight limit (validation rule 6) and the region-length cap `MAX_SEGDATA_REGION_LENGTH` (validation rule 7). Per-entry size caps are relay policy, as standardness limits are for transactions.

**Per-payload cost.** A payload of `N` bytes carried as one entry with one reference of a fixed 47 bytes contributes `r × N + 188 WU`.

The tables below give the full cost of a standalone publication, showing a SegData transaction with P2WPKH funding and one reference, against an estimated commit-reveal inscription of the same payload. Each SegData figure is the marginal `r × N + 188` WU plus roughly 420 WU for the funding input and change.

At parity (`r = 1`) the saving is a fixed overhead difference, largest for small payloads and shrinking as `N` grows:

| Payload | SegData | Witness Commit+Reveal | Saving | Saving % |
|----|----|----|----|----|
| 256 B | ~865 WU (216 vB) | ~1,210 WU (303 vB) | ~345 WU (86 vB) | ~28% |
| 1 KB | ~1,633 WU (408 vB) | ~1,996 WU (499 vB) | ~363 WU (91 vB) | ~18% |
| 10 KB | ~10,849 WU (2,712 vB) | ~11,266 WU (2,817 vB) | ~417 WU (104 vB) | ~4% |
| 100 KB | ~103,009 WU (25,752 vB) | ~103,960 WU (25,990 vB) | ~951 WU (238 vB) | ~1% |

At half the witness price (`r = 0.5`) the saving grows with payload size rather than shrinking:

| Payload | SegData | Witness Commit+Reveal | Saving | Saving % |
|----|----|----|----|----|
| 256 B | ~737 WU (184 vB) | ~1,210 WU (303 vB) | ~473 WU (118 vB) | ~39% |
| 1 KB | ~1,121 WU (280 vB) | ~1,996 WU (499 vB) | ~875 WU (219 vB) | ~44% |
| 10 KB | ~5,729 WU (1,432 vB) | ~11,266 WU (2,817 vB) | ~5,537 WU (1,384 vB) | ~49% |
| 100 KB | ~51,809 WU (12,952 vB) | ~103,960 WU (25,990 vB) | ~52,151 WU (13,038 vB) | ~50% |

### Validation rules (consensus)

A block is valid only if:

1. If any transaction contains a SegData reference output, the coinbase MUST contain at least one matching SegData commitment output. The canonical commitment is the matching output with the highest output index; any other matching outputs have no consensus meaning.
2. The commitment hash in the canonical SegData commitment MUST equal `tagged_hash("SegData/commitment", SegData Merkle root)`, where the Merkle root is computed over the 32-byte entry hashes carried in the block's SegData reference outputs, in canonical order. The leaves are the reference-output hashes, so this is checkable from the block's transactions alone, and it binds the commitment to the manifest the transactions declare.
3. A SegData reference output MUST have value zero (0). A transaction containing a SegData reference output with non-zero value is invalid.
4. A transaction spending a SegData reference output is invalid. Being unspendable and value zero, such outputs MUST NOT be added to the UTXO set, receiving the same treatment as OP_RETURN outputs so that data carriage adds no UTXO-set entries.
5. If no transaction in the block contains a SegData reference output, the SegData commitment output (if present) MUST commit to the empty Merkle root and a region length of zero.
6. The block weight, computed with the SegData region length committed in the coinbase (§Weight accounting), MUST NOT exceed the block weight limit (`MAX_BLOCK_WEIGHT`).
7. The SegData region length committed in the coinbase MUST NOT exceed `MAX_SEGDATA_REGION_LENGTH`, defined as `MAX_BLOCK_WEIGHT` less the 32-byte block hash a `segdata` message prepends. It is chosen so the region plus its 32-byte wire prefix stays within the peer-to-peer message limit, and that holds at every block weight, since the message limit already tracks `MAX_BLOCK_WEIGHT` so ordinary blocks relay. The whole region therefore always fits a single relay message. The committed region length is a byte count and `MAX_BLOCK_WEIGHT` is a weight in weight units, so the comparison is against the numeric value of `MAX_BLOCK_WEIGHT`. The region's own weight contribution is `r` times its byte length (§Weight accounting) and is bounded separately by rule 6.

No rule above needs the `segdata` region (§Uniform validation). The region itself is governed by relay policy, not consensus. That each referenced entry is present and hashes to its leaf, that the region carries no unreferenced entries, that it is canonically encoded, and that its byte length equals the committed length, are checks a node applies when it receives the region, as a condition of relaying and building on the block, not of the block's validity. They are specified in the companion peer-services BIP (§Region validation).

### Uniform validation

Consensus validation is identical at every depth. Every node applies the rules above from the base serialisation, the transactions and the coinbase commitment, for a block at the tip and for one buried under the deepest reorg alike, whether or not it holds the `segdata` region. There are no depth-scoped validation modes and no burial trust. A block's validity is fixed by its base serialisation when it is first seen and never changes, so two nodes cannot reach different verdicts on the same block by having encountered it at different depths.

### Prunability

A SegData entry is never a consensus input. The commitment binds the entry hashes carried in the reference outputs, not the entry bytes (§SegData Merkle tree), so a block validates from its base serialisation whether or not any entry is held. A node MAY therefore discard any or all entries at any depth and keep only the commitment, so SegData is structurally prunable, independently of the rest of the block.

This extends the established notion of pruning, discarding data once it has served validation, to a higher precision. Block pruning drops whole blocks by depth, SegData pruning discards individual or bulk entries by type.

Retention has two independent operator controls:

  1. an amount: how much to keep, from nothing up to the full archive.
  2. exclusions: specific entries the operator declines to keep, by any criteria.

The consensus layer constrains none of this. It guarantees only that the commitment remains and that any retained entry is verifiable against it. Mechanisms for advertising what a peer retains, requesting specific SegData entries from peers, and the operator-side amount and exclusion controls are addressed in the companion peer-services BIP.

### Activation

Activation follows [BIP-8](bip-0008.mediawiki) with parameters:

| Parameter | Value |
|---|---|
| `bit` | TBD |
| `start_height` | TBD |
| `timeout_height` | TBD (start + 1 year) |
| `min_activation_height` | TBD (start + 18 months) |
| `lockinontimeout` | TBD (§Open Questions) |

Pre-activation, any output matching the SegData reference encoding (witness-v2 with a 36-byte program whose first 4 bytes are `0x64617430`) is treated as anyone-can-spend per BIP-141 §Witness program. Post-activation, such outputs become unspendable per this BIP's validation rules.

At the activation height, any unspent output matching the encoding is removed from the UTXO set, the treatment rule 4 prescribes for outputs created after activation. This keeps chainstate contents, and therefore UTXO-set hashes, implementation-independent. Any value carried becomes permanently unspendable, as rule 4 already implies. The `dat0` marker makes accidental matches improbable and value-zero outputs are nonstandard pre-activation, so this set is expected to be empty.

## Rationale

### Why a dedicated data channel

Without a dedicated data channel, on-chain data carriage routes through existing vectors with no structural way to signal intent. From the protocol's perspective this creates an evaluation gap where data-carriage and monetary use can look identical, with no way to distinguish the two.

With SegData available, a carrier's choice becomes legible. A cost-competitive, purpose-built channel now exists, so whether a carrier moves to it or stays on an existing vector is deliberate, and the reason open to examination:

- Carriage needing only a minimal commitment, its data kept off-chain (timestamping, off-chain protocol commitments), has no reason to move. For a bare hash SegData is overhead, so OP_RETURN stays the cheaper home for it.
- Carriage that no script reads (application-layer assets, published content) has reason to migrate. SegData carries it at least as cheaply, with clean layer separation and a commitment that stays permanent for every node.
- Carriage with specific dependencies on existing properties (value transfer, script binding) remains on existing vectors, and those dependencies are now explicitly signalled by the carrier's choice rather than masked by the absence of alternatives.
- Carriage that specifically targets the uniform-retention property of witness (§Security Considerations item 7) becomes distinguishable from carriage that prefers witness for unrelated reasons.

Bitcoin has taken this approach before, and SegData applies it one layer deeper. A provably-unspendable OP_RETURN output is a content-blind declaration that the output is not a coin, and on that declaration every node excludes it from the UTXO set. It was made standard precisely to draw data carriage out of the fake keys and addresses that stored it as spendable outputs and bloated the UTXO set permanently. SegData extends the same logic to the data itself. A reference output and the region typing declare that the carried bytes are script-isolated, read by no opcode now or in any future one, so once the commitment is verified no node needs them again and the payload becomes prunable while the commitment remains.

OP_RETURN permits exclusion from the UTXO set. SegData permits exclusion of all but the commitment. The one difference is whether the exclusion is automatic. Removing an unspendable output is, because it has value to no one, whereas dropping data is a per-operator choice, because the data has value to some. The harm SegData addresses is therefore not UTXO bloat but the retention and IBD burden that OP_RETURN and witness carriage impose on every node, and retention is optional by design, the same principle that already removes unspendable outputs from the UTXO set applied to bytes consensus will never read.

### Why "honest" is a technical term

§Motivation describes SegData as letting data be carried "honestly". The term is technical, not moral. It refers to the transparency of the encoding. A SegData reference declares its bytes as a data payload, so an operator can recognise them and exercise a retention choice, and the network can differentiate declared data from monetary use. Data placed in witness envelopes or vanity addresses is opaque only in the narrow sense that it presents itself as a script or a key rather than as the data it is. This says nothing about whether the content is legitimate or should exist, only whether the carriage discloses what it is.

### Why entry integrity is relay policy

Consensus rules must be replayable and deterministic, such that every node must reach the same verdict on a block from the block alone, whenever it validates it. The region's integrity checks cannot be consensus rules because the region is prunable and may never be received. A block one node would reject for a missing or mismatched entry is indistinguishable, to a node syncing later after that entry was validly discarded, from a correctly pruned block, so making these checks consensus would tie a block's validity to when and from whom a node first saw it, splitting the network on data availability. Binding the commitment to the entry hashes in the reference outputs instead keeps the only data-derived consensus check computable from the base serialisation, so validity stays replayable while the payloads stay prunable.

### Why script isolation is a permanent invariant

The retention-from-validation decoupling holds only if script execution never depends on SegData entry contents. If any opcode were to read SegData entries, then transactions using that opcode would no longer be validatable by nodes that have pruned the referenced entries, and the central prunability property would silently break for that transaction class. A hostile actor could deliberately construct such transactions to force every validating node to retain the targeted entries.

The script-isolation rule prevents this attack surface from ever opening. No present opcode reads SegData, and the rule binds future BIPs to the same constraint. Any future opcode that would read SegData entries must either be rejected on prunability grounds or be paired with a redesign of the prunability model that accepts the consequences.

### Why selective retention preserves consensus

SegData lets a node keep the commitment and whatever subset of entries its operator chooses, and consensus is unaffected. Every node still validates the same chain and agrees on the same committed entry hashes. Only the stored payload bytes differ from node to node, and nodes already differ that way, pruning to different depths and running different indexes. A node that keeps just some entries still has the full list of what was committed, so it knows which it lacks and can check any it later obtains against the commitment. What consensus needs is agreement on what was committed, not that every node store the same bytes.

### Why selective retention preserves permanence

Selective retention leaves the permanent record intact. The commitment is permanent for every node forever, and the payload behind it persists wherever a willing party retains it, exactly as witness and OP_RETURN data do today, which no consensus rule compels any node to store. What SegData offers is consensual storage rather than coercing operators to store payloads they would prefer to decline. A genuine durability need survives, since the carrier can keep its data or request others to. The carrier that turns down an equally priced consensual channel reveals what it was really seeking (§Why a dedicated data channel). Guaranteed availability is a different requirement, out of scope, and witness does not provide it either.

### Why selective retention is not censorship

Censorship would mean preventing publication, or erasing what was published. SegData does neither. What goes into a block is still chosen by miners and priced by fees, exactly as today. No consensus rule reads an entry's contents, and once a block is mined its commitment is permanent for every node. Choosing not to retain an entry does not remove it from the chain or stop it being included.

What selective retention affects is availability, not the record. A node keeps SegData by default, as it does witness today, and its operator may now decline to host a copy, which the protocol never required anyway, since pruned nodes already discard block data. An entry may then end up with fewer copies than witness produces, but the availability floor is unchanged: one surviving copy, held by anyone anywhere, remains distributable and verifiable against the permanent commitment.

### Why a discounted weight unit

SegData is priced at witness parity or less. Parity is the ceiling which puts SegData at the price of the cheapest existing vector, so moving carriage into SegData never costs more than leaving it in the witness. Whether the rate should sit below parity is left open, and the case for a sub-witness discount rests on three grounds.

1. Availability. Although both witness and SegData can be pruned, SegData need not be received at all and may be dropped per entry at any depth, so its availability is best-effort and can rest on fewer copies. This presents the trade-off that SegData is cheaper because the carrier accepts the weaker guarantee. At exact parity the carrier pays the same for that weaker guarantee, so has less reason to choose SegData.
2. Resource cost. Prunable SegData is a genuinely smaller long-term burden than witness data, therefore pricing it below witness is cost-reflective rather than a preferential subsidy.
3. Decentralisation. Witness data is validation-required, so every byte of it raises the participation floor for every validating node. SegData is sheddable, so it does not. A discount pulls migratable carriage out of the witness, where it burdens all nodes, into SegData, where opt-out nodes discard it, lowering the floor as data grows. Routing data to the sheddable channel is the objective, not a distortion of it.

The discount has a floor of its own. Migration of data from witness into SegData is a pure improvement, whereas induction of new data is an additional burden even though it is sheddable. The target has to be a rate deep enough to empty the witness of migratable carriage and no deeper. A rate below the cost of the signatures securing payments invites the objection that Bitcoin subsidises data over money, which the decentralisation framing answers strongly but does not erase completely.

### Why not the Taproot annex

The [BIP-341](bip-0341.mediawiki) annex is the existing reserved slot for additional per-input data, so it is the natural alternative to evaluate. However, it cannot deliver this BIP's properties:

1. **Sighash-bound.** The annex is committed by the signature message (`sha_annex` in the BIP-341 digest), so its bytes are required to verify the spend. Annex data is validation data by construction, so it cannot be selectively pruned.
2. **Uniform retention at receipt.** Annex bytes ride the witness serialisation, which every node downloads during IBD and block relay. There is no opt-out of receipt, no per-entry retention choice, and no historical skip.
3. **No separate commitment.** The annex has no independent root, so a node cannot retain a verifiable commitment while discarding the payload.

The distinction is between two meanings of prunable. Witness data is prunable in the discard-after-validation sense: every node must still receive and validate it, including the full history during IBD. SegData is prunable in the operator-choice sense: discard to commitments at any depth, retain selectively per entry, and never download the region at all if the operator does not want it.

Assigning data-carriage meaning to the annex would also overload a slot BIP-341 reserves for future extensions (its cited example is signalling the validation cost of new opcodes), violating the no-semantic-overload criterion (§Design lineage).

### Why no signing or sighash semantics are required

SegData reference outputs are unspendable by consensus so no signature is ever verified against them. Therefore SegData requires no new sighash algorithm, no signature-verification rules, and no companion BIP analogous to [BIP-143](bip-0143.mediawiki). This is one reason SegData is structurally simpler than SegWit despite using the same architectural pattern.

### Why SegData cannot become a monetary-function vector

A natural adversarial framing asks whether SegData could be inadvertently used for monetary function, the way witness is used for data carriage. For SegData to be inadvertently used as a monetary substrate at the consensus layer, certain properties would need to apply in the data-to-monetary direction. Three structural rules close this path:

1. **Reference output value=0** (validation rule 3): SegData reference outputs cannot hold value, so SegData cannot directly carry satoshis.

2. **Script isolation** (Specification §Script isolation): opcodes cannot read SegData entry contents, so SegData cannot influence script execution or gate spending. The same rule that prevents script-time content access also prevents content-driven monetary semantics.

3. **No sighash binding**: entry bytes never enter any signature hash, so no signature verification rule reads, requires, or acts on them. A signer whose sighash covers the reference output does commit to the entry content transitively through its hash, which is the timestamping use case, but that commitment is application-layer evidence only. Consensus never evaluates it, so it cannot gate spending or carry monetary semantics.

Application-layer use of SegData for off-chain protocols remains possible and is the intended use of the layer. The structural rules above ensure such uses cannot couple to Bitcoin's monetary primitives at the consensus layer. Off-chain interpretation therefore cannot become on-chain enforcement.

So the symmetry breaks. SegData inverts witness in two ways. Witness is for authorisation and SegData for data. And witness leaves its content open to script, while SegData seals its entries away.

## Backward Compatibility

Since this BIP proposes a soft fork, pre-activation nodes will:

- Accept all blocks, ignoring the OP_RETURN commitment and treating reference outputs as harmless value-zero anyone-can-spend (BIP-141 §Witness program).
- Not validate SegData commitment consistency or entry presence.
- Receive only the base block serialisation and therefore not retain SegData entries.

Post-activation nodes enforce the rules in §Specification. A miner producing a block that violates them has it rejected by activated nodes, while pre-activation nodes follow it until the upgraded majority's chain accumulates more work. This is the standard soft-fork exposure window every deployment since [BIP-34](bip-0034.mediawiki) has carried, identically shaped for BIP-141 and BIP-341.

Because the SegData reference encoding requires the `dat0` marker prefix, no non-SegData wallet produces a matching output by accident. SegData-aware software MUST set value zero from the start. Pre-activation a matching output is anyone-can-spend but carries no value, so the activation window exposes no funds, and post-activation rule 3 makes any non-zero-value reference invalid. The encoding makes data carriage an explicit, inspectable output rather than bytes hidden in witness or key fields, so wallets have everything needed to surface it.

Witness-v2 outputs that do not match the SegData reference encoding are unaffected, and future BIPs MAY assign meaning to them. [BIP-360](bip-0360.mediawiki) (P2MR) already defines a 32-byte witness-v2 program. Being length-disjoint from SegData's 36-byte reference, the two coexist in either activation order.

Existing transactions, address formats, and non-SegData-aware wallet software are unaffected. UTXO-set handling changes for exactly one output class and reference outputs are never added to the set (validation rule 4). All other outputs, including non-matching witness-v2 outputs, are handled as today.

Block weight remains derivable for software outside the node. Although the `segdata` region is absent from the base serialisation, the SegData commitment carries the region byte length, so any holder of the base bytes computes a block's full weight from a proof-of-work-committed field without fetching the region.

Per-transaction weight is a new break. BIP-141 kept the witness inside the transaction, so a transaction stayed computable from its own bytes. SegData puts the entry bytes outside the transaction, so a SegData transaction's weight, and therefore its feerate, needs the entry sizes and their attribution from a node (§Reference Implementation item 4). Committing the length in each reference (§Open Questions) would remove this break for SegData-aware software.

## Reference Implementation

A reference implementation of the consensus-layer rules in this BIP requires:

1. Block validation changes: commitment-output detection, canonical-commitment selection, and reference-output validation (value, unspendability, and Merkle-root match). The `segdata` region itself is not parsed by consensus (§Uniform validation); region receipt and matching is a peer-services concern.
2. Weight-accounting changes: per the extended formula in §Weight accounting.
3. Storage layer changes: per-entry addressable `segdata` storage with a single allocation parameter, following the `-prune` idiom: the default retains everything, as unpruned block storage does, and the parameter opts into less. Storage MAY deduplicate identical entries across blocks, since each block's canonical entry list is derivable from its reference outputs and reconstructs the region from a content-addressed store exactly.
4. RPC interface: inspection of retained entries, plus a manual `prunesegdata` call discarding a block's `segdata` or a single entry within it, refusing targets the node is committed to serve under its retention policy, as `pruneblockchain` refuses heights inside the pruned-node minimum. Selective retention policy thereby lives in external tooling driving this RPC, not in the node. Block and mempool reporting exposes weight with and without the SegData term: the full consensus weight, the three-term BIP-141 weight byte-holding tooling can still derive and cross-check, and the SegData component per block and per transaction (attributed entry weight). This keeps weight statistics comparable across activation and makes each block's data-carriage share directly observable.

P2P propagation, service-bit advertising, request/response messages for SegData entries, and operator-policy retention mechanics belong to the companion peer-services BIP.

## Security Considerations

1. **Migration incompleteness.**
  - *Risk*: existing data-carriage vectors remain available. SegData does not close them, and at witness parity it does not undercut witness on price, so migration is voluntary and not guaranteed.
  - *Mitigation*: SegData is intended to draw traffic by offering a purpose-built channel, not to compel it. It is cheaper than OP_RETURN and vanity embedding and gives witness users layer separation and selective discardability, but a carrier is free to stay on any existing vector. Future BIPs MAY restrict existing vectors at the standardness-policy layer, one such historical example being `permitbaremultisig`. This BIP intentionally does not couple migration to restriction, preserving soft-fork-only scope.

2. **Induced demand.**
  - *Risk*: discounted pricing for SegData may incentivise larger payloads than existing vectors carry today. Aggregate block weight devoted to data carriage may rise.
  - *Mitigation*: SegData competes for blockspace exactly as witness data does within the unchanged 4M WU budget. What it mitigates is the burden on operator resources. Each node keeps only the entries its operator accepts, and can shed all of them, so however much data-carriage demand rises, the storage and IBD burden an opt-out operator bears does not.

3. **Post-pruning verification gap.**
  - *Risk*: once SegData is pruned, future participants can verify only that *some* payload matching the commitment was once present, not what it was.
  - *Mitigation*: this is the intended property. The chain guarantees inclusion and ordering, not retrieval, and anyone needing the bytes can keep their own copy or obtain one from a retaining node. Complete loss is unlikely in practice, since retention defaults to archival and an entry becomes unretrievable only if every holder has discarded it.

4. **Arbitrary content embedding.**
  - *Risk*: no vector, SegData included, can prevent content that some jurisdictions classify as illicit from being committed. The concern is the node operator who must then store it.
  - *Mitigation*: content carried in SegData can be pruned by any operator at any depth. Content embedded in the existing vectors cannot. Mitigating the latter is out of scope for this BIP (§Open Questions).

5. **Centralisation of archival, and de facto deletion.**
  - *Risk*: because retention is voluntary, an entry survives only where someone keeps it. If the dominant implementation defaulted to pruning SegData, or retention concentrated in a few relay hubs, the redundancy behind an entry could erode until it is effectively deleted network-wide, and archival capacity would concentrate in a small number of operators.
  - *Mitigation*: retention defaults to block storage, so a default-configured unpruned node is archival and the archival set stays as broad as the unpruned-node set until operators opt out; implementation diversity keeps that default from resting on one codebase. Because the commitment is permanent for every node, deletion is reversible: any party that still holds an entry can re-serve it and prove it against the commitment, so a single surviving copy re-seeds availability. The protocol guarantees decentralisation of the commitment, not of the data, the same property Bitcoin already accepts for pruned block data, and IBD never depends on it since every block validates from its base serialisation. The honest limit is that prunable means deletable: a carrier needing guaranteed permanence should use a non-prunable vector such as the witness.

6. **Re-org-induced segdata loss.**
  - *Risk*: a re-org could surface a block whose SegData entries a pruning node has already discarded.
  - *Mitigation*: this poses no validity risk. A block validates from its base serialisation at any depth (§Uniform validation), so a re-org never requires the region to re-validate. Availability of a re-orged block's entries is the same best-effort property as any SegData and defaults to archival retention. Entries should be considered "permanently committed" only after the same depth used for transaction finality.

7. **Adversarial witness-vector retention.**
  - *Risk*: carriers specifically motivated by witness fields' uniform-retention property have a positive reason to prefer witness over SegData regardless of fee parity, because the non-cost properties of witness are exactly what SegData removes.
  - *Mitigation*: none within this BIP. Future BIPs may address the witness vector directly via standardness-policy restrictions, by extending operator-policy retention to witness data, or by consensus-level restrictions on arbitrary witness data carriage.

8. **Future opcode access to SegData entries.**
  - *Risk*: a future BIP introducing an opcode that read SegData entry contents would defeat prunability and could be exploited to force universal retention.
  - *Mitigation*: the script-isolation constraint (Specification §Script isolation) forbids this. See Rationale §Why script isolation is a permanent invariant for the full argument.

9. **Withheld or corrupted region.**
  - *Risk*: a miner can mine a consensus-valid block while withholding its SegData region, or serving a region that does not match the commitment. Nodes that wanted those entries do not receive them.
  - *Mitigation*: this is a data-availability concern, not a consensus split. Entry presence and integrity are relay policy, never consensus (§Validation rules), so a withheld or mismatched region cannot make one node accept a block another rejects; every node reaches the same verdict from the base serialisation. A relaying peer that receives a region not matching the commitment rejects it as a relay violation and does not propagate it, and a node that never receives a region it wants can request it from any retaining peer (peer-services BIP). Data that needs the strongest retention the network offers belongs in a non-prunable vector such as the witness, which every non-pruned node keeps.

10. **Selective inclusion and class filtering.**
  - *Risk*: the explicit `dat0` marker makes SegData references trivially identifiable, so a miner, a relay policy, or a regulator mandating one can filter the entire class by pattern match, with no content inspection. This is cheaper than identifying data hidden in witness envelopes or key fields, so SegData marginally lowers the cost of class-level filtering.
  - *Mitigation*: inclusion is the ordinary censorship-resistance problem. A fee-paying SegData transaction is profit for whoever mines it, so durable exclusion requires majority hashrate and otherwise only delays confirmation, exactly as for any transaction. Relay-layer filtering impedes propagation but is trivially routed around. The same transparency that eases filtering is what makes SegData sheddable, and declining to *retain* an entry, unlike declining to mine it, is not censorship at all.

The above are non-exhaustive. Community review is expected to surface additional considerations.

## Open Questions

- **Activation parameters and `lockinontimeout`**: the `bit`, heights, and the LOT setting are left for the activation discussion.

- **Discount depth**: the SegData weight rate is witness parity or less (§Weight accounting), and the exact value of `r ≤ 1` is left open. Parity is the ceiling. The grounds for going below it, and against, are developed in §Why a discounted weight unit. The guiding target is a rate deep enough to migrate existing witness carriage without conjuring net-new data. The discount is a price lever, not a capacity one. A sub-parity rate makes region bytes cheaper in weight, not more numerous, and the region-length cap (validation rule 7) holds per-block data capacity near a single relay message at any rate. How much data a block carries within that is left to the fee market, and any tighter per-block or per-entry limit is relay policy, tunable like `datacarriersize`.

- **Witness version and length slot**: the reference uses witness v2 with a 36-byte program, distinguished from other v2 uses by the `dat0` marker and program length. This makes SegData references unambiguous in any version, so the choice between sharing v2 and taking a dedicated version is a matter of coordination, not of correctness.

- **Committing to per-reference entry length**: the per-transaction counterpart to the region length committed in the coinbase (§SegData commitment). Encoding each entry's byte length beside its hash in the reference output (a maximum 40-byte program) would make a transaction's SegData weight, and therefore its feerate, computable from its own bytes by any SegData-aware node. Because references live in the base transaction and are never pruned, this survives entry pruning, so a commitments-only node could still report accurate historical feerates without querying a retaining peer. Shared entries resolve under the existing canonical ordering. It does not help non-SegData-aware nodes, whose feerate view skews until upgrade as it did under BIP-141. Costs: every reference grows to the 40-byte maximum, one added validation rule, and the reference stops being a pure content hash.

## Copyright

This BIP is dual-licensed under the BSD 3-clause license and the Open Publication License v1.0 or later.

## Changelog

- 0.1.0 (2026-07-24): Initial Draft.

## References

- [BIP-8](bip-0008.mediawiki) - Version bits with lock-in by height
- [BIP-34](bip-0034.mediawiki) - Block v2, Height in Coinbase (first miner-activated soft fork, origin of the exposure-window pattern)
- [BIP-141](bip-0141.mediawiki) - Segregated Witness (Consensus layer)
- [BIP-143](bip-0143.mediawiki) - Transaction Signature Verification for Version 0 Witness Program
- [BIP-144](bip-0144.mediawiki) - Segregated Witness (Peer Services)
- [BIP-340](bip-0340.mediawiki) - Schnorr Signatures for secp256k1 (tagged-hash construction)
- [BIP-341](bip-0341.mediawiki) - Taproot: SegWit version 1 spending rules
- [BIP-360](bip-0360.mediawiki) - Pay-to-Merkle-Root (P2MR): the other draft claim on witness v2 (length-disjoint, §SegData reference in transactions)
- [RFC-6962](https://www.rfc-editor.org/rfc/rfc6962) - Certificate Transparency (Merkle tree construction)
