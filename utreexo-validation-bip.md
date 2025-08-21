```
BIP: TBD
Layer: Peer Services
Title: Utreexo - Validation Layer
Authors: Tadge Dryja <rx@awsomnet.org>
         Calvin Kim <bip@calvinkim.info>
         Davidson Souza <bip@dlsouza.dev>
Comments-URI: TBD
Status: Draft
Type: Specification
Created: 2023-10-01
License: BSD-3-Clause
Requires: BIP-???? (Utreexo Accumulator Specification)
```

## Abstract

This BIP defines the rules for validating blocks and transactions using the
Utreexo accumulator. It is important to note that this BIP does not define the
Utreexo accumulator itself, for that see BIP-????. This document is only concerned with
the general rules for validating blocks and transactions using the Utreexo,
so that all Utreexo nodes can stay in consensus with one another.

## Motivation

Although Utreexo in its current form is not proposed as a soft fork, it is essential that
all implementations adhere to a consistent workflow when performing consensus-critical
operations. This BIP defines that workflow, along with the specific rules and their
required ordering.

There are five consensus-critical components when using the Utreexo accumulator to
represent the UTXO set:

 - 1: The serialization format of each UTXO ("leaf data").
 - 2: The hash function used to hash the leaf data.
 - 3: Which transaction outputs are excluded from the accumulator.
 - 4: The order of operations for the additions and deletions in the accumulator.
 - 5: The format of the UTXO proof.

A discrepancy in any of the five components above will result in a divergent
accumulator state, leading to consensus incompatibilities.

## License

This BIP is licensed under the BSD 3-clause license.

## Specification

### Node Hashes

During a node's normal operation, it will need to compute the leaf hash for UTXOs
being added or removed from the accumulator. The leaf hash is a 32 byte hash that
is computed using the SHA-512/256 hash function. See [UTXO Hash Preimages](#utxo-hash-preimages) for the
details on how to compute the leaf hash.

Unless otherwise specified, all fields are in little-endian format.

#### UTXO Hash Preimages

Individual UTXOs are represented as 32 byte hashes in the Utreexo accumulator. To obtain this
hash, you must compute the SHA-512/256 hash of the following data:

| Name              | Type                     | Description                               |
| ----------------- | ------------------------ | ----------------------------------------- |
| Utreexo_Tag_V1    | 64 byte array            | The version tag to be prepended to the leafhash. |
| Utreexo_Tag_V1    | 64 byte array            | The version tag to be prepended to the leafhash. |
| BlockHash         | 32 byte array            | The hash of the block in which this tx was confirmed. |
| TXID              | 32 byte array            | The transaction's TXID                    |
| Vout              | 4 bytes unsigned integer | The output index of this UTXO             |
| Header code       | 4 bytes unsigned integer | The block height and iscoinbase. This is a value obtained by left shifting the block height that confirmed this transaction, and then OR-ing it with 1, only if this transaction is a coinbase. |
| Amount            | 8 bytes unsigned integer | The amount in satoshis for this UTXO      |
| scriptPubkey size | varint                   | scriptPubKey length in bytes              |
| scriptPubkey      | variable byte array      | The locking script of the UTXO            |

Each field being defined as follows:

##### Version tag

We use tagged hashes for the hashes committed in the accumulator for versioning
purposes. This is added so that if there are changes in the preimage of the
hash, the version tag helps to avoid misinterpretation.

The Utreexo version tag is the SHA512 hash of the string `UtreexoV1`, which is represented as the vector
`[85 116 114 101 101 120 111 86 49]` and hex `0x5574726565786f5631`.  (The resulting 64 byte output is
`5b832db8ca26c25be1c542d6cceddda8c145615cff5c35727fb3462610807e20ae534dc3f64299199931772e03787d18156eb3151e0ed1b3098bdc8445861885`).

##### Blockhash

We commit to the hash of the block which confirms the UTXO. This
is not currently used in the validation code, but could be used at a future
version to increase the work required for collision attacks.
A valid blockhash requires a large amount of work, which would prevent an
attacker from performing a standard cycle-finding collision attack in $2^{n/2}$
operations for an n-bit hash.

This could allow a later or alternate version to use shorter truncated hashes,
saving bandwidth and storage while still keeping Bitcoin's $2^{128}$ security.

##### TXID

The TXID is the transaction ID of the transaction that created this UTXO.

##### VOUT

The output index of the UTXO in the transaction.

##### Header code

This field stores the block height and a boolean for marking that the UTXO is
part of a coinbase transaction. Mostly serves to save space as the coinbase
boolean can be stored in a single bit.

This field is a value obtained by left shifting the block height that
confirmed this transaction, and then setting the least significant bit to 1 only
if it's part of a coinbase transaction. The code to do that is like so:

```
header_code = block_height
header_code <<= 1
if IsCoinBase {
    header_code |= 1 // only set the bit 0 if it's a coinbase.
}
```

The block height is needed as during transaction validation, it is used during
the check of BIP-0065 CLTV. In current nodes, the block height is stored locally
as a part of the UTXO set. Since Utreexo nodes get this data from peers, we need
to commit to the block height to avoid security vulnerabilities.

The boolean for coinbase is needed as they may not be spent before having 100 confirmations.
This data is also currently stored locally as a part of the UTXO set for current nodes.

##### Amount

This field is added to commit to the value of the UTXO. With current nodes, this
is stored in the UTXO set but since we receive this in the proof from our peers,
we need to commit to this value to avoid malicious peers that may send over the
wrong amount.

##### script pubkey size

As the script pubkey is a variable length byte array, we prepend it with the
length.

##### script pubkey

This field is added to commit to the locking script of the UTXO. With current
nodes, this is stored in the UTXO set but since we receive this in the proof
from our peers, we need to commit to this value to avoid malicious peers that
may send over the wrong locking script.

#### Hash function

The leaf data is hashed with SHA-512/256, which gives us a 32 byte hash.
It was chosen over SHA-256 due to the faster performance on 64 bit systems.

#### Excluded UTXOs from the accumulator

Not all transaction outputs are added to a node's UTXO set. Normal Bitcoin nodes
only form consensus on the set of transactions, not on the UTXO set, so different
nodes can omit different outputs and stay compatible as long as those outputs are
never spent. Utreexo nodes, however, do require explicit consensus on the UTXO set
as all proofs are with respect to the Merkle roots of the entire set.

For this reason, we define which UTXOs are not inserted to the accumulator.  Any
variations here will result in Utreexo nodes with incompatible proofs.

##### Provably unspendable transaction outputs

There are outputs in the Bitcoin network that we can guarantee that they cannot
be spent without a hard-fork of the network. The following output types are not
added to the accumulator:
- Outputs that start with an OP_RETURN (0x6a)
- Outputs with a scriptPubkey larger than 10,000 bytes

##### Same block spends

Often, UTXOs are created and spent in the same block. This is allowed by Bitcoin
consensus rules as long as the output being spent is created by a transaction earlier
in the block than the spending transaction.
In Utreexo, nodes inspect blocks and identify which outputs are being created
and destroyed in the same block, and exclude them from the accumulator and proofs.

There's no need to provide proofs for outputs which have been created in the same
block. Adding and then immediately removing the output from the accumulator would be
possible but doesn't serve any purpose - once outputs are spent their past existence
cannot be proven with the Utreexo accumulator (and SPV proofs already provide that).

For these reasons, outputs which are spent in the same block where they are created
are omitted from the accumulator, and those inputs are omitted from block proofs.

#### Order of operations

The Utreexo accumulator lacks associative properties during addition and the
ordering of which UTXO hash gets added first is consensus critical. For
the modification of the accumulator the steps are as follows:

1. Batch remove the UTXOs that were spent in the block based on the algorithm
   defined in BIP-????. Deletions itself are order-independent.
2. Batch add all non-excluded outputs in the order they're included in the
   Bitcoin block. Additions are order-dependent.

The removal and the addition of the hashes follow the algorithms defined in
BIP-????.

#### Format of the UTXO proof

The UTXO proof has 2 elements: the accumulator proof and the leaf data. The
leaf data provides the necessary UTXO data for block validation that would be
stored locally for non-Utreexo nodes. The accumulator proof proves that the
given UTXO hash preimages are committed in the accumulator.

Accumulator proof is defined in BIP-????, and contains two elements:

1. A vector of positions of the UTXO hashes in the accumulator.
2. A vector of hashes required to hash up to the roots.

For (1), positions are in the order of the leaves that are being proved in
the accumulator. These are all the inputs in the natural blockchain order that
excludes the same block spends.

The UTXO hash preimages follow the same ordering as (1) in the accumulator
proofs. Each of the positions in (1) refer to the UTXO hash preimage in the same
index.

| Field Name          | Data Type           | Byte Size | Description                             |
| ------------------- | ------------------- | --------- | --------------------------------------- |
| Accumulator Proof   | variable byte array | variable  | The Utreexo proof as defined in BIP-????|
| UTXO hash preimages | variable byte array | variable  | The UTXO data needed to validate all the transaction in the block |

#### UTXO proof validation

For each block, the UTXO proof must be provided with the bitcoin block for
validation to be possible. Without the UTXO proof, it's not possible to
validate that the inputs being referenced exists in the UTXO set.

The end result of the UTXO proof validation results us in the vector of UTXO
hash preimages that are required to perform the rest of the consensus
validation checks. Note that the resulting data from the UTXO proof validation
is the same data that would normally be fetched from the locally stored UTXO
set.

The order of operations for the UTXO proof validation are:

1. Hash the UTXO preimages.
2. Verify that the UTXO preimages exist in the accumulator with the verification
   algorithm specified in BIP-????.

### BIP-0030

[`BIP-0030`](https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki) is an added
consensus check that prevents duplicate TXIDs. This check and the historical violations
of this check affect the consensus validation for Utreexo nodes.

### BIP-0030 and BIP-0034 consensus check

Before `BIP-0030`, the Bitcoin consensus rules allowed for duplicate TXIDs. If two
transactions shared a same TXID, the transaction outputs of the preceding
transaction would overwrite the previously created UTXOs. It was assumed that
TXIDs were unique but it's trivially easy to create a transaction that share
the same `TXID` for coinbase transactions by re-using the same bitcoin address.

`BIP-0030` check is a consensus check that enforces that newly created transactions
do not have outputs that overwrites an existing UTXO.

`BIP-0034` was a rule where the block height was included in the script signature
of the coinbase transaction. One of the reason for the change was to make
coinbase transactions unique so that the expensive check of going through the
UTXO set wouldn't be needed. However, there were blocks in the past that had
random bytes that could be interpreted as block heights. The lowest block
heights are: 209,921, 490,897, and 1,983,702.

Up until block 209,921 the BIP-0030 checks are performed for non-Utreexo nodes.
Since Utreexo nodes only keep the UTXO set commitment, it's not possible to
perform the `BIP-0030` check. In theory, those blocks can't be reorged, because
of checkpoints, that goes back to block height 295,000 with the block hash
`00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983`. Any chain that
doesn't include this block at height 295,000 isn't valid as removing this check
would be a hard-fork. We note, however, that after version `0.30`, Bitcoin Core
will remove the checkpoints[^1], as they are not needed anymore to prevent attacks
against nodes during Initial Block Download. This is effectively a hard-fork,
that will probably never actually happen, however.

Block 1,983,702 is the first block that Utreexo nodes would be in danger of a
consensus failure due to the inability to perform the BIP-0030 checks. However,
this block will happen in roughly 21 years from now, and some mitigations have been
proposed [^2].

### Historical BIP-0030 violations

There were two UTXOs that were overwritten due to this consensus rule are:
`e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468:0` at block height 91,722
`d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599:0` at block height 91,812

Since the leaf hashes that are committed to the Utreexo accumulator commit to
the block hash as well, all the leaf hashes are unique and the two historical
violations do not happen with how the UTXO set is represented with the Utreexo
accumulator. To be consensus compatible with clients that do have the historical
violations, the leaves representing these two UTXOs in the Utreexo accumulator
are hardcoded as unspendable.

These two leaf hashes encoded in hex string are:

 1. `84b3af0783b410b4564c5d1f361868559f7cf77cfc65ce2be951210357022fe3`
 2. `bc6b4bf7cebbd33a18d6b0fe1f8ecc7aa5403083c39ee343b985d51fd0295ad8`

(1) represents the UTXO created at block height 91,722 and (2) represents the
UTXO created at block height 91,812.

## Reference Implementation

[Utreexod](https://github.com/utreexo/utreexod): A full node implementation with Utreexo support, written in Golang.

[Floresta](https://github.com/vinteumorg/floresta): A lightweight Utreexo client, written in Rust.

## Backward Compatibility

Utreexo nodes are fully backwards compatible with current nodes as they will follow the same chain tip as the current nodes.
Similarly, Utreexo nodes will only consider currently valid transactions for mempool acceptance.

## Acknowledgements

We thank BOB Spaces for lending the space to draft this BIP.

## References

[^1]: https://groups.google.com/g/bitcoindev/c/qyId8Yto45M
[^2]: https://delvingbitcoin.org/t/great-consensus-cleanup-revival/710
