```
  BIP: ?
  Layer: Applications
  Title: Testnet 5
  Authors: Pol Espinasa <polespinasa@protonmail.com>
           Fabian Jahr <fjahr@protonmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: CC0-1.0
  Discussion: ?
```

## Abstract

A new test network with the goal of replacing [Testnet 4][BIP94]. Testnet 5 removes the difficulty
exception defined in Testnet 4. Sustained exploitation of this exception has made the network difficult
to use for testing. Additionally, Testnet 5 enforces the consensus rules specified in BIP 54 from Genesis.

## Motivation

Testnet 4 included mitigations for an issue known as the [block storm attack][block-storms] which could render the
whole network unusable. This led to a depletion of block subsidies, which made it hard to acquire
coins for testing. However, Testnet 4 still retained a modified version of the difficulty exception rule
with the aim of allowing CPU users a limited path to acquire coins for testing, to mine non-standard
transactions that other miners would not relay, and to keep the chain moving if a large source of hash
power were to leave the network. Shortly after Testnet 4's introduction, the exception has been
systematically and sustainably exploited, which prevented the exception from achieving the intended
goals. While block storms were prevented, the network suffers from constant re-orgs of small
numbers of blocks due to multiple difficulty-exception blocks competing for the tip. This led
to discussion about changing Testnet 4 to mitigate this issue (see [Bitcointalk][bitcointalk-thread]
for analysis and discussion).

In Testnet 5 there is no exception to the PoW rules. This appears to be the logical conclusion,
since any such exception could be exploited by a motivated attacker. This
ensures the network’s behavior matches mainnet as closely as possible.

BIP 54 is already enforced on signet through [Bitcoin Inquisition][signet-bip54] as of this BIP's creation.
However, signet does not allow miners to test that their software reliably follows the rules of
BIP 54. Testnet 5 provides a testing environment for this.

## Specification

Testnet 5 follows the same consensus rules as mainnet with the following exception.

### BIP 54 activation

The rules specified in [BIP 54 version 1.0.0][BIP54] are active on Testnet 5 from Genesis.

#### Problem Statement

BIP 54 proposes new consensus rules in order to fix several potential attack vectors. Namely 
it prevents the timewarp attack, reduces the worst-case block validation time, prevents Merkle
tree weaknesses, and avoids duplicate transactions without [bip-0030][BIP30] validation.

#### Rule Specification

See specification in [bip-0054][BIP54].

## Rationale

Instead of starting a new Testnet, changing the rules of Testnet 4 was considered as well. The decision
for a new network has two main reasons:

1. Deploying network changes is hard and typically takes a long time. This effort doesn't seem to be
   worth it for a Testnet that has the alternative option to start fresh, especially considering that
   the attackers exploiting Testnet 4's rules may use them to prevent a smooth deployment of new rules,
   including those of BIP 54.
2. Any fix to Testnet 4 that goes beyond a band-aid would require a hard fork, which brings its own
   implementation cost: adding hard-fork support to clients, handling the p2p layer correctly, etc.
   For a test network this isn't worth taking on, especially since a band-aid would only make
   Testnet 4 diverge further from mainnet.

## Network Parameters

### Consensus Rules

All consensus rules active on mainnet as of May 2026 are enforced from Genesis, the most
recent of these being the Taproot softfork.

### Genesis Block

TODO: Mine the block. The values below are placeholders inherited from Testnet 4. Notes
for the miner:

- For the `Pubkey` field, use a recent Bitcoin mainnet block hash. This single field then
  serves two purposes: the output is provably unspendable and it acts as an anti-pre-mine
  commitment. This is different from what Testnet 4 did (empty Pubkey and block hash in
  message) but this is actually more elegant and was only suggested by Sjors after the
  final Genesis block for Testnet 4 was already mined.
- `Message` content is up for suggestions but keeping it empty would prevent bike shedding
- `Time stamp` time of mining or that of the block which hash is used in `Pubkey`
- Other parameters (`Difficulty: 0x1d00ffff`, `Version: 1`) should match Testnet 4.

Testnet 4 placeholders:

> * Message: <code>03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e</code>
> * Pubkey: <code>000000000000000000000000000000000000000000000000000000000000000000</code>
> * Time stamp: 1714777860
> * Nonce: 393743547
> * Difficulty: <code>0x1d00ffff</code>
> * Version: 1
> 
> The resulting Genesis block hash is <code>00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043</code>, and the block hex is <code>0100000000000000000000000000000000000000000000000000000000000000000000004e7b2b9128fe0291db0693af2ae418b767e657cd407e80cb1434221eaea7a07a046f3566ffff001dbb0c78170101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5504ffff001d01044c4c30332f4d61792f323032342030303030303030303030303030303030303030303165626435386332343439373062336161396437383362623030313031316662653865613865393865303065ffffffff0100f2052a010000002321000000000000000000000000000000000000000000000000000000000000000000ac00000000</code>.

### Message Start

The message start is defined as <code>0x46495645</code>. These four bytes spell `FIVE` when
interpreted as ASCII.

### Network Parameters

The default p2p port for Testnet 5 is `18335`.

## Backward Compatibility

Testnet 5's consensus rules are not compatible with those of Testnet 3 and Testnet 4. The
consensus rules differ in both directions: Testnet 5 enforces the BIP 54 consensus rules from
Genesis which is not the case for Testnet 3 or Testnet 4. Testnet 5 also does not apply the
difficulty exception rule from Testnet 3 or Testnet 4 requires.

Any implementation that intends to follow Testnet 5 must add the new network parameters and
additionally enforce the BIP 54 rules while not permitting any of the difficulty exception rules.

## Reference Implementation

Pull request at ?

## References

[block-storms]: https://blog.lopp.net/the-block-storms-of-bitcoins-testnet/
[bitcointalk-thread]: https://bitcointalk.org/index.php?topic=5569103.0
[signet-bip54]: https://delvingbitcoin.org/t/bitcoin-inqusition-29-2/2236
[BIP30]: bip-0030.mediawiki
[BIP54]: bip-0054.md
[BIP94]: bip-0094.mediawiki

## Copyright

This document is licensed under the Creative Commons CC0 1.0 Universal license.
