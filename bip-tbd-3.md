```
  BIP: TBD-3
  Layer: Consensus (soft fork)
  Title: Coinbase Locktime Duplicate Prevention
  Authors: Antoine Poinsot <mail@antoinep.com>
           Matt Corallo <bips@bluematt.me>
  Status: Complete
  Type: Specification
  Assigned: ?
  License: CC0-1.0
```

## Abstract

This document proposes consensus restrictions on the coinbase transaction's `nLockTime` and
`nSequence` fields. These restrictions make new coinbase transactions distinct from earlier
BIP 34 violations and avoid the need to resume BIP 30 duplicate transaction validation.

## Motivation

Since [BIP 34][BIP34] activation, explicit [BIP 30][BIP30] validation is not necessary until block
height 1,983,702.[^1] Resuming [BIP 30][BIP30] validation would unnecessarily increase block
validation overhead and preclude alternative full node designs such as [BIP 182][BIP182] Utreexo.

Enforcing that new coinbase transactions are different from the early [BIP 34][BIP34] violations
makes it possible to get rid of [BIP 30][BIP30] validation forever.

## Specification

For all blocks after activation, the coinbase transaction's `nLockTime` field must be set to the
height of the block minus 1[^2] and the `nSequence` field of its sole input must not be equal to
`0xffffffff`.

## Rationale

The `nLockTime` field of transactions is a natural place to store a block height and is currently
unused in coinbase transactions. Using it to enforce that new coinbase transactions differ from
early [BIP 34][BIP34] violations also allows applications to recover the block height without
having to parse Script.

Leveraging the existing timelock mechanism makes the check self-contained: the same coinbase
transaction cannot have been valid in a previous block.[^3] This simplifies both reasoning and
client implementation, since the [BIP 30][BIP30] check can be skipped entirely past activation,
regardless of the [BIP 34][BIP34] activation status.[^4] Requiring the coinbase input's `nSequence`
field to be non-final ensures that `nLockTime` is consensus-enforced.

One person [raised the concern][miningdev nLockTime] that the `nLockTime` field would be an ideal
extranonce for ASIC controllers if such controllers ever became a bottleneck in mining operations.
Others [replied][miningdev nLockTime] that the same benefits could be achieved by using a dummy
output instead, should that ever become necessary. The authors [believe][ML remaining concerns] the
benefits of using `nLockTime` to differentiate coinbase transactions outweigh the theoretical cost
of making it unavailable for extranonce rolling by ASIC controllers.

## Backward compatibility

This proposal only tightens the block validation rules: there is no block that is valid under the
rules proposed in this BIP but not under the existing Bitcoin consensus rules. As a consequence,
these changes are backward-compatible with non-upgraded node software. That said, the authors
strongly encourage node operators to upgrade in order to fully validate all consensus rules.

## Miner forward compatibility

The coinbase transaction is usually crafted by mining pool software. To the best of the authors'
knowledge, there does not exist an open source reference broadly in use today for such software.
We encourage mining pools to update their software to craft coinbase transactions that are
forward-compatible with the changes proposed in this BIP.

## Reference implementation

An implementation of this rule as part of BIP 54 is available [here][Core BIP 54 implem].

## Test vectors

Test vectors for this rule are available in [`coinbases.json`](./bip-0054/test_vectors/coinbases.json).

## Copyright

This document is licensed under the Creative Commons CC0 1.0 Universal license.

[^1]: Block 1,983,702 is the earliest future block which could contain a duplicate coinbase
transaction while still respecting [BIP 34][BIP34]. See [this post][Delving duplicable] for a list
of all such future blocks.
[^2]: The locktime validation, which is also performed for coinbase transactions, enforces that the
`nLockTime` value is the last block at which a transaction is invalid, not the first one at which it
is valid.
[^3]: Technically it could be argued a duplicate could in principle always be possible before block
31,001 when `nLockTime` enforcement [was originally soft-forked][Harding nLockTime]. But treating
coinbase transactions as not having duplicate past activation would be consistent for any
implementation which enforces `nLockTime` from the genesis block, which is the behaviour notably of
Bitcoin Core but also of all other implementations the authors are aware of.
[^4]: For instance Bitcoin Core only disables [BIP 30][BIP30] validation for a specific chain where
[BIP 34][BIP34] violations have been manually inspected. Without the guarantee given by enforcing
the timelock on coinbase transactions, this would have to be perpetuated after activation.

[BIP30]: https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki
[BIP34]: https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
[BIP182]: https://github.com/bitcoin/bips/pull/1923
[Delving duplicable]: https://delvingbitcoin.org/t/great-consensus-cleanup-revival/710/4
[Harding nLockTime]: https://bitcoin.stackexchange.com/questions/90229/nlocktime-in-bitcoin-core
[miningdev nLockTime]: https://groups.google.com/g/bitcoinminingdev/c/jlqlNHHNSNk
[ML remaining concerns]: https://gnusha.org/pi/bitcoindev/UsKuvCXXhSAnNVx5a0K2UfP3srAr3slW9mcOjtYk9LnolaOXfWrW9jpqbxsQQPkyQuZogkhz2Hbfwii2VsTm79vRDpgKduxk35hpBu_t7Do=@protonmail.com/
[Core BIP 54 implem]: https://github.com/darosior/bitcoin/tree/bip54
