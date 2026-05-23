```
  BIP: TBD-1
  Layer: Consensus (soft fork)
  Title: Difficulty Period Timestamp Limits
  Authors: Antoine Poinsot <mail@antoinep.com>
           Matt Corallo <bips@bluematt.me>
  Status: Complete
  Type: Specification
  Assigned: ?
  License: CC0-1.0
```

## Abstract

This document proposes consensus restrictions on block timestamps at the boundaries of each 2016-block
difficulty adjustment period. These restrictions fix the timewarp attack and the Murch-Zawy
negative-time-period vulnerability.

## Motivation

The [timewarp bug][SE timewarp] makes it possible for a majority-hashrate attacker to arbitrarily
lower mining difficulty, and therefore arbitrarily increase the block rate. In the worst case, an
attacker can bring down the difficulty to its minimum within 38 days of starting the attack. Besides
empowering a 51% attacker, the presence of this bug makes it harder to reason about miners'
incentives. Accelerating the block rate allows an attacker to steal block subsidy from future
miners and increases available block space. It may be in the interest of short-sighted users and
miners to exploit this vulnerability to materially increase the block rate without fatally hurting
the network.

The [Murch-Zawy attack][Delving Murch-Zawy] allows the duration of a difficulty adjustment period to
become negative by manipulating the last block timestamp of the period. While the practical impact is
mostly theoretical, it is straightforward to prevent at the same difficulty-period boundary where the
timewarp mitigation applies.

## Specification

For all blocks after activation, the following new rules apply.

Given a block at height `N` with timestamp T<sub>N</sub>:

- if `N % 2016` is equal to 0, the timestamp of the block must be set to a value higher than or
  equal to the value of the timestamp of block at height `N-1` minus 7200
  (T<sub>N</sub> &ge; T<sub>N-1</sub> - 7200);
- if `N % 2016` is equal to 2015, the timestamp of the block must be set to a value higher than
  or equal to the value of the timestamp of the block at height `N-2015`
  (T<sub>N</sub> &ge; T<sub>N-2015</sub>).

## Rationale

The restriction on the timestamp of the first block of a difficulty adjustment period fixes the
timewarp vulnerability by preventing the first timestamp in the period from being much lower than the
last timestamp in the preceding period. A two-hour grace period is provided to avoid invalidating
blocks produced by software with minor timestamp inconsistencies.

The restriction on the timestamp of the last block of a difficulty adjustment period fixes the
Murch-Zawy vulnerability by ensuring that each retarget period has a non-negative duration.

A [previous proposal][BIP-XXXX] to fix the timewarp attack used a ten-minute grace period instead,
and this approach has been adopted for [testnet4][BIP94 timewarp]. Out of an abundance of caution
and because it only trivially worsens the block rate increase under attack, a two-hour grace period
is used here.[^1]

## Backward compatibility

This proposal only tightens the block validation rules: there is no block that is valid under the
rules proposed in this BIP but not under the existing Bitcoin consensus rules. As a consequence,
these changes are backward-compatible with non-upgraded node software. That said, the authors
strongly encourage node operators to upgrade in order to fully validate all consensus rules.

## Miner forward compatibility

Bitcoin Core version [29.0][Core 29.0] and later will not generate a block template that violates
the timestamp restrictions introduced in this BIP. Although it would be extremely unlikely due to
the grace period used in this proposal, miners should use the `curtime` or `mintime` field from the
`getblocktemplate` result for their block's timestamp to make sure they always create blocks valid
according to this proposal. Note this is not a new requirement: using a timestamp lower than the
`mintime` field from the `getblocktemplate` result already leads to creating an invalid block.

## Reference implementation

An implementation of this rule as part of BIP 54 is available [here][Core BIP 54 implem].

## Test vectors

Test vectors for this rule are available in [`timestamps.json`](./bip-0054/test_vectors/timestamps.json).

## Copyright

This document is licensed under the Creative Commons CC0 1.0 Universal license.

[^1]: The testnet4 difficulty exception pushed blocks' timestamps in the future when abused,
revealing how some broken pool software may produce blocks that don't respect a 10-minute grace
period. Some [raised concerns][Sjors grace period] similarly broken software might be used on
mainnet. Using a grace period of 2 hours instead of 10 minutes only reduces the expected block
interval time under attack by approximately 2.2 seconds. See [this post][grace period debate
summary] for more.

[SE timewarp]: https://bitcoin.stackexchange.com/questions/75831/what-is-time-warp-attack-and-how-does-it-work-in-general/75834#75834
[Delving Murch-Zawy]: https://delvingbitcoin.org/t/zawy-s-alternating-timestamp-attack/1062#variant-on-zawys-attack-2
[BIP-XXXX]: https://github.com/TheBlueMatt/bips/blob/7f9670b643b7c943a0cc6d2197d3eabe661050c2/bip-XXXX.mediawiki
[BIP94 timewarp]: https://github.com/bitcoin/bips/blob/master/bip-0094.mediawiki#time-warp-fix
[Sjors grace period]: https://delvingbitcoin.org/t/timewarp-attack-600-second-grace-period/1326
[grace period debate summary]: https://delvingbitcoin.org/t/great-consensus-cleanup-revival/710/66
[Core 29.0]: https://bitcoincore.org/en/releases/29.0
[Core BIP 54 implem]: https://github.com/darosior/bitcoin/tree/bip54
