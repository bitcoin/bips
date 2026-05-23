```
  BIP: TBD-2
  Layer: Consensus (soft fork)
  Title: Legacy Sigops Transaction Limit
  Authors: Jeremy Rubin <j@rubin.io>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: CC0-1.0
```

## Abstract

This document proposes a per-transaction consensus limit on legacy signature operations. The limit
reduces the worst case block validation time while preserving existing Script functionality.

## Motivation

Specially crafted blocks may be expensive to process, [taking up to][Delving worst block] several
minutes to validate even on high-end devices, and up to a few hours on lower-end devices. Long block
validation times are a nuisance to users, increasing the cost to independently fully validate the
consensus rules. In addition, they can be used by miners to attack their competition, creating
perverse incentives, centralization pressures, and leading to reduced network security.

## Specification

For all blocks after activation, a limit is set on the number of signature operations present in the
scripts used to validate a transaction. It applies to all transactions in the block except the
coinbase transaction.[^1]

For each input in the transaction, count the number of `CHECKSIG` and `CHECKMULTISIG` operations in
the input scriptSig and previous output's scriptPubKey, including the P2SH redeemScript. If the
total summed over all transaction inputs is strictly higher than 2500, the transaction is invalid.
The accounting is the same as for [BIP 16][BIP16 specs], evaluating the scriptSig, scriptPubKey, and
P2SH redeemScript separately:

1. `CHECKSIG` and `CHECKSIGVERIFY` count as 1 signature operation, whether or not they are evaluated.
2. `CHECKMULTISIG` and `CHECKMULTISIGVERIFY` immediately preceded by `OP_1` through `OP_16` are counted as 1 to 16 signature operations, whether or not they are evaluated.
3. All other `CHECKMULTISIG` and `CHECKMULTISIGVERIFY` operations are counted as 20 signature operations, whether or not they are evaluated.

## Rationale

Disabling some Script operations and functionalities was [previously proposed][BIP-XXXX] to reduce
the worst case block validation time but was met with resistance due to confiscation concerns.[^2]
A delicate balance needs to be struck between minimizing the confiscation risks of a mitigation,
even if merely theoretical, and bounding the costs one could impose on all other users of the
system. To that end, limiting potentially executed signature operations targets the exact harmful
behaviour while preserving maximal flexibility in Script usage.

Such a limit reduces the worst case block validation time by a factor of 40 and drastically
increases the preparation cost of an attack, making it uneconomical for a miner.[^3] The maximum of
2500 was chosen as the tightest value that did not make any non-pathological standard transaction
invalid.[^4]

## Backward compatibility

This proposal only tightens the block validation rules: there is no block that is valid under the
rules proposed in this BIP but not under the existing Bitcoin consensus rules. As a consequence,
these changes are backward-compatible with non-upgraded node software. When this proposal is slated
for activation, node operators are encouraged to upgrade in order to fully validate all consensus
rules.

## Miner forward compatibility

Bitcoin Core version [30.0][Core 30.0] and later will not generate a block template including a
transaction that violates the signature operations limit introduced in this BIP.

## Reference implementation

An implementation of this rule as part of BIP 54 is available [here][Core BIP 54 implem].

## Test vectors

Test vectors for this rule are available in [`sigops.json`](./bip-tbd-2/test_vectors/sigops.json).

## Acknowledgements

This document was split out from [BIP 54](bip-0054.md).

## Copyright

This document is licensed under the Creative Commons CC0 1.0 Universal license.

[^1]: Technically this limit cannot apply to a coinbase transaction as the size of its sole input's
scriptSig is limited.
[^2]: The argument is about someone having a timelocked presigned transaction using some of those
features in its output script. The transaction cannot be mined before activation. Such outputs would
not be covered by an amnesty for old UTxOs. See for instance [here][O'Connor OP_CODESEPARATOR] and
[here][O'Connor sighash type] for discussions on this topic.
[^3]: It is important to reduce the worst case block validation time as well as the ratio of
validation time imposed over preparation cost. The former is to limit the damages an externally
motivated attacker can do. The latter is to disincentivize miners slowing down their competition by
mining expensive blocks. See [this thread][ML thread validation time] for more.
[^4]: A non-pathological transaction would have a public key per signature operation and at least
one signature per input. Per standardness a single P2SH input may not have more than 15 signature
operations. Even by using 1-of-15 `CHECKMULTISIG`s a transaction would bump against the maximum
standard transaction size before running into the newly introduced limit. To run against the newly
introduced limit but not the transaction size a transaction would need to spend P2SH inputs with a
redeem script similar to `CHECKSIG DROP CHECKSIG DROP ...`. This type of redeem script serves no
purpose beyond increasing its validation cost, which is exactly what this proposal aims to mitigate.

[Delving worst block]: https://delvingbitcoin.org/t/great-consensus-cleanup-revival/710/93
[BIP16 specs]: https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki#specification
[BIP-XXXX]: https://github.com/TheBlueMatt/bips/blob/7f9670b643b7c943a0cc6d2197d3eabe661050c2/bip-XXXX.mediawiki
[O'Connor OP_CODESEPARATOR]: https://gnusha.org/pi/bitcoindev/CAMZUoKneArC+YZ36YFwxNTKsDtJhEz5P2cosXKxJS8Rf_3Nyuw@mail.gmail.com
[O'Connor sighash type]: https://gnusha.org/pi/bitcoindev/CAMZUoK=1kgZLR1YZ+cJgzwmEOwrABYFs=2Ri=xGX=BCr+w=VQw@mail.gmail.com
[ML thread validation time]: https://gnusha.org/pi/bitcoindev/VsltJ2PHqWfzG4BU9YETTXjL7fYBbJhjVXKZQyItemySIA1okvNee9kf0zAOyLMeJ4Nqv1VOrYbWns5nP4TANCWvPJYu1ew_yxQSaudizzk=@protonmail.com
[Core 30.0]: https://bitcoincore.org/en/releases/30.0
[Core BIP 54 implem]: https://github.com/darosior/bitcoin/tree/bip54
