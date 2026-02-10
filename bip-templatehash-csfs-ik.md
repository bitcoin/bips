```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: Next-transaction and Rebindable Signatures
  Author: Gregory Sanders <gsanders87@gmail.com>
          Antoine Poinsot <mail@antoinep.com>
          Steven Roose <steven@stevenroose.org>
  Status: Draft
  Type: Specification
  License: CC0-1.0
```

## Abstract

This document proposes bundling three new operations for [Tapscript][tapscript-bip]:
[`OP_TEMPLATEHASH`][templatehash-bip], [`BIP348 OP_CHECKSIGFROMSTACK`][csfs-bip], and [`BIP349 OP_INTERNALKEY`][internalkey-bip].

These minimal operations introduce modular functionalities which improve existing second layer protocols and make new
ones possible through plausible interactivity requirements.

## Motivation

The three proposed operations are simple, well-understood, and enable powerful new capabilities while minimizing the
risk of surprising behavior or unintended applications. They improve existing, well-studied protocols and make promising
new ones possible.

`OP_TEMPLATEHASH` enables committing to the transaction spending an output. `OP_CHECKSIGFROMSTACK` enables
[BIP340][schnorr-bip] signature verification of arbitrary messages. `OP_INTERNALKEY` allows to push the
[Taproot][taproot-bip] internal key on the stack.

The ability to commit to the future transaction spending an output is useful to reduce interactivity in second-layer
protocols. For instance it can [reduce roundtrips][symmetric-greg] in the implementation of [LN-Symmetry][optech-eltoo], or make
creating an [Ark][optech-ark] "VTXO" [non-interactive][ark-case-ctv]. Additionally, it enables [significant
optimizations][fournier-dlc-ctv] in the implementation of [Discreet Log Contracts][optech-dlcs].

The ability to verify a signature for an arbitrary message in Tapscript enables delegation and oracle attestations. This capability can
for instance [significantly reduce][bitvm-ctv-csfs] the onchain footprint of [BitVM][bitvm-website]. Reducing the onchain
footprint of an application is beneficial to users of Bitcoin especially as it reduces economic demand for
extremely large transactions that induce further mining centralization pressures[^large-txs-mining-centralization].

Together, these features enable rebindable transaction signatures, making possible a new type of payment channel: LN-Symmetry ("Eltoo").
Its simplicity makes advanced constructs like multiparty channels practical, while also enabling simplifications of 2-party channels such as [Daric][daric-channels]. The same techniques can also substantially improve [statechains][statechains-optech]. Rebindable signatures also enable further interactivity reduction
in second layer protocols, as illustrated by the Ark variant "[Erk][ark-erk]" or the [dramatic simplification][greg-rebindable-ptlcs]
they bring to upgrading today's Lightning to [Point Time Locked Contracts][optech-ptlcs].

The ability to push the Taproot internal key on the stack is a natural and extremely simple optimisation for rebindable
signatures.

## Rationale

This proposal seeks to extend Bitcoin's scripting capabilities in areas that are useful to proven approaches to scaling
Bitcoin payments. The operations proposed to achieve
these capabilities are contained within the more modern and well-studied Tapscript context. They are simple, composable
and unlikely to be made obsolete by future extensions to Bitcoin Script. They build upon existing operations and
therefore present a minimal cost to validation and implementation complexity.

More modular operations (such as [BIP346][txhash-bip]) also enable these capabilities, and more. However they also present
more implementation complexity and introduce more risks of enabling, or substantially simplifying, undesirable
applications. As the additional capabilities have not been demonstrated to enable new important use cases or
substantially improve existing ones, this proposal favours the minimal approach.

`OP_TEMPLATEHASH` enables the same capability [BIP119][ctv-bip]'s `OP_CHECKTEMPLATEVERIFY` does. The former is preferred because:
- it does not unnecessarily modify legacy scripting contexts;
- the template hashed minimally departs from Taproot signature hashes, simplifying the implementation
  and, importantly, committing to the Taproot annex;
- it does not limit itself to the verify semantic required by the legacy `OP_NOP` upgrade hooks, making rebindable
  signatures usage more efficient;
- it prevents surprising interactions with programs in a transaction input's `scriptSig`.

## Implementation

[`OP_TEMPLATEHASH`][templatehash-bip], [`BIP348 OP_CHECKSIGFROMSTACK`][csfs-bip], and [`BIP349 OP_INTERNALKEY`][internalkey-bip] implemented as specified in their corresponding documents.

## Backward compatibility

This document proposes to give meaning to three Tapscript `OP_SUCCESS` operations. The presence of an `OP_SUCCESS` in a
Tapscript would previously make it unconditionally succeed. This proposal therefore only tightens the block validation
rules: there is no block that is valid under the rules proposed in this BIP but not under the existing Bitcoin consensus
rules. As a consequence these changes are backward-compatible with non-upgraded node software. That said, the authors
strongly encourage node operators to upgrade in order to fully validate all consensus rules.

## Acknowledgements

This proposal is similar to the combination of opcodes Brandon Black previously
[proposed](https://delvingbitcoin.org/t/lnhance-bips-and-implementation/376) for activation under the name "LNHANCE".

## Copyright

This document is licensed under the Creative Commons CC0 1.0 Universal license.

[^large-txs-mining-centralization]: Large transactions are difficult to relay through the p2p network as they make it
harder for nodes to reason about miners' block templates. This may lead to a situation where such transactions get
submitted directly to miners. See [this discussion][sipa-large-txs] for more details.

[templatehash-bip]: bip-templatehash.md
[ctv-bip]: bip-0119.mediawiki
[csfs-bip]: bip-0348.md
[internalkey-bip]: bip-0349.md
[schnorr-bip]: bip-0340.mediawiki
[taproot-bip]: bip-0341.mediawiki
[tapscript-bip]: bip-0342.mediawiki
[optech-ark]: https://bitcoinops.org/en/topics/ark
[optech-dlcs]: https://bitcoinops.org/en/topics/discreet-log-contracts
[optech-eltoo]: https://bitcoinops.org/en/topics/eltoo
[optech-ptlcs]: https://bitcoinops.org/en/topics/ptlc
[txhash-bip]: https://github.com/bitcoin/bips/pull/1500
[symmetric-greg]: https://delvingbitcoin.org/t/ln-symmetry-project-recap/359
[ark-case-ctv]: https://delvingbitcoin.org/t/the-ark-case-for-ctv/1528
[bitvm-ctv-csfs]: https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591
[sipa-large-txs]: https://delvingbitcoin.org/t/non-confiscatory-transaction-weight-limit/1732/8
[ark-erk]: https://delvingbitcoin.org/t/evolving-the-ark-protocol-using-ctv-and-csfs/1602
[greg-rebindable-ptlcs]: https://delvingbitcoin.org/t/ctv-csfs-can-we-reach-consensus-on-a-first-step-towards-covenants/1509/18
[fournier-dlc-ctv]: https://gnusha.org/pi/bitcoindev/CAH5Bsr2vxL3FWXnJTszMQj83jTVdRvvuVpimEfY7JpFCyP1AZA@mail.gmail.com
[bitvm-website]: https://bitvm.org
[daric-channels]: https://eprint.iacr.org/2022/1295
[statechains-optech]: https://bitcoinops.org/en/topics/statechains/
