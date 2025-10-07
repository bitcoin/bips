```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: OP_TEMPLATEHASH
  Author: Gregory Sanders <gsanders87@gmail.com>
          Antoine Poinsot <mail@antoinep.com>
          Steven Roose <steven@stevenroose.org>
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-?
  Status: Draft
  Type: Standards Track
  Created: ?
  License: CC0-1.0
```

## Abstract

This document proposes a new operation for [Tapscript][tapscript-bip]: `OP_TEMPLATEHASH`. It introduces the ability to
push on the stack a hash of the transaction spending an output.

## Motivation

`OP_TEMPLATEHASH` can be used to commit to the transaction spending an output[^commit-exact-tx]. This capability
can replace the use of pre-signed transactions in second-layer protocols. By reducing interactivity it makes such
protocols simpler, safer, and sometimes notably more efficient. For instance it can remove the need to share HTLC
signatures in the Lightning Network protocol's [`commitment_signed` message][ln-commit-signed][^ln-second-stage], make
receiving an Ark "VTXO" [non-interactive][ark-case-ctv], and [reduces roundtrips][symmetric-greg] in the implementation
of LN-Symmetry. It is also a [significant optimisation][fournier-ctv-dlcs] for [Discreet Log Contracts][optech-dlcs].

## Specification

`OP_TEMPLATEHASH` redefines `OP_SUCCESS187` (0xbb) in the Tapscript execution context with further restrictions.

Upon execution of the opcode, the template hash of the transaction in context is pushed onto the stack as defined below,
and script execution continues.

The template hash uses a tagged hash as introduced by [BIP340][schnorr-bip] and [BIP341][taproot-bip]. We use a new tag
for this purpose: *TemplateHash*.

The template hash re-uses the *sha_sequences*, *sha_outputs* and *sha_annex* pre-computed transaction data introduced in
BIP341. Numerical values in 4-byte are encoded in little-endian.

The template hash is the *hash<sub>TemplateHash</sub>* of the following transaction fields concatenated:

- Transaction data:
    - *nVersion* (4): the version of the transaction.
    - *nLockTime* (4): the locktime of the transaction.
    - *sha_sequences* (32): the SHA256 of the serialization of all input sequence, as per BIP341.
    - *sha_outputs* (32): the SHA256 of the serialization of all outputs in `CTxOut` format, as per BIP341.
- Data about this input:
    - *annex_present* (1): as defined in BIP341 (0 if no annex is present, or 1 otherwise).
    - *input_index* (4): index of this input in the transaction input vector. Index of the first input is 0.
    - If an annex is present:
        - *sha_annex* (32): the SHA256 of the annex, as per BIP341.

## Rationale

The template hash follows BIP341's signature message format, with minimal necessary deviations. This reuses a
tried-and-proven approach to hashed messages, and importantly makes it possible to reuse the pre-computed subfields
introduced by BIP341 to prevent quadratic hashing. Besides the hash tags, this results in at most 109 bytes being hashed
upon execution of the operation[^hashed-msg-max-size]. This is strictly less hashing than is necessary for other
existing operations.

The specific fields from the BIP341 signature message that are ommitted when computing the template hash are the
following:
- *hash_type*: this is the sighash type identifier. Only a single hash type is supported by `OP_TEMPLATEHASH`, so there
  is no need to commit to such an identifier.
- *spend_type*: this value is defined by BIP341 as *2\*ext_flag + annex_present*. Since no extension is appended to the
  signature message, *ext_flag* is set to 0. Therefore we commit directly to *annex_present*.
- *sha_prevouts* / *sha_scriptpubkeys*: committing to these fields as is would introduce a hash cycle when the hash is
  committed in the output itself. Committing to all other prevouts or scriptpubkeys would introduce hashing a quantity
  of data quadratic in the number of inputs. It would also prevent spending two coins encumbered by a template hash
  check in the same transaction. Finally, the flexibility of not committing to the specific coins spent is also
  desirable to recover from mistakes[^no-commit-other-coins].
- *sha_amounts*: the BIP341 rationale for committing to the amounts of all spent coins is to be able to prove to an offline
  signer the fees of a transaction. Although `OP_TEMPLATEHASH` can be used as a building block for rebindable
  signatures, the utility of committing to spent amounts but not spent scriptpubkeys [is
  limited][greg-attack-input-ownership]. Still for rebindable signatures, committing to spent amounts can be justified
  as defense-in-depth against implementation mistakes[^commit-spent-amounts]. However, the lack of flexibility this
  introduces also makes it harder to recover from a mistake in committing to the next
  transaction[^no-commit-other-coins]. Furthermore, committing to all spent amounts also makes overcommitting funds to
  such a script result in the output being forever unspendable instead of the excess just going to fees at spend time.

The design of `OP_TEMPLATEHASH` was inspired by the design of [BIP119][ctv-bip] `OP_CHECKTEMPLATEVERIFY` but differs in
several important ways.

First of all, `OP_TEMPLATEHASH` is only defined for Tapscript, as modifying legacy Script comes with an unnecessarily
increased risk surface. In addition, sticking to Tapscript allows leveraging more powerful upgrade hooks (`OP_SUCCESS`s
instead of `OP_NOP`s) which make it possible to push the template hash on the stack instead of being constrained to
strict assertions with no stack modification. Pushing the template hash on the stack substantially improves the
efficiency of using `OP_TEMPLATEHASH` as a building block for rebindable signatures.

Unlike `OP_TEMPLATEHASH`, `OP_CHECKTEMPLATEVERIFY` also commits to the scriptSig of all inputs of the spending
transaction. `OP_CHECKTEMPLATEVERIFY` gives txid stability when the committed spending transaction has a single input,
and when the scriptSig of this single input has been committed by the hash.
Taproot scriptSigs must be empty and therefore under the single input case `OP_TEMPLATEHASH` has no requirement
to commit to scriptSigs to achieve txid stability.

Finally, BIP119 `OP_CHECKTEMPLATEVERIFY` does not commit to the Taproot annex (or its absence). `OP_TEMPLATEHASH` does.
Deviating from other operations which do commit to the annex would be unnecessary and surprising. Committing to the
annex also makes usage of `OP_TEMPLATEHASH` forward compatible with potential future meaning that it could be given. Not
committing to it would also prevent using `OP_TEMPLATEHASH` in conjunction with annex-based proof of publication
techniques unless additional signatures are included, as used for instance [in the LN-Symmetry demo][symmetry-annex-publication].

Programmable transaction introspection capabilities have been proposed as an alternative to a primitive which only
allows committing to the exact next transaction. It remains to be shown that these more flexible capabilities do
enable important use cases which justify each proposed change's specific semantics and implementation complexity. It
has been suggested that the new primitive should have its own upgrade hook from which to softfork in additional
consensus meaning for more flexible introspection at some future point. We have not done so due to the fact that Taproot
and Tapscript already presents plentiful upgrade hooks for the future.

## Backward compatibility

This document proposes to give meaning to a Tapscript `OP_SUCCESS` operation. The presence of an `OP_SUCCESS` in a
Tapscript would previously make it unconditionally succeed. This proposal therefore only tightens the block validation
rules: there is no block that is valid under the rules proposed in this BIP but not under the existing Bitcoin consensus
rules. As a consequence these changes are backward-compatible with non-upgraded node software. That said, the authors
strongly encourage node operators to upgrade in order to fully validate all consensus rules.

## Implementation

* https://github.com/instagibbs/bitcoin/tree/2025-07-op_templatehash

## Test Vectors

For development and testing purposes, we provide a [collection of test vectors](bip-templatehash/test_vectors). The test
vectors are separated into two JSON files. The [first one](bip-templatehash/test_vectors/basics.json) is a short list of
simple test cases exercising the various fields of a transaction committed to when using `OP_TEMPLATEHASH`. The [second
one](bip-templatehash/test_vectors/script_assets_test.json) is a more exhaustive suite of tests exercising `OP_TEMPLATEHASH`
under a large number of different conditions. It reuses the [Bitcoin Core Taproot test framework][feature_taproot.py]
introduced with the implementation of BIP341. Format details and usage demonstration are available
[here](bip-templatehash/test_vectors/README.md).

## Acknowledgements

Credit to Jeremy Rubin for his leadership and perseverance in defending how a simple primitive which
allows committing to the entire spending transaction is useful for reducing
interactivity in second layer protocols. This BIP draws on the design of BIP119 and is
heavily inspired by his exploration of the potential uses for such a primitive.

## Copyright

This document is licensed under the Creative Commons CC0 1.0 Universal license.


[^ln-second-stage]: Second-stage HTLC transactions are currently enforced through a 2-of-2 multisig between the channel
partners. Committing to the HTLC transaction directly in the commitment transaction's HTLC output is a drop-in
replacement for the multisig, which has the advantage of not requiring Lightning nodes to transmit and store signatures
for every HTLC at every state it is still active for.
[^commit-exact-tx]: All the transaction's fields are committed to except the inputs' prevout. This means the output must
be spent by this exact transaction, although the other spent outputs may vary.
[^no-commit-other-coins]: It is possible to commit to an underfunded transaction to spend a coin. If the transaction
commits to more than one input, it is possible to recover from the mistake by creating a separate coin of an appropriate
value and spending it along with the encumbered coin. Committing to other inputs this transaction must spend or their
input removes the ability to recover from such a mistake.
[^commit-spent-amounts]: Adding commitments to the spent amounts may offer extra protection when reusing a public key
previously associate with a rebindable signature. See [BIP118's rationale][apo-bip-spent-amounts] for more about this.
[^hashed-msg-max-size]: If no annex is committed, 77 bytes are hashed: 72 bytes of transaction data + 5 bytes of data
about this input. Committing to an annex adds 32 additional bytes of data about this input, bringing the total to 109.


[schnorr-bip]: bip-0340.mediawidi
[taproot-bip]: bip-0341.mediawidi
[tapscript-bip]: bip-0342.mediawidi
[csfs-bip]: bip-0348.md
[ctv-bip]: bip-0119.md
[apo-bip-spent-amounts]: https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki#cite_note-3
[ark-case-ctv]: https://delvingbitcoin.org/t/the-ark-case-for-ctv/1528
[symmetric-greg]: https://delvingbitcoin.org/t/ln-symmetry-project-recap/359
[greg-attack-input-ownership]: https://gnusha.org/pi/bitcoindev/CAB3F3Dv1kuJdu8veNUHa4b58TvWy=BT6zfxdhqEPBQ8rjDfWtA@mail.gmail.com
[symmetry-annex-publication]: https://github.com/instagibbs/bolts/blob/eltoo_draft/XX-eltoo-transactions.md#update-transaction
[ln-commit-signed]: https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#committing-updates-so-far-commitment_signed
[fournier-ctv-dlcs]: https://gnusha.org/pi/bitcoindev/CAH5Bsr2vxL3FWXnJTszMQj83jTVdRvvuVpimEfY7JpFCyP1AZA@mail.gmail.com
[optech-dlcs]: https://bitcoinops.org/en/topics/discreet-log-contracts
[feature_taproot.py]: https://github.com/bitcoin/bitcoin/blob/v29.0/test/functional/feature_taproot.py
