```
BIP: XXX
Layer: Consensus (soft fork)
Title: CHECKSIGFROMSTACK
Author: Brandon Black <freedom@reardencode.com>, Jeremy Rubin <j@rubin.io>
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXXX
Status: Draft
Type: Standards Track
Created: 2023-12-22
License: BSD-3-CLAUSE
```

## Abstract

This BIP describes two new opcodes for the purpose of checking cryptographic
signatures in bitcoin scripts against data other than bitcoin transactions.

## Summary

We propose replacing `OP_NOP5` (0xb4) in bitcoin script with
`OP_CHECKSIGFROMSTACKVERIFY`. When verifying taproot script spends having
leaf version 0xc0 (as defined in [BIP 342]), we propose `OP_CHECKSIGFROMSTACK`
to replace `OP_SUCCESS204` (0xcc).

`OP_CHECKSIGFROMSTACK` and `OP_CHECKSIGFROMSTACKVERIFY`
have semantics similar to `OP_CHECKSIG` and
`OP_CHECKSIGVERIFY` respectively, as specified below.

Only 32-byte keys are constrained. Similar to [BIP 341] unknown key types, for
other key lengths no signature verification is performed.

## Specification

* If fewer than 3 elements are on the stack, the script MUST fail and terminate immediately.
* The public key (top element), message (second to top element), and signature (third from top element) are read from the stack.
* For `OP_CHECKSIGFROMSTACK` the top three elements are popped from the stack.
* If the public key size is zero, the script MUST fail and terminate immediately.
* If the public key size is 32 bytes, it is considered to be a public key as described in [BIP 340]:
    * If the signature is not the empty vector, the signature is validated against the public key and message according to [BIP 340]. Validation failure in this case immediately terminates script execution with failure.
* If the public key size is not zero, and it is not a [BIP 340] public key; the public key is of an unknown public key type, and no actual signature verification is applied. During script execution of signature opcodes they behave exactly as known public key types except that signature validation is considered to be successful.
* If the script did not fail and terminate before this step, regardless of the public key type:
    * If the signature is the empty vector:
        * For `OP_CHECKSIGFROMSTACKVERIFY`, the script MUST fail and terminate immediately.
        * For `OP_CHECKSIGFROMSTACK`, an empty vector is pushed onto the stack, and execution continues with the next opcode.
    * If the signature is not the empty vector:
        * For tapscript 0xc0, the opcode is counted towards the sigops budget as described in [BIP 342].
        * For legacy and segwit v0, the opcode is counted towards the sigops limit, as described in [BIP 141]
        * For `OP_CHECKSIGFROMSTACKVERIFY`, execution continues without any further changes to the stack.
        * For `OP_CHECKSIGFROMSTACK`, a 1-byte value 0x01 is pushed onto the stack.

## Design Considerations

1. Message hashing: [BIP 340] is compatible with any size of message and does not require it to be a securely hashed input, so the message is not hashed prior to [BIP 340] verification.
2. Verify NOP upgrade: To bring stack signature verification to legacy and segwitv0 bitcoin script, a NOP upgrade path was chosen for `OP_CHECKSIGFROMSTACKVERIFY`. This necessarily means leaving the 3 arguments on the stack when executing `OP_CHECKSIGFROMSTACKVERIFY`. Scripts will need to drop or otherwise manage these stack elements.
3. Add/multisig: No concession is made to `OP_CHECKMULTISIG` or `OP_CHECKSIGADD` semantics with `OP_CHECKSIGFROMSTACK(VERIFY)`. In Tapscript, add semantics can be implemented with 1 additional vByte per key (`OP_TOALTSTACK OP_CHECKSIGFROMSTACK OP_FROMALTSTACK OP_ADD`).
4. Splitting R/S on the stack: Implementing split/separate signatures is left as an exercise for other bitcoin upgrades, such as `OP_CAT`.
5. [BIP 118]-style Taproot internal key: Rather than introducing an additional key type in this change, we suggest implementing OP_INTERNALKEY or separately introducing that key type for all Tapscript signature checking operations in a separate change.
6. Unknown key lengths: The semantics of other signature checking opcodes in their respective script types (legacy, segwit-v0, tapscript-c0) are applied.

## Resource Limits

These opcodes are treated identically to other signature checking opcodes and
count against the various sigops limits and budgets in their respective script
types.

## Motivation

### LN Symmetry

When combined with [BIP 119] (`OP_CHECKTEMPLATEVERIFY`/CTV),
`OP_CHECKSIGFROMSTACK` (CSFS) can be used in Lightning Symmetry channels.
The construction `OP_CHECKTEMPLATEVERIFY <pubkey> OP_CHECKSIGFROMSTACK` with a
spend stack containing the CTV hash and a signature for it is logically
equivalent to `<bip118_pubkey> OP_CHECKSIG` and a signature over
`SIGHASH_ALL|SIGHASH_ANYPREVOUTANYSCRIPT`. The `OP_CHECKSIGFROMSTACK`
construction is 8 vBytes larger.

### Delegation

Using a script like:
`<pubkey> SWAP IF 2 PICK SWAP CSFSV ENDIF CHECKSIG`
either direct verification or delegation can be achieved by the following
unlock stacks: `<sig> 0` or `<dsig> <dpubkey> <sig> 1`

## Reference Implementation

A reference implementation is provided in provided here:

https://github.com/bitcoin/bitcoin/pull/29270

## Backward Compatibility

By constraining the behavior of an OP_SUCCESS opcode and an OP_NOP opcode,
deployment of the BIP can be done in a backwards compatible, soft-fork manner.
If anyone were to rely on the OP_SUCCESS behavior of
`OP_SUCCESS204`, `OP_CHECKSIGFROMSTACK` would invalidate
their spend.

## Deployment

TBD

## Credits

Reference implementation was made with reference to the implementation in
Elements and started by moonsettler.

## Copyright

This document is licensed under the 3-clause BSD license.

[BIP 119]: https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki

[BIP 118]: https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki

[BIP 340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

[BIP 341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

[BIP 342]: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki

[OP_CAT]: https://github.com/EthanHeilman/op_cat_draft/blob/main/cat.mediawiki

[mailing list]: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2021-July/019192.html
