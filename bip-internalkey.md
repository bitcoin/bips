```
BIP: XXX
Layer: Consensus (soft fork)
Title: OP_INTERNALKEY
Author: Brandon Black <freedom@reardencode.com>, Jeremy Rubin <j@rubin.io>
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXXX
Status: Draft
Type: Standards Track
Created: 2023-12-22
License: BSD-3-Clause
```

## Abstract

This BIP describes a new tapscript opcode (`OP_INTERNALKEY`) which
pushes the taproot internal key to the stack.

## Specification

When verifying taproot script spends having leaf version `0xc0` (as defined in
[BIP 342]), `OP_INTERNALKEY` replaces `OP_SUCCESS203` (0xcb). `OP_INTERNALKEY`
pushes the taproot internal key, as defined in [BIP 341], to the stack.

## Motivation

### Key spend with additional conditions

When building taproot outputs, especially those secured by an aggregate key
representing more than one signer, the parties may wish to collaborate on
signing with the taproot internal key, but only with additional script
restrictions. In this case, `OP_INTERNALKEY` saves 8 vBytes.

### Mitigated control block overhead for scripts using hash locks

In cases where script path spending is not desired, the internal key may be set
to a NUMS point whose bytes would otherwise be required in a tapscript. This
could be used with any hash locked transaction, for example, to save 8 vBytes.

Note: The internal key must be the X coordinate of a point on the SECP256K1
curve, so any such hash must be checked and modified until it is such an X
coordinate. This will typically take approximately 2 attempts.

## Reference Implementation

A reference implementation is provided here:

https://github.com/bitcoin/bitcoin/pull/29269

## Backward Compatibility

By constraining the behavior of an OP_SUCCESS opcode, deployment of the BIP
can be done in a backwards compatible, soft-fork manner. If anyone were to
rely on the OP_SUCCESS behavior of `OP_SUCCESS203`, `OP_INTERNALKEY` would
invalidate their spend.

## Deployment

TBD

## Credits

TODO

## Copyright

This document is licensed under the 3-clause BSD license.

[BIP 341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

[BIP 342]: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
