<pre>
  BIP: ???
  Layer: Applications
  Title: raw() as subscript in Output Script Descriptors
  Author: Matias Furszyfer <mfurszy@protonmail.com>
  Comments-Summary: No comments yet.
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-???
  Status: Draft
  Type: Standards Track
  Created: ?
  License: BSD-2-Clause
</pre>

==Abstract==

This document specifies `raw()` as subscript for output script descriptors.
`raw()` encapsulates a raw hex script. This BIP allows `raw()` to be used in
the context of other descriptors.

==Copyright==

This BIP is licensed under the BSD 2-clause license.

==Motivation==

Allowing arbitrary hex data to be wrapped in `sh()`, `wsh()`, or even within the `TREE`
argument of a `tr(KEY, TREE)` descriptor enables the representation of currently
inexpressible information in the descriptors' language.

Specifically, the absence of this feature limits the representation of non-standard redeem
and witness scripts. This occurs because they can currently only be represented as top-level
`raw(HEX)` descriptors, which retain only the output script information and lack the ability
to preserve the actual script.

Additionally, as noted [here](https://github.com/bitcoin/bitcoin/issues/24114#issuecomment-1127978154),
there are other useful scenarios for this feature. For example, it allows representing
in a descriptor that we lack complete knowledge of all solvability paths but can still
solve the output. This includes cases like a taproot tree where we know only one of its
paths. Or, participating in signing a script without knowing all participants' keys,
relying solely on the script structure.

==Specification==

### For `sh()` and `wsh()` descriptors:
`raw(HEX)` must represent the arbitrary script data within the provided context.
This for example means that a P2SH output script (OP_HASH160 <hash160(HEX_script)> OP_EQUAL)
must be created from the provided hex data when a `sh(raw(HEX))` descriptor is provided.

Parallelly, a P2WSH output script (OP_0 <hash160(HEX_script)>) must be created from the provided
hex data when a `wsh(raw(HEX))` descriptor is provided.

### For `tr(KEY, TREE)` descriptors:
Two new fragments are allowed within the taproot `TREE` context: `rawnode(HEX)` and `raw(HEX)`.

#### `rawnode(HEX)`:
Indicating a tree node with specified 32-bit hash, but no specified subtree.
This can serve as either a tree branch or the root of the Merkle tree.

#### `raw(HEX)`:
Defines a tree leaf containing the specified script in hex.
Note: The leaf version must be internally fixed at the existing `0xC0` to prevent introducing
unsupported or undefined functionality.
If a different version is required for any use case, a new BIP could introduce `raw(HEX, VERSION)`
in the future.

==Test Vectors==

Valid descriptors followed by the scripts they produce.

* `sh(raw(5387))`
** `a9149e02f205612b4d7fe9466a789764b0eafe7eb07287`
* `sh(wsh(raw(5387)))`
** `a9140d1a6a9fd7e20b6e4091e2c10284fb1130afd46787`
* `wsh(raw(5387))`
** `00205c5fc1afc3d712a8e8602cee8590234ab2213be58943fca65436439f08017a64`
# TODO: Complete examples:
  1) tr(key, rawnode())
  2) tr(key, {pk(), raw()})
  3) tr(key, {pk(), rawnode()})
  4) tr(key, {pk(), sortedmulti_a(2,key1,key2,raw())})
  5) tr(key, {pk(raw())})

Invalid descriptors

* Non-hex script: `sh(raw(asdf))`
* Non 32-bit hash in `rawnode`: `tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd, rawnode(kjke))`
* Non-hex in `rawnode`: `tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd, rawnode(<complete me with a 32-bit non-hex hash>))`
* `raw` in the key path `tr`: `tr(raw(asdf), pk(key))`

==Backwards Compatibility==

`raw()` as subscript descriptors use the format and general operation specified in [[bip-0380.mediawiki|380]].
As this is a wholly new descriptor, it is not compatible with any implementation.

==Reference Implementation==

# TODO: add Bitcoin-Core PR..

==Acknowledgements==

Thanks to Pieter Wuille who came up with the original idea (https://github.com/bitcoin/bitcoin/issues/24114) and brainstorming support.
