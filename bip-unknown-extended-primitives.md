```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: Tapleaf 0xc2: Extended Primitives
  Authors: Rusty Russell <rusty@rustcorp.com.au>
           Julian Moik <julianmoik@gmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-3-Clause
  Discussion: https://groups.google.com/g/bitcoindev/c/GisTcPb8Jco/m/8znWcWwKAQAJ
  Version: 0.1.0
  Requires: 440, 441, unknown-optx
```

## Introduction

### Abstract

This BIP defines three opcodes for Tapleaf 0xc2: OP_CHECKSIGFROMSTACK, OP_TWEAKADD, and OP_BYTEREV.  Together with [BIP440](bip-0440.mediawiki), [BIP441](bip-0441.mediawiki) and [OP_TX](bip-unknown-optx.md), they let Script verify a signature over any message on the stack and compute Taproot outputs.

### Copyright

This document is licensed under the 3-clause BSD license.

### Motivation

BIP 440, BIP 441 and OP_TX let Script read the spending transaction and compute over what it reads, but two capabilities that Bitcoin's own consensus rules already use remain out of practical reach:

- **Authorize a script-built message.** OP_CHECKSIG verifies a signature only over the message fixed by [BIP342](bip-0342.mediawiki).  OP_CHECKSIGFROMSTACK verifies a [BIP340](bip-0340.mediawiki) signature over a message on the stack.  This enables custom signature-hash modes, rebindable signatures such as those of [BIP448](bip-0448.md) and LN-Symmetry, key delegation, and oracle attestations.
- **Construct a Taproot output.** A covenant that carries state from one output to the next must produce the next output's key from computed data.  OP_TWEAKADD performs [BIP341](bip-0341.mediawiki)'s key tweak.  OP_BYTEREV orders hashes for Taproot trees and converts between the big-endian encodings of BIP 340 and BIP 341 and the little-endian numbers of BIP 441.

With these three opcodes, the Tapleaf 0xc2 proposals aim to form a reasonably complete, unopinionated and resource-bounded verification language for Bitcoin outputs.  Every construction in the [Examples](#examples) section uses only these proposals.

This BIP introduces no new cryptographic semantics.  OP_CHECKSIGFROMSTACK adopts [BIP348](bip-0348.md), OP_TWEAKADD adopts [BIP449](bip-0449.md), and OP_BYTEREV only reverses bytes.  What this BIP adds is their definition in Tapleaf 0xc2 and their [BIP440](bip-0440.mediawiki) varops costs.

## Specification

All opcode definitions in this BIP apply only to Tapleaf 0xc2 as defined by [BIP441](bip-0441.mediawiki).  Legacy Script, Segwit v0, Tapleaf 0xc0 and unknown leaf versions are unchanged.

References to BIP 348 and BIP 449 are to their text at the following `bitcoin/bips` commits, since neither carries a version number: [BIP 348 at `24e96e8`](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0348.md) and [BIP 449 at `76d434e`](https://github.com/bitcoin/bips/blob/76d434e5fc781b579495b336ab0b6a73e8e05a54/bip-0449.md).  Later changes to those BIPs do not change this BIP unless it is revised to adopt them.

Stack notation follows BIP 441: `[A B]` means B is on top.  Unless stated otherwise, an opcode fails validation if the stack has fewer elements than it consumes, and its varops cost is deducted before the work it pays for is performed.

### Opcode Assignments

| Opcode | Value | Previous `0xc2` meaning | Stack | Varops cost |
| --- | --- | --- | --- | --- |
| OP_CHECKSIGFROMSTACK | `0xcc` | OP_SUCCESS204 | `[sig msg pubkey] -> [result]` | `BASE + WRITE(0)` with an empty signature; `BASE + SIGCHECK + HASH(64 + length(msg)) + WRITE(1)` otherwise |
| OP_TWEAKADD | `0xbe` | OP_SUCCESS190 | `[tweak pubkey] -> [pubkey']` | `BASE + SIGCHECK + WRITE(32)` |
| OP_BYTEREV | `0xcf` | OP_SUCCESS207 | `[x] -> [reverse(x)]` | `BASE + ARITH(n)` for an `n`-byte element |

OP_TWEAKADD's elliptic-curve work, parsing an x-only public key, adding a tweak multiple of the generator and serializing the resulting key, is charged as one `SIGCHECK`, as BIP 440 prices every elliptic-curve operation.

### OP_CHECKSIGFROMSTACK

OP_CHECKSIGFROMSTACK follows BIP 348, except that it applies to Tapleaf 0xc2, accepts messages of any length permitted by BIP 441, and is charged against the BIP 440 budget instead of the BIP 342 signature-operation budget.  Its varops cost is deducted before verification; with a nonempty signature it includes SIGCHECK and the HASH charge, even if the public key type is unknown or the signature proves invalid.

The HASH charge covers the hashing that BIP 340 verification performs: its tagged challenge hash over `R || P || msg`, which is 64 + length(msg) bytes.

### OP_TWEAKADD

OP_TWEAKADD follows BIP 449, except that it applies to Tapleaf 0xc2 and is charged against the BIP 440 budget.

### OP_BYTEREV

OP_BYTEREV fails on an empty stack.  Otherwise, it pops the top element, reverses its bytes and pushes the result.  For example, `01 02 03` becomes `03 02 01`, and an empty element remains empty.  The result is not normalized: a byte string with leading zero bytes becomes a little-endian value with trailing zero bytes, which BIP 441's numeric opcodes accept as input.

OP_BYTEREV costs `BASE + ARITH(n)` varops for an `n`-byte element, using [BIP 440](bip-0440.mediawiki)'s primitives: reversing byte-swapped 64-bit words makes each result word depend on at most two input words, so the reversal is one ARITH pass.

## Rationale

### Inclusion Criterion

BIP 441's unsigned arithmetic is general enough to emulate each of these opcodes, so none of them is strictly impossible without this BIP.  An opcode is included here if it meets all three conditions:

1. It performs an operation Bitcoin's consensus rules already use: BIP 340 signature verification, BIP 341's key tweak, or handling the big-endian hashes and keys of BIP 340 and BIP 341.
2. Emulating it with BIP 441 and OP_TX is impractical in validation budget or script weight.
3. Its semantics are already specified elsewhere or trivial, so including it adds no new cryptographic design.

The second condition is met by a wide margin for OP_TWEAKADD and OP_CHECKSIGFROMSTACK: emulating either requires secp256k1 point arithmetic built from `OP_MUL` and `OP_MOD`, thousands of 256-bit modular multiplications for a single tweak or signature check.  For OP_BYTEREV the margin is smaller: the straightforward emulation takes an `OP_SUBSTR` and an `OP_CAT` per byte, about 175 bytes of script to reverse one 32-byte value, and ordering sibling hashes needs two reversals at every level of a Merkle path.

### OP_CHECKSIGFROMSTACK

OP_TX and OP_SHA256 can reproduce any part of a signature hash, including every BIP 341 signature-hash mode.  OP_CHECKSIGFROMSTACK checks a signature against the result, so a script can define a signature-hash mode without a new consensus rule for each mode.  It keeps BIP 348's name, value and behavior, so that `0xc0` and `0xc2` scripts agree; BIP 348 explains why it does not hash the message and has no VERIFY or ADD variant.

### OP_TWEAKADD

A Taproot output key is `P + t·G`, where `t` commits to the internal key and the script tree.  OP_TWEAKADD exposes exactly this operation, with BIP 449's x-only keys, pushed result and failure on a tweak of `n` or more, which BIP 449's rationale explains.

### OP_BYTEREV

Taproot trees order sibling hashes lexicographically, but BIP 441 numbers are little-endian, so OP_LESSTHAN compares two hashes starting from their last byte.  OP_BYTEREV's main use is reversing both hashes so that OP_LESSTHAN orders them as a TapBranch hash requires, and as any Merkle path that orders siblings the same way does.

It also converts between BIP 441 numbers and the big-endian scalars, x-coordinates and hash-derived integers of BIP 340 and BIP 341: for example, to reduce a challenge hash modulo `n`, or to turn a computed number, padded to 32 bytes with `OP_CAT` and `OP_LEFT`, into a tweak for OP_TWEAKADD.

### Considered and Excluded

The following are not included: none has yet been shown to enable a use case that these proposals cannot express, or to make a wanted one substantially simpler or cheaper.  Each can be proposed separately once it does.

| Proposal | Reason |
| --- | --- |
| Verify-style elliptic-curve opcodes (Elements `OP_TWEAKVERIFY`, `OP_ECMULSCALARVERIFY`) | OP_TWEAKADD covers the tweak and pushes the key, which a script can compare with OP_TX data or pass to OP_CHECKSIGFROMSTACK; `OP_TWEAKADD <Q> OP_EQUALVERIFY` gives the verify form.  General scalar multiplication is left to a separate proposal. |
| OP_INTERNALKEY ([BIP349](bip-0349.md)) | OP_TX's `CURRENT_INTERNAL_KEY`. |
| OP_MULTI and iteration opcodes | They add consensus and review surface while saving a negligible share of a transaction's size: repeated code uses [Reusable Macros](bip-unknown-reusable-macros.md). |
| OP_CHECKCONTRACTVERIFY ([BIP443](bip-0443.mediawiki)) | Its output-program commitment is expressible (see [State-Carrying Output](#state-carrying-output)); its amount semantics are not addressed. |
| OP_SEGMENT (segmented evaluation, in which an OP_SUCCESS opcode affects only its own segment) | For a covenant that requires a fixed prefix, such as a delay, ahead of script another party supplies in the same leaf (see [Composing Leaves](#composing-leaves)), as proposed for Tapscript v2.  It changes BIP 342's OP_SUCCESS scan; whether it is useful enough to add is open for discussion. |

## Examples

In the examples below, `TAG(X)` stands for `<X> OP_SHA256 OP_DUP OP_CAT`, which pushes the 64-byte value `SHA256(X) || SHA256(X)` for the tag `X`.  Prepending it with `OP_CAT` before `OP_SHA256` computes BIP 340's tagged hash `hash_X`.  OP_TX selectors are the six-byte version-0 selectors of the OP_TX BIP.

| Selector | Pushes |
| --- | --- |
| `<00 00 00 01 00 02>` | `OUTPUT_SCRIPTPUBKEY` of the output whose index equals the current input index |
| `<00 00 20 00 00 00>` | `CURRENT_INTERNAL_KEY` |
| `<00 00 40 00 00 00>` | `CURRENT_TAPTREE_ROOT` |
| `<00 00 10 00 00 00>` | `CURRENT_CONTROL_BLOCK` |
| `<00 00 00 11 04 01>` | `INPUT_PREVOUT_AMOUNT` of the current input, then `OUTPUT_AMOUNT` of the output whose index equals the current input index |
| `<00 07 00 02 00 03>` | `COLLATE` of `TX_VERSION`, `TX_LOCKTIME`, and the amount and scriptPubKey of every output |

`TAPTWEAK` and `DATATWEAK` stand for the scripts below.  `TAPTWEAK` computes a BIP 341 output key from an internal key `P` and a tree root `r`.  `DATATWEAK` computes a key tweaked with data `d` from a key `N`, similar to BIP 443's data tweak:

```text
TAPTWEAK   [P r] -> [Q]:   OP_OVER OP_SWAP OP_CAT TAG(TapTweak) OP_SWAP OP_CAT OP_SHA256 OP_SWAP OP_TWEAKADD
DATATWEAK  [N d] -> [K]:   OP_OVER OP_SWAP OP_CAT OP_SHA256 OP_SWAP OP_TWEAKADD
```

### State-Carrying Output

[MATT](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021182.html)-style contracts keep application state, such as a counter, balance or commitment, in the output.  Each spend reads the current state and computes the output that carries the next one, whereas with a template commitment such as [BIP119](bip-0119.mediawiki)'s, every possible next output must be fixed when the output is created.  A contract whose Taproot internal key is `DATATWEAK(N, d)` carries the data `d` in its output key.  Here `N` is a fixed key, for example a MuSig2 aggregate key for cooperative key-path spends.  The following leaf verifies the current data, computes the next data with an application-specific script `UPDATE [d] -> [d']`, and requires the output at the same index to carry `d'` with the same script tree:

```text
# witness: <d>
OP_DUP <N> OP_SWAP DATATWEAK                # [d K]
<00 00 20 00 00 00> OP_TX OP_EQUALVERIFY    # [d]      K is the current internal key
UPDATE                                      # [d']
<N> OP_SWAP DATATWEAK                       # [K']
<00 00 40 00 00 00> OP_TX TAPTWEAK          # [Q']     the same script tree as the current input
<51 20> OP_SWAP OP_CAT
<00 00 00 01 00 02> OP_TX OP_EQUAL
```

Taproot validation authenticates the current internal key, so comparing `K` with it authenticates `d`.  A contract can also check the amount.  For example, `<00 00 00 11 04 01> OP_TX <max_fee> OP_ADD OP_LESSTHANOREQUAL OP_VERIFY` requires the output to keep the input's value, less at most `max_fee`.

### Replacing the Current Leaf

Vaults built with [BIP345](bip-0345.mediawiki)'s OP_VAULT change one spending condition, for example to record a pending withdrawal's destination, while keeping the contract's other conditions, including its recovery path, unchanged.  A contract can instead carry state in the script of a leaf, replacing the executing leaf with a new script `S'` while keeping its siblings and internal key.  Let `BUILD [d'] -> [S']` be an application-specific script that concatenates fixed script templates with a data push of the new state `d'`.  For a leaf at depth one, the sibling hash is the 32 bytes of the control block starting at offset 33.  The following computes the new leaf hash and TapBranch hash, and checks the resulting output:

```text
# stack: <d'>
BUILD                                            # [S']      1 <= length(S') <= 252
OP_SIZE OP_SWAP OP_CAT                           # [CompactSize(length(S')) || S']
<c2> OP_SWAP OP_CAT
TAG(TapLeaf) OP_SWAP OP_CAT OP_SHA256            # [h']      new TapLeaf hash
<00 00 10 00 00 00> OP_TX <33> <32> OP_SUBSTR    # [h' s]    sibling hash from the control block
OP_2DUP OP_BYTEREV OP_SWAP OP_BYTEREV
OP_LESSTHAN OP_IF OP_SWAP OP_ENDIF OP_CAT        # [lesser || greater]
TAG(TapBranch) OP_SWAP OP_CAT OP_SHA256          # [r']      new root
<00 00 20 00 00 00> OP_TX OP_SWAP TAPTWEAK       # [Q']
<51 20> OP_SWAP OP_CAT
<00 00 00 01 00 02> OP_TX OP_EQUAL
```

### Rebindable Signature

In LN-Symmetry (eltoo) channels, a later state can spend whichever earlier state was published, and in Ark's [Erk](https://delvingbitcoin.org/t/evolving-the-ark-protocol-using-ctv-and-csfs/1602) variant a user pre-signs a refund before the round transaction that creates their output exists; in both, the signature cannot commit to the outpoint it spends.  The following leaf accepts a signature by key `P` over the transaction's version, locktime and outputs, but not over the outpoint being spent.  Any output with this leaf can therefore be spent by the same signature, as with [BIP118](bip-0118.mediawiki)'s `SIGHASH_ANYPREVOUTANYSCRIPT` or the constructions of BIP 448:

```text
# witness: <sig>
<00 07 00 02 00 03> OP_TX                   # [sig fields]
<"example/rebind"> OP_SWAP OP_CAT           # [sig msg]
<P> OP_CHECKSIGFROMSTACK
```

A protocol using this for LN-Symmetry adds its own state-ordering condition, for example on the transaction locktime.  Since the message commits to no input, one signature can also spend several such outputs in one transaction; as with BIP 118 keys, `P` should only be reused where that cannot cause loss.

## Security Considerations

### Message Construction

OP_CHECKSIGFROMSTACK verifies exactly the message supplied by the script.  Scripts must therefore include every transaction field, input or output identity, and protocol domain separator required by their authorization rule.  In particular, a message that omits the spent outpoint is rebindable.

A BIP 342 signature signs a 32-byte signature hash.  A signature by the same key over an OP_CHECKSIGFROMSTACK message equal to such a hash is also a valid OP_CHECKSIG signature, and the reverse also holds.  Unless a script reproduces a BIP 341 signature hash, keys used with OP_CHECKSIGFROMSTACK should not also sign transactions, and messages should include an application-specific prefix, as in the Rebindable Signature example.

### Keys From the Stack

OP_CHECKSIG and OP_CHECKSIGFROMSTACK accept any nonempty signature for a public key of unknown type, that is, of any nonzero length other than 32 bytes ([BIP342](bip-0342.mediawiki), [BIP348](bip-0348.md)).  A script that takes a key from the witness, or computes one, lets whoever supplies the bytes choose the type, and must check that the key is 32 bytes, for example with `OP_SIZE <32> OP_EQUALVERIFY`.  Keys produced by OP_TWEAKADD and by OP_TX's `CURRENT_INTERNAL_KEY` are always 32 bytes.

### Tweak Derivation

If a script passes a tweak supplied by the witness to OP_TWEAKADD, the spender chooses the resulting key.  Scripts constructing outputs must derive tweaks from committed data, as `TAPTWEAK` and `DATATWEAK` do.

OP_TWEAKADD returns an x-only key.  A construction that needs the parity of the resulting point, for example to build a control block, must obtain it separately.

### Composing Leaves

A leaf cannot combine a required script with script another party chooses: an OP_SUCCESS opcode anywhere in the leaf makes it succeed unconditionally when spent.  Scripts should build leaves only from fixed templates and data pushes of verified length, as `BUILD` does above.

## Backwards Compatibility

Without this BIP, each assigned opcode is an OP_SUCCESS opcode in Tapleaf 0xc2.  Replacing immediate success with the stricter rules above can only invalidate previously valid spends and is therefore a soft fork.  Other script and Tapleaf versions are unchanged.

## Reference Implementation

A prototype of all three opcodes, with the costs above, is part of the Bitcoin Core Tapleaf 0xc2 prototype implementing BIPs 440 and 441: <https://github.com/jmoik/bitcoin/tree/gsr>.  The prototype is not an activation or deployment.

## Changelog

- 0.1.0: 2026-10-27: initial draft.

## Thanks

This BIP would not exist without the thoughtful contributions of the following (in alphabetical order):

- Brandon Black
- Robin Linus
