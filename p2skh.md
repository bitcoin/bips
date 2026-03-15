```
BIP: ???
Layer: Consensus (soft fork)
Title: Pay to Schnorr Key Hash (P2SKH)
Author: sashabeton <sashabeton2007@gmail.com>
Status: Draft
Type: Standards Track
Created: 2026-03-15
Requires: 340, 341
```

## Abstract

This BIP defines **Pay to Schnorr Key Hash (P2SKH)**, a new native SegWit output type
using witness version 2.  The locking script commits to the 20-byte `RIPEMD160(SHA256(P.x))`
of the signer's x-only public key rather than the full 32-byte key.  Spending requires a
single 64-byte Schnorr signature; the verifier recovers the public key and checks its hash
against the program, eliminating key exposure in unspent outputs.

P2SKH combines the compact 20-byte program of P2WPKH with the Schnorr signature efficiency
of P2TR key-path spending, producing outputs that are 12 bytes smaller than P2TR while
keeping an identical witness footprint.

## Motivation

### Existing output types and their trade-offs

| Type   | scriptPubKey | Witness (key spend) | Signature scheme |
|--------|-------------|---------------------|-----------------|
| P2PKH  | 25 bytes    | ~107 bytes (scriptSig) | ECDSA        |
| P2WPKH | 22 bytes    | ~108 bytes          | ECDSA           |
| P2TR   | 34 bytes    | 64 bytes            | Schnorr (BIP340) |
| P2SKH  | **22 bytes**| **64 bytes**        | Schnorr (BIP340) |

P2WPKH (BIP141/143) achieves a compact 22-byte scriptPubKey by hashing the public key, but
still uses ECDSA signatures and requires the full compressed public key (33 bytes) in the
witness, resulting in ~108 witness bytes per input.

P2TR (BIP341) adopts Schnorr signatures (BIP340), reducing the witness to 64 bytes.  However,
the locking script embeds the full 32-byte x-only public key, producing a 34-byte scriptPubKey
— 12 bytes larger than P2WPKH — and exposing the key in every unspent output.

P2SKH eliminates this trade-off: it uses a 20-byte hash commitment in the scriptPubKey
(matching P2WPKH) and a 64-byte Schnorr signature in the witness (matching P2TR key-path),
yielding the smallest combined transaction footprint of any current single-key output type.

### Concrete size and fee impact

For every output created, P2SKH saves **12 bytes** relative to P2TR
(`34 − 22 = 12`).  At the default witness discount (4:1), the 64-byte witness costs
16 vbytes, identical to P2TR.

A typical payment transaction (2 inputs, 2 outputs) replacing P2TR with P2SKH:

* Output savings: `2 × 12 = 24 bytes` → reduces the base transaction size.
* Input witness savings relative to P2WPKH: ~88 witness bytes per input → 22 vbytes saved.

On a busy network with high fee rates, these savings directly reduce user costs and increase
the number of transactions that fit in a block, improving network throughput.

### UTXO set pressure

Every full node must keep every unspent output in memory.  A 12-byte saving per output
across millions of UTXOs meaningfully reduces RAM usage for the entire network.

### Pre-spending key privacy

Because the scriptPubKey contains only `hash160(P.x)`, the public key is not revealed
until the output is spent.  This matches the privacy model users have relied on since P2PKH
and is stronger than P2TR, which reveals `Q` (the tweaked output key) unconditionally.

### Familiar user experience

The 20-byte program encodes to a bech32m address of comparable length to existing bc1q
(P2WPKH) addresses.  Wallets and exchanges that already support P2WPKH addresses can
adopt P2SKH with minimal UI changes, while gaining Schnorr signature efficiency.

## Specification

### Definitions

The following notation and definitions apply throughout this document.

* Lowercase letters denote scalars; uppercase letters denote elliptic curve points.
* `||` denotes byte-string concatenation.
* `hash160(x)` = `RIPEMD160(SHA256(x))` (20 bytes).
* `TaggedHash(tag, data)` = `SHA256(SHA256(tag) || SHA256(tag) || data)` as defined in BIP340.
* `G` is the secp256k1 generator; `n` is the group order.
* `x(P)` denotes the x-coordinate of point `P` serialised as a 32-byte big-endian integer.
* `has_even_y(P)` is `true` when the y-coordinate of `P` is even.

### Output script

A P2SKH output has the following scriptPubKey:

```
OP_2 <hash160(P.x)>
```

In raw bytes (22 bytes total):

```
0x52  0x14  <20 bytes of hash160(P.x)>
```

where `P` is the signer's public key and `P.x` is its 32-byte x-coordinate (x-only
encoding as in BIP340).

The 20-byte witness program is `hash160(P.x)`.

### Spending

A P2SKH output is spent with a witness stack containing exactly one item: a 64-byte or
65-byte signature.

```
<sig>
```

A 64-byte `sig` encodes a signature with implicit `SIGHASH_DEFAULT` (equivalent to
`SIGHASH_ALL`).  A 65-byte `sig` appends an explicit hash type byte as the last byte,
following the same conventions as BIP341.

### Sighash

The sighash is computed using the BIP341 transaction digest algorithm
(`SigHash` as defined in BIP341, `ext_flag = 0`, `SigVersion::TAPROOT`), applied to
the spending transaction at the appropriate input index.  This reuses the existing
BIP341 precomputation infrastructure and includes the `scriptPubKey` of the spent output
in the digest, preventing cross-version signature replay.

### Signing

Given a private key `d` with corresponding public key `P = d·G`:

1. **Normalise the key** — if `P.y` is odd, negate `d` so the effective key has even y:
   ```
   if not has_even_y(P):
       d = n - d
   ```

2. **Derive the nonce** — let `k` be the Schnorr nonce scalar, derived as:
   ```
   If aux_rand is provided (recommended):
       t = d XOR TaggedHash("P2SKH/aux", aux_rand)
   else:
       t = d

   k = int(TaggedHash("P2SKH/nonce", t || x(P) || msg)) mod n
   ```
   Fail if `k = 0`.

3. **Compute R** — `R = k·G`.  If `R.y` is odd, negate `k`:
   ```
   if not has_even_y(R):
       k = n - k
   ```

4. **Compute the challenge**:
   ```
   e = int(TaggedHash("P2SKH/challenge", x(R) || hash160(x(P)) || msg)) mod n
   ```

5. **Compute the signature scalar**:
   ```
   s = (k + e·d) mod n
   ```

6. **Encode the signature**: `sig = bytes(x(R)) || bytes(s)` (64 bytes).

The signing algorithm is intentionally compatible with the structure of BIP340 but uses
distinct tagged-hash domain separators to prevent nonce reuse and cross-scheme attacks.

### Verification

Given a 64-byte signature `sig`, a 32-byte message `msg`, and the 20-byte witness program
`h` (= `hash160(P.x)` from the scriptPubKey):

1. Let `rx = sig[0:32]`, `s = int(sig[32:64])`.
2. Fail if `rx ≥ p` (not a valid field element).
3. Fail if `s = 0` or `s ≥ n`.
4. Let `R` be the secp256k1 point with x-coordinate `rx` and even y-coordinate.
   Fail if no such point exists.
5. Compute:
   ```
   e = int(TaggedHash("P2SKH/challenge", rx || h || msg)) mod n
   ```
6. Fail if `e = 0`.
7. Compute the key-recovery scalar `e⁻¹ = e^(n−2) mod n` (modular inverse).
8. Recover the public key:
   ```
   P = e⁻¹ · (s·G − R)
   ```
   Fail if `P` is the point at infinity.
9. **Verify the hash commitment**:
   ```
   Fail if hash160(x(P)) ≠ h
   ```

*Key-recovery note:* Steps 7–9 recover `P` from the signature and check that its hash
matches the spending program.  This is mathematically equivalent to the standard Schnorr
verification equation `s·G = R + e·P`: rearranging gives `P = e⁻¹·(s·G − R)`.

### Script execution

The following rules apply when `SCRIPT_VERIFY_P2SKH` is active:

1. The witness must contain exactly one stack item.  Fail otherwise.
2. That item must be 64 or 65 bytes.  Fail otherwise.
3. If 65 bytes, the last byte is the hash type and must be a valid BIP341 sighash type.
4. Compute `msg = SigHash(spending_tx, input_index, hash_type, SigVersion::TAPROOT)`.
5. Run the verification procedure above with `sig = witness[0][0:64]`, `msg`, and `h`
   taken from the witness program.
6. Succeed if and only if verification passes.

## Rationale

### Why key recovery instead of direct verification?

Direct Schnorr verification (`s·G = R + e·P`) requires the verifier to know `P`.  In P2TR,
`P` is stored in the scriptPubKey; the verifier reads it directly.  P2SKH stores only
`hash160(P.x)`, so the verifier must obtain `P` another way.  Key recovery is the natural
solution: given `(R, s, e)` and the group law, `P` is uniquely determined (up to the even-y
convention), and the hash provides the necessary commitment to rule out substitution attacks.

The recovery step adds approximately one field inversion and one scalar multiplication
relative to direct verification.  This overhead is modest in absolute terms and is the
direct price paid for the 12-byte output size reduction.

### Why hash160?

RIPEMD160(SHA256(·)) (`hash160`) has been used in Bitcoin since its genesis and produces a
20-byte digest that encodes compactly into a bech32m address.  Using SHA256 alone would
produce a 32-byte program, giving outputs equal in size to P2TR and eliminating the primary
space advantage.

`hash160` provides 80-bit second-preimage resistance against classical adversaries, which is
the same security level Bitcoin has relied upon for P2PKH and P2WPKH since 2009.  This is
considered sufficient for address collision resistance in current threat models.

### Why reuse the BIP341 sighash?

Reusing the BIP341 transaction digest:

* Eliminates the need for a new sighash specification.
* Allows wallets and signing devices to share precomputation code.
* The `scriptPubKey` of the UTXO (which includes `OP_2` and the 20-byte hash) is committed
  to in the digest, making P2SKH signatures non-transferable to P2TR UTXOs and vice versa.

### Even-y conventions

Both the long-term signing key (step 1 of signing) and the nonce (step 3) use the
even-y convention from BIP340.  This ensures a unique canonical signature and simplifies
the key-recovery step (the verifier always reconstructs the even-y `R`).

## Compatibility

This is a consensus soft fork.  Nodes that do not recognise `SCRIPT_VERIFY_P2SKH` will
treat P2SKH outputs as anyone-can-spend (following the standard SegWit upgrade path) and
will not enforce the new rules, but will also not reject them.  This maintains backward
compatibility with all existing clients.

## Acknowledgements

This proposal builds directly on BIP340 (Schnorr Signatures) by Pieter Wuille, Jonas Nick,
and Tim Ruffing, and on BIP341 (Taproot) by Pieter Wuille, Jonas Nick, and Anthony Towns,
whose design decisions and rationale heavily informed this work.

