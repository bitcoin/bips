```
BIP: ?
Layer: Consensus (soft fork)
Title: OP_TWEAKADD - x-only key tweak addition
Authors: Jeremy Rubin <jeremy@char.network>
Status: Draft
Type: Specification
Assigned: ?
License: BSD-3-Clause
```
## Abstract

This proposal defines a new tapscript opcode, `OP_TWEAKADD`, that takes an x-only public key and a 32-byte integer `h` on the stack and pushes the x-only public key corresponding to `P + h*G`, where `P` is the lifted point for the input x-coordinate and `G` is the secp256k1 generator. The operation mirrors the Taproot tweak used by BIP340 signers and enables simple, verifiable key modifications inside script without revealing private keys or relying on hash locks.

## Motivation

Bitcoin already leverages x-only key tweaking (for example, Taproot internal to output key derivation). Exposing a minimal, consensus-enforced version of "add a generator multiple to this key" inside tapscript:

- Enables script-level key evolutions (e.g., variable dependent authorized keys) without full signature verification at each step.
- Supports scriptless-script patterns where spending conditions are realized by transforming keys rather than revealing preimages.
- Allows compact covenant-like constructions where authorization is carried by key lineage, while keeping semantics narrowly scoped.


## Specification

### Applicability and opcode number

- Context: Only valid in tapscript (witness version 1, leaf version 0xc0). In legacy or segwit v0 script, `OP_TWEAKADD` is disabled and causes script failure.
- Opcode: OP_TWEAKADD (0xBE, or TBD, any unused OP_SUCCESSx, preferably one which might never be restored in the future).

### Stack semantics


```

... [h32] [pubkey32] OP_TWEAKADD  -> ... [pubkey32_out]

```
Input:

- `pubkey32`: 32-byte x-only public key (big-endian x coordinate).
- `h32`: 32-byte big-endian unsigned integer `t`.

Output:

- `pubkey32_out`: 32-byte x-only public key for `Q = P + t*G`.

#### Operation and failure conditions

Let `n` be the secp256k1 curve order.

1. If `h32` or `pubkey32` are not 32 bytes, fail.
2. Parse `h32` as big-endian integer `t`. If `t >= n`, fail.
3. Interpret `pubkey32` as an x-coordinate and attempt the BIP340 even-Y lift:
   - If no curve point exists with that x, fail.
   - Otherwise, obtain `P` with even Y.
4. Compute `Q = P + t*G`. If `Q` is the point at infinity, fail.
5. Push `x(Q)` as a 32-byte big-endian value.

Note: `t = 0` may fail if `pubkey32` is not valid.

#### Script evaluation rules

1. If less than 2 stack elements, fail.
2. Pop `pubkey32` and then `h32`
3. If either length is not 32, fail.
4. Run `tweak_add` as above.
5. Push the 32-byte x-only result.

### Resource usage

- Performs one fixed-base EC scalar multiplication (`t*G`) plus one EC point addition (`P + t*G`).
- Costs should be aligned with `OP_CHECKSIG` operation, budget is decremented by 50.

## Rationale

- Even-Y x-only is consistent with BIP340/Taproot.
- Infinity outputs are rejected to avoid invalid keys.
- Functionality is narrowly scoped to Taproot-style tweaks, avoiding arbitrary EC arithmetic.
- Push opcode rather than verification opcode for script compactness.
- Argument order to permit tweak from witness onto fixed key without OP_SWAP.

## Compatibility

This is a soft-fork change which is tapscript-only. Un-upgraded nodes will continue
to treat unknown tapscript opcode as OP_SUCCESSx.

A future upgrade, such as an OP_CAT or OP_TAPTREE opcode, can prepare a tweak for a
taproot output key correctly, if it is needed to create BIP-341 compatible outputs.

## Deployment

TBD

## Security considerations

- Scalar range check prevents overflow and ambiguity.
- Infinity guard ensures valid outputs only.
- Scripts must control `t` derivation securely, which in many applications is trivial.
- No new witness malleability introduced because tweaks must be exactly 32-bytes, and x-only key can only derive one even-Y point.

## Reference semantics (pseudocode)

```python
SECP256K1_ORDER = n  # 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

def tweak_add(pubkey32: bytes, h32: bytes) -> bytes:
    if len(pubkey32) != 32 or len(h32) != 32:
        raise ValueError
    t = int.from_bytes(h32, 'big')
    if t >= SECP256K1_ORDER:
        raise ValueError
    P = lift_x_even_y(pubkey32)  # BIP340 lift of x to the point with even Y
    if P is None:
        raise ValueError
    Q = point_add(P, scalar_mul_G(t))  # Q = P + t*G
    if Q is None:  # point at infinity
        raise ValueError
    return Q.x.to_bytes(32, 'big')
```



## Reference implementation notes

* Reuse BIP340 lift/encode helpers from Taproot verification.
* Implement `t*G` via fixed-base multiplication, then combine with `P` using point addition.
* Serialize the result as 32-byte x-only.
* Charge EC op budget as 50, like `OP_CHECKSIGADD`.


## Protocol Design Note: Scalar Adjustment

When working with x-only keys, it is important to remember that each 32-byte value encodes the equivalence class `{P, −P}`.
BIP340 defines the canonical lift as **the point with even Y**. As a result:

- If an off-chain protocol describes an x-only key as "the point `s·G`," then in consensus terms the actual key is `adj(s)·G`, where:

```

adj(s) = s        if y(s·G) is even
       = n − s    if y(s·G) is odd

```

- Consequently, `OP_TWEAKADD(x(s·G), t)` always computes:

```

result = x(adj(s)·G + t·G)

```

not simply `x(s·G + t·G)`.

This distinction is invisible when signing or verifying against BIP340 keys, because both `s` and `n − s` yield the same x-only key.
But it matters when a protocol tries to relate "a tweak applied at the base" (`x(G), t = s`) to "a tweak applied at a derived key" (`x(s·G), t = 1`). In general those will differ unless the original point already had even Y.


- If you want consistent algebraic relations across different ways of composing tweaks, **normalize scalars off-chain** before pushing them into script.
- That is: replace every candidate tweak `s` with `adj(s)`, so that `adj(s)·G` has even Y.
- A simple library function can perform this parity check and adjustment using libsecp256k1 without a consensus modification or opcode.

If the tweak is derived from inflexible state, such as a transaction hash or a signature, it may be infeasible to depend on commutativity of tweaking.
Protocols such as LN-Symmetry may simply grind the tx if even-y of tweak is required.


## Test vectors (Generated)


Curve order n = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


### Passing cases

1) Identity tweak (t = 0)
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  0000000000000000000000000000000000000000000000000000000000000000
  expect      =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

  script      =  <0000000000000000000000000000000000000000000000000000000000000000> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_EQUAL
```
2) Increment by 1
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  0000000000000000000000000000000000000000000000000000000000000001
  expect      =  c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5

  script      =  <0000000000000000000000000000000000000000000000000000000000000001> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD <c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5> OP_EQUAL
```
3) Increment by 2
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  0000000000000000000000000000000000000000000000000000000000000002
  expect      =  f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9

  script      =  <0000000000000000000000000000000000000000000000000000000000000002> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD <f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9> OP_EQUAL
```
4) Increment by 5
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  0000000000000000000000000000000000000000000000000000000000000005
  expect      =  fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556

  script      =  <0000000000000000000000000000000000000000000000000000000000000005> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD <fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556> OP_EQUAL
```
5) Input x(2G), t = 3
```
  pubkey32    =  c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
  h32         =  0000000000000000000000000000000000000000000000000000000000000003
  expect      =  2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4

  script      =  <0000000000000000000000000000000000000000000000000000000000000003> <c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5> OP_TWEAKADD <2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4> OP_EQUAL
```
6) Input x(7G), t = 9
```
  pubkey32    =  5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
  h32         =  0000000000000000000000000000000000000000000000000000000000000009
  expect      =  e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a

  script      =  <0000000000000000000000000000000000000000000000000000000000000009> <5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc> OP_TWEAKADD <e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a> OP_EQUAL
```
7) Input x(h(1) G), t = 1
```
  pubkey32    =  d415b187c6e7ce9da46ac888d20df20737d6f16a41639e68ea055311e1535dd9
  h32         =  0000000000000000000000000000000000000000000000000000000000000001
  expect      =  c6713b2ac2495d1a879dc136abc06129a7bf355da486cd25f757e0a5f6f40f74

  script      =  <0000000000000000000000000000000000000000000000000000000000000001> <d415b187c6e7ce9da46ac888d20df20737d6f16a41639e68ea055311e1535dd9> OP_TWEAKADD <c6713b2ac2495d1a879dc136abc06129a7bf355da486cd25f757e0a5f6f40f74> OP_EQUAL
```
8) Input x(h(2) G), t = 1
```
  pubkey32    =  d27cd27dbff481bc6fc4aa39dd19405eb6010237784ecba13bab130a4a62df5d
  h32         =  0000000000000000000000000000000000000000000000000000000000000001
  expect      =  136f23e6c2efcaa13b37f0c22cd6cfb0d4e6e9eddccefe17e747f5cf440bb785

  script      =  <0000000000000000000000000000000000000000000000000000000000000001> <d27cd27dbff481bc6fc4aa39dd19405eb6010237784ecba13bab130a4a62df5d> OP_TWEAKADD <136f23e6c2efcaa13b37f0c22cd6cfb0d4e6e9eddccefe17e747f5cf440bb785> OP_EQUAL
```
9) Input x(h(7) G), t = 1
```
  pubkey32    =  ddc399701a78edd5ea56429b2b7b6cd11f7d1e4015e7830b4f5e07eb25058768
  h32         =  0000000000000000000000000000000000000000000000000000000000000001
  expect      =  0e27b02714b3f2344f2bfa6d821654f2bd9f0ef497ec541b653b8dcb3a915faf

  script      =  <0000000000000000000000000000000000000000000000000000000000000001> <ddc399701a78edd5ea56429b2b7b6cd11f7d1e4015e7830b4f5e07eb25058768> OP_TWEAKADD <0e27b02714b3f2344f2bfa6d821654f2bd9f0ef497ec541b653b8dcb3a915faf> OP_EQUAL
```
10) Input x(G), t = 1
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
  expect      =  c6713b2ac2495d1a879dc136abc06129a7bf355da486cd25f757e0a5f6f40f74

  script      =  <4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD <c6713b2ac2495d1a879dc136abc06129a7bf355da486cd25f757e0a5f6f40f74> OP_EQUAL
```
11) Input x(G), t = h(2)
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986
  expect      =  136f23e6c2efcaa13b37f0c22cd6cfb0d4e6e9eddccefe17e747f5cf440bb785

  script      =  <dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD <136f23e6c2efcaa13b37f0c22cd6cfb0d4e6e9eddccefe17e747f5cf440bb785> OP_EQUAL
```
12) Input x(G), t = h(7) (Note: differs from 9)
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879
  expect      =  00b152fb17d249541e3b2f51455269e02d76507ad7857aaa98e3c51ee5da5b1d

  script      =  <ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD <00b152fb17d249541e3b2f51455269e02d76507ad7857aaa98e3c51ee5da5b1d> OP_EQUAL
```

### Failing cases

A) Scalar out of range (t = n)
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  expect      =  fail
  script      =  <fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD OP_DROP OP_1
```
B) Invalid x (x = 0), t = 1
```
  pubkey32    =  0000000000000000000000000000000000000000000000000000000000000000
  h32         =  0000000000000000000000000000000000000000000000000000000000000001
  expect      =  fail
  script      =  <0000000000000000000000000000000000000000000000000000000000000001> <0000000000000000000000000000000000000000000000000000000000000000> OP_TWEAKADD OP_DROP OP_1
```
C) Infinity result (x(G), t = n-1)
```
  pubkey32    =  79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  h32         =  fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
  expect      =  fail
  script      =  <fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140> <79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798> OP_TWEAKADD OP_DROP OP_1
```

## Acknowledgements

This proposal extends the Taproot tweak mechanism (BIP340/341) into script, inspired by prior work on scriptless scripts and key-evolution constructions. There has been various discussion of OP_TWEAKADD over the years, including by Russell O'Connor and Steven Roose.

## References

- [Bitcoin Dev Mailing List Discussion](https://groups.google.com/g/bitcoindev/c/-_geIB25zrg)
- [CATT: Thoughts about an alternative covenant softfork proposal](https://delvingbitcoin.org/t/catt-thoughts-about-an-alternative-covenant-softfork-proposal/125)
- [Draft BIP: OP_TXHASH and OP_CHECKTXHASHVERIFY](https://gnusha.org/pi/bitcoindev/e98d76f2-6f2c-9c3a-6a31-bccb34578c31@roose.io/)
- [Advent 8: Scriptless Scripts and Key Tweaks](https://rubin.io/bitcoin/2021/12/05/advent-8/)
- [Re: [bitcoin-dev] Unlimited covenants, was Re: CHECKSIGFROMSTACK/{Verify} BIP for Bitcoin](https://gnusha.org/pi/bitcoindev/CAMZUoKnVLRLgL1rcq8DYHRjM--8VEUC5kjUbzbY5S860QSbk5w@mail.gmail.com/)
- [Re: [bitcoin-dev] Unlimited covenants, was Re: CHECKSIGFROMSTACK/{Verify} BIP for Bitcoin](https://gnusha.org/pi/bitcoindev/CAMZUoKkAUodCT+2aQG71xwHYD8KXeTAdQq4NmXZ4GBe0pcD=9A@mail.gmail.com/)
- [ElementsProject: Tapscript opcodes documentation](https://github.com/ElementsProject/elements/blob/master/doc/tapscript_opcodes.md#new-opcodes-for-additional-functionality)
- [[bitcoin-dev] Merkleize All The Things](https://gnusha.org/pi/bitcoindev/CAMhCMoH9uZPeAE_2tWH6rf0RndqV+ypjbNzazpFwFnLUpPsZ7g@mail.gmail.com/)
- [Alpen Labs Technical-Whitepaper](https://github.com/alpenlabs/Technical-Whitepaper/tree/76d5279e62fe3f157ae94ffc0514ad2a95c6dbcf)

## Copyright

This BIP is licensed under the [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause).