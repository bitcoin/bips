```
BIP: TBD
Layer: Consensus (soft fork)
Title: OP_TWEAKADD - x-only key tweak addition
Author: Jeremy Rubin <jeremy@char.network>
Status: Draft
Type: Standards Track
Created: 2025-08-22
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

Input (top last):

```

... \[pubkey32] \[h32] OP\_TWEAKADD  ->  ... \[pubkey32\_out]

````

- `pubkey32`: 32-byte x-only public key (big-endian x coordinate).
- `h32`: 32-byte big-endian unsigned integer `t`.

Output:

- `pubkey32_out`: 32-byte x-only public key for `Q = P + t*G`.

### Operation and failure conditions

Let `n` be the secp256k1 curve order.

1. Parse `h32` as big-endian integer `t`. If `t >= n`, fail.
2. Interpret `pubkey32` as an x-coordinate and attempt the BIP340 even-Y lift:
   - If no curve point exists with that x, fail.
   - Otherwise, obtain `P` with even Y.
3. Compute `Q = P + t*G`. If `Q` is the point at infinity, fail.
4. Push `x(Q)` as a 32-byte big-endian value.

### Conventions

- X-only keys follow BIP340 conventions (even-Y).
- Scalars must be exactly 32 bytes, big-endian, and less than `n`.
- Non-32-byte inputs fail (consensus). Minimal push rules apply (policy).

### Resource usage

- Performs one fixed-base EC scalar multiplication (`t*G`) plus one EC point addition (`P + t*G`).
- Costs should be aligned with `OP_CHECKSIG` operation, budget is decremented by 50.

## Rationale

- Even-Y x-only is consistent with BIP340/Taproot.
- Infinity outputs are rejected to avoid invalid keys.
- Functionality is narrowly scoped to Taproot-style tweaks, avoiding arbitrary EC arithmetic.
- Push opcode rather than verification opcode for script compactness.

## Backwards compatibility

- Old nodes: treat unknown tapscript opcode as OP_SUCCESSx.
- This is a soft-fork change, tapscript-only.

## Future compatibility

- A future OP_CAT or OP_TAPTREE opcode can prepare a tweak for a taproot output key correctly

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
````

## Script evaluation rules

0. If less than 2 stack elements, fail.
1. Pop `h32`, then `pubkey32`.
2. If either length is not 32, fail.
3. Run `tweak_add` as above.
4. Push the 32-byte x-only result.

## Test vectors (numeric, hex)

All values are 32-byte hex, big-endian. Curve is secp256k1 with generator G. Order `n`:

```
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 
```

The following vectors assume BIP340 even-Y lifting of input x-only keys.

TODO: these test vectors will be actually computed and checked...

### Known inputs

```
x(G)   = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
x(2G)  = c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
x(3G)  = f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
x(5G)  = 2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4
x(6G)  = fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556
x(7G)  = 5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
```

### Passing cases

1. Identity tweak (t = 0):

```
pubkey32 = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
h32      = 0000000000000000000000000000000000000000000000000000000000000000
result   = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

2. Increment by 1:

```
pubkey32 = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
h32      = 0000000000000000000000000000000000000000000000000000000000000001
result   = c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
```

3. Increment by 2:

```
pubkey32 = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
h32      = 0000000000000000000000000000000000000000000000000000000000000002
result   = f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
```

4. Increment by 5:

```
pubkey32 = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
h32      = 0000000000000000000000000000000000000000000000000000000000000005
result   = fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556
```

5. Different input x (using x(2G)) with t = 3:

```
pubkey32 = c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
h32      = 0000000000000000000000000000000000000000000000000000000000000003
result   = 2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4
```

6. Larger values: input x(7G) with t = 9:

```
pubkey32 = 5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
h32      = 0000000000000000000000000000000000000000000000000000000000000009
result   = e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a
```

### Failing cases

A) Scalar out of range (t = n):

```
pubkey32 = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
h32      = ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
expect   = fail
```

B) Invalid x (no lift possible), example x = 0:

```
pubkey32 = 0000000000000000000000000000000000000000000000000000000000000000
h32      = 0000000000000000000000000000000000000000000000000000000000000001
expect   = fail
```

C) Infinity result: choose input x(G), t = n - 1 (so P + t*G = n*G = infinity):

```
pubkey32 = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
h32      = ffffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
expect   = fail
```


## Reference implementation notes

* Reuse BIP340 lift/encode helpers from Taproot verification.
* Implement `t*G` via fixed-base multiplication, then combine with `P` using point addition.
* Serialize the result as 32-byte x-only.
* Charge EC op budget as 50, like `OP_CHECKSIGADD`.


## Acknowledgements

This proposal extends the Taproot tweak mechanism (BIP340/341) into script, inspired by prior work on scriptless scripts and key-evolution constructions. There has been various discussion of OP_TWEAKADD over the years, including by Russell O'Connor and Steven Roose.

## References

- [CATT: Thoughts about an alternative covenant softfork proposal](https://delvingbitcoin.org/t/catt-thoughts-about-an-alternative-covenant-softfork-proposal/125)
- [Bitcoindev mailing list discussion](https://gnusha.org/pi/bitcoindev/e98d76f2-6f2c-9c3a-6a31-bccb34578c31@roose.io/)
- [Advent 8: Scriptless Scripts and Key Tweaks](https://rubin.io/bitcoin/2021/12/05/advent-8/)
- [Re: [bitcoin-dev] Unlimited covenants, was Re: CHECKSIGFROMSTACK/{Verify} BIP for Bitcoin](https://gnusha.org/pi/bitcoindev/CAMZUoKnVLRLgL1rcq8DYHRjM--8VEUC5kjUbzbY5S860QSbk5w@mail.gmail.com/)
- [Re: [bitcoin-dev] Unlimited covenants, was Re: CHECKSIGFROMSTACK/{Verify} BIP for Bitcoin](https://gnusha.org/pi/bitcoindev/CAMZUoKkAUodCT+2aQG71xwHYD8KXeTAdQq4NmXZ4GBe0pcD=9A@mail.gmail.com/)
- [ElementsProject: Tapscript opcodes documentation](https://github.com/ElementsProject/elements/blob/master/doc/tapscript_opcodes.md#new-opcodes-for-additional-functionality)
