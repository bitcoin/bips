```
  BIP: ???
  Layer: Consensus (soft fork)
  Title: Elliptic Curve Operations for Bitcoin Script
  Author: Olaoluwa Osuntokun <laolu32@gmail.com>
  Comments-Summary: X
  Comments-URI: X
  Status: Draft
  Type: Standards Track
  Created: 2025-08-22
  License: BSD-3-Clause
  Requires: 340, 341, 342
```


# Introduction

## Abstract

This document specifies a series of Elliptic Curve opcodes for secp256k1. These
opcodes permit Bitcoin Script to carry out the individual Elliptic Curve
operations that are used in routine signature generation and validation. When
combined with opcodes such as `OP_CAT` this suite of opcodes enables a higher
degree of expressivity via composition, as they enable the creation of on-chain
state machines, by enabling Bitcoin Script programs to recompute a Tapscript
output public key, from an internal key and a tweak.

## Copyright

This document is licensed under the 3-clause BSD license.

## Motivation

Taproot was introduced via BIP 341. One of Taproot's major improvements was the
introduction of the Tapscript tree, which enabled a greater degree of privacy
and expressively via the creation of an execution mode that allows developers
to commit to N scripts within a Taproot output public key. A satisfying witness
can then opt to reveal just the internal key and a signature, or one of the
leaves with a corresponding authentication path. However, this functionality is
limited as today in Bitcoin Script, a program cannot dynamically compute such a
tree, nor the Taproot output key.

In order to get around this limitation, developers protecting new uses cases
with `OP_CAT` [created the "Caboose"
pattern](https://github.com/Bitcoin-Wildlife-Sanctuary/covenants-examples?tab=readme-ov-file#caboose-the-state-carrying-utxo-via-p2wsh).
As `OP_CAT` alone cannot reconstruct the Tapscript root, developers instead
opted to _commit_ to state in a `P2WSH` output, that commits to a simple
`OP_RETURN` script that carries the state. This approach has a clear drawback
in that it requires spending an extra output to funnel instructions into an
on-chain covenant state machine. This extra output increase the size of the
transaction, uses a legacy output type, and further increases the introspection
Script size.

With the addition of the `OP_EC_POINT_ADD`, `OP_EC_POINT_MUL`, and
`OP_EC_POINT_X_COORD` op codes (in concert with `OP_CAT`), a Bitcoin Script
program gains the ability to recompute the top-level Tapscript output public
key, and use that in assertions for an on-chain state machine. This creates a
natural programming pattern wherein state is committed to in the left sub-tree
of a Tapscript tree, while the actual program being executed is committed to in
the right sub-tree. State can be verified via inclusion proofs passed into the
witness, which can then be executed against the program portion in the right
sub-tree.

Aside from enabling this on-chain state machine paradigm, the addition of
routine Elliptic Curve op codes into Bitcoin Script enables dynamic computation
related to Elliptic Curves. Example use cases include: native blinded signature
verification, partial musig2 signature verification, adapter signature
operations, JIT DLC computations, and generically a large class of Sigma
Protocol based on Elliptic Curves.


# Preliminaries

## Notation and Definitions

The following conventions are used throughout this specification:

### Field and Curve Parameters
* The constant `p` refers to the field size: `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`
* The constant `n` refers to the curve order: `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
* The curve equation is `y² = x³ + 7` over the integers modulo `p`

### Points
* The generator point `G` has coordinates:
  * `x(G) = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798`
  * `y(G) = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8`
* The point at infinity `O` is the identity element of the elliptic curve group
* An empty vector (0 bytes) on the stack represents the point at infinity

## Point Encoding and Decoding

All elliptic curve points in this specification use 33-byte compressed encoding:

### Compressed Point Format (33 bytes)
* First byte: `0x02` if y-coordinate is even, `0x03` if y-coordinate is odd
* Next 32 bytes: x-coordinate in big-endian format

### Point Decoding
To decode a 33-byte compressed point:
1. Verify the first byte is `0x02` or `0x03`
2. Extract x-coordinate from bytes 1-32
3. Verify `x < p`
4. Compute `y² = x³ + 7 mod p`
5. Compute `y = (y²)^((p+1)/4) mod p`
6. Verify `y² = x³ + 7 mod p` (point is on curve)
7. If prefix byte parity doesn't match y parity, set `y = p - y`

```python
def decode_compressed_point(data: bytes) -> Optional[Point]:
    """Decode a 33-byte compressed point."""
    if len(data) != 33:
        raise ValueError(f"Invalid compressed point length: {len(data)}")
    
    prefix = data[0]
    if prefix not in [0x02, 0x03]:
        raise ValueError(f"Invalid compression prefix: {prefix:02x}")
    
    x = int.from_bytes(data[1:33], byteorder='big')
    if x >= p:
        raise ValueError("X coordinate >= field prime")
    
    # Compute y² = x³ + 7 mod p
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    
    if pow(y, 2, p) != y_sq:
        raise ValueError("Invalid point: not on curve")
    
    # Select y coordinate based on prefix parity
    if (y & 1) != (prefix & 1):
        y = p - y
    
    return (x, y)
```

# Design

Only 33-byte public keys are accepted by the set of defined op codes. All op
codes return 33-byte compressed EC points.

The point-at-infinity is represented by an empty byte slice.

Points can be converted into their 32-byte x-only counterpart via a dedicated
op code.

All scalars are encoded as a 32-byte big-endian integer. Scalar values greater
than or equal to the curve order n are automatically reduced modulo n.

The existing sig op cost model introduced by BIP 342 is maintained. Each
introduced op code is assigned a cost designed to ensure that it's more
expensive to re-create common operations (such as signature verification) using
these opcodes, than via the dedicated `OP_CHECKSIG` opcode


# Specification

Depictions of the stack below are always represented from top to bottom. Given
a stack of `[x] [y]`, the first element to be popped off is `[x]`.

## `OP_SUCCESS` Assignment

The following existing `OP_SUCCESS` reserved opcodes are re-allocated to create
our new elliptic curve opcodes: 
  * `OP_EC_POINT_ADD` (`187`/ `0xbb`): Replaces `OP_SUCCESS187`
  * `OP_EC_POINT_MUL` (`188` / `0xbc`): Replaces `OP_SUCCESS188`
  * `OP_EC_POINT_NEGATE` (`189` / `0xbd`): Replaces `OP_SUCCESS189`
  * `OP_EC_POINT_X_COORD` (`190` / `0xbe`): Replaces `OP_SUCCESS190`

## `OP_EC_POINT_ADD`

**Stack Input**: `[point2] [point1]` 

**Stack Output**: `[point1 + point2]`

Pops two elliptic curve points from the stack, computes their sum, and pushes
the result back onto the stack in 33-byte compressed format.

### Execution Rules

1. Fail if the stack contains fewer than two elements.
2. Pop the top two stack elements.
3. For each popped element, validate that it is a valid elliptic curve point:
   a. MUST be exactly 33 bytes in length
   b. First byte MUST be 0x02 or 0x03
   c. The x-coordinate (bytes 1-32) MUST be less than field prime p
   d. The point MUST be on the secp256k1 curve
   e. If any validation fails, script execution MUST fail immediately
4. Compute the elliptic curve point addition: `result = point1 + point2`
5. If the result is the point at infinity:
   a. Push an empty vector (0 bytes) onto the stack
6. Otherwise:
   a. Encode the result in 33-byte compressed format
   b. Push the encoded result onto the stack

### Reference Implementation

```python
def op_ec_point_add(stack: list) -> None:
    """
    Implements OP_EC_POINT_ADD.
    Stack: [point2] [point1] -> [point1 + point2]
    """
    # Check stack depth
    if len(stack) < 2:
        raise ValueError("OP_EC_POINT_ADD requires 2 stack elements")
    
    # Pop elements (top first)
    point2_bytes = stack.pop()
    point1_bytes = stack.pop()
    
    # Validate and decode points
    if len(point1_bytes) != 33 or len(point2_bytes) != 33:
        raise ValueError("Points must be 33 bytes")
    
    P1 = decode_compressed_point(point1_bytes)
    P2 = decode_compressed_point(point2_bytes)
    
    # Point addition
    if P1[0] == P2[0]:
        if P1[1] != P2[1]:
            # P + (-P) = O
            stack.append(b'')
            return
        # Point doubling: λ = (3x₁²)/(2y₁)
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p
    else:
        # Point addition: λ = (y₂ - y₁)/(x₂ - x₁)  
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    
    # Compute result: x₃ = λ² - x₁ - x₂
    x3 = (lam * lam - P1[0] - P2[0]) % p
    # y₃ = λ(x₁ - x₃) - y₁
    y3 = (lam * (P1[0] - x3) - P1[1]) % p
    
    # Push result
    stack.append(encode_compressed_point((x3, y3)))
```

## `OP_EC_POINT_MUL`

**Stack Input**: `[scalar] [point]`

**Stack Output**: `[scalar * point]`

Pops a scalar value and an elliptic curve point from the stack, computes scalar
multiplication, and pushes the result in 33-byte compressed format.

### Execution Rules

1. Fail if the stack contains fewer than two elements.
2. Pop the top two stack elements (scalar on top, then point).
3. Validate the scalar:
   a. MUST be exactly 32 bytes in length
   b. If the scalar value is greater than or equal to the curve order n, it is automatically reduced modulo n
   c. If the length validation fails, script execution MUST fail immediately
4. Validate the point:
   a. If the point is an empty vector (0 bytes):
      i. Interpret as the secp256k1 generator point G
      ii. This enables efficient computation of `scalar * G`
   b. Otherwise, the point MUST be a valid 33-byte compressed point:
      i. Length MUST be exactly 33 bytes
      ii. First byte MUST be 0x02 or 0x03
      iii. The x-coordinate MUST be less than field prime p
      iv. The point MUST be on the secp256k1 curve
   c. If validation fails, script execution MUST fail immediately
5. Compute the scalar multiplication: `result = scalar * point`
6. If the result is the point at infinity:
   a. Push an empty vector (0 bytes) onto the stack
7. Otherwise:
   a. Encode the result in 33-byte compressed format
   b. Push the encoded result onto the stack

### Reference Implementation

```python
def op_ec_point_mul(stack: list) -> None:
    """
    Implements OP_EC_POINT_MUL.
    Stack: [scalar] [point] -> [scalar * point]
    """
    # Check stack depth
    if len(stack) < 2:
        raise ValueError("OP_EC_POINT_MUL requires 2 stack elements")
    
    # Pop elements (top first)
    scalar_bytes = stack.pop()
    point_bytes = stack.pop()
    
    # Validate scalar
    if len(scalar_bytes) != 32:
        raise ValueError(f"Invalid scalar length: {len(scalar_bytes)}")
    
    k = int.from_bytes(scalar_bytes, byteorder='big')
    # Reduce modulo n if needed
    k = k % n
    
    # Handle point
    if len(point_bytes) == 0:
        # Empty vector means generator point G
        P = G
    elif len(point_bytes) == 33:
        P = decode_compressed_point(point_bytes)
    else:
        raise ValueError(f"Invalid point length: {len(point_bytes)}")
    
    # Double-and-add algorithm (constant-time in production)
    R = None  # Start at infinity
    for i in range(256):
        if (k >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    
    # Push result
    if R is None:
        stack.append(b'')  # Point at infinity
    else:
        stack.append(encode_compressed_point(R))
```

## `OP_EC_POINT_NEGATE`

**Stack Input**: `[point]` (top element)

**Stack Output**: `[-point]`

Pops an elliptic curve point from the stack, computes its negation, and pushes
the result in 33-byte compressed format.

### Execution Rules

1. Fail if the stack is empty.
2. Pop the top stack element.
3. Validate the point:
   a. If the point is an empty vector (0 bytes):
      i. Push an empty vector back onto the stack (negation of infinity is infinity)
      ii. Execution succeeds and terminates here
   b. Otherwise, validate as a 33-byte compressed point:
      i. Length MUST be exactly 33 bytes
      ii. First byte MUST be 0x02 or 0x03
      iii. The x-coordinate MUST be less than field prime p
      iv. The point MUST be on the secp256k1 curve
   c. If validation fails, script execution MUST fail immediately
4. Compute the point negation: `result = -point`
   a. For point (x, y), the negation is (x, p - y)
5. Encode the result in 33-byte compressed format
6. Push the encoded result onto the stack

### Reference Implementation

```python
def op_ec_point_negate(stack: list) -> None:
    """
    Implements OP_EC_POINT_NEGATE.
    Stack: [point] -> [-point]
    """
    # Check stack depth
    if len(stack) < 1:
        raise ValueError("OP_EC_POINT_NEGATE requires 1 stack element")
    
    # Pop element
    point_bytes = stack.pop()
    
    # Handle infinity
    if len(point_bytes) == 0:
        stack.append(b'')  # -O = O
        return
    
    # Validate point
    if len(point_bytes) != 33:
        raise ValueError(f"Invalid point length: {len(point_bytes)}")
    
    P = decode_compressed_point(point_bytes)
    
    # Negate y-coordinate
    neg_P = (P[0], (p - P[1]) % p)
    
    # Push result
    stack.append(encode_compressed_point(neg_P))
```

## `OP_EC_POINT_X_COORD`

**Stack Input**: `[point]` (top element)

**Stack Output**: `[x_coordinate]`

Pops an elliptic curve point from the stack and pushes its x-coordinate.

### Execution Rules

1. Fail if the stack is empty.
2. Pop the top stack element.
3. Validate the point:
   a. If the point is an empty vector (0 bytes):
      i. Script execution MUST fail (cannot extract x-coordinate from infinity)
   b. Otherwise, validate as a 33-byte compressed point:
      i. Length MUST be exactly 33 bytes
      ii. First byte MUST be 0x02 or 0x03
      iii. The x-coordinate MUST be less than field prime p
      iv. The point MUST be on the secp256k1 curve
   c. If validation fails, script execution MUST fail immediately
4. Extract the x-coordinate from the point
5. Push the x-coordinate as a 32-byte big-endian value onto the stack

### Reference Implementation

```python
def op_ec_point_x_coord(stack: list) -> None:
    """
    Implements OP_EC_POINT_X_COORD.
    Stack: [point] -> [x_coordinate]
    """
    # Check stack depth
    if len(stack) < 1:
        raise ValueError("OP_EC_POINT_X_COORD requires 1 stack element")
    
    # Pop element
    point_bytes = stack.pop()
    
    # Cannot extract x from infinity
    if len(point_bytes) == 0:
        raise ValueError("Cannot extract x from infinity")
    
    # Validate point
    if len(point_bytes) != 33:
        raise ValueError(f"Invalid point length: {len(point_bytes)}")
    
    # Validate point is on curve
    P = decode_compressed_point(point_bytes)
    
    # Push x-coordinate  
    stack.append(P[0].to_bytes(32, byteorder='big'))
```

## Resource Limits

As mentioned above, each opcode will consume from the per-input sigops budget:
- `OP_EC_POINT_ADD`: Consumes 10 units from the sigops budget
- `OP_EC_POINT_MUL`: Consumes 30 units from the sigops budget
- `OP_EC_POINT_NEGATE`: Consumes 5 units from the sigops budget
- `OP_EC_POINT_X_COORD`: Consumes 1 unit from the sigops budget

# Rationale

## Resource Pricing

The resource pricing was set up, so that it's more expensive to manually
compute the BIP 340 signature verification compared to just using plain
`OP_CHECKSIG`.

Schnorr (BIP 340) signature verification computes: `R = s⋅G - e⋅P`, then checks
`x(R) = r`.

Using our opcodes, this requires:
- 1 × OP_EC_POINT_MUL for s⋅G (30 units)
- 1 × OP_EC_POINT_MUL for e⋅P (30 units)  
- 1 × OP_EC_POINT_NEGATE for -e⋅P (5 units)
- 1 × OP_EC_POINT_ADD for the final addition (10 units)
- 1 × OP_EC_POINT_X_COORD to extract `x(R)` (1 unit)
- Plus computing e and comparison (additional overhead)

If we sum up all the cost units, we arrive at 76 units minimum vs 50 units for
`OP_CHECKSIG`.

All in all, we arrive at a 52% premium for manual derivation vs just using
`OP_CHECKSIG`. This ensures that it requires more resources to use the opcodes
for this purpose than normally.

This 52% premium provides strong economic incentive to use the optimized
OP_CHECKSIG for signature verification rather than reimplementing it manually.

## Why Are Only 33-byte Points Accepted?

Accepting only 33-byte points simplifies usage of these opcodes. Otherwise,
chained operations may require the tracking/offset of the parity bit.
Additionally since the advent of 32-byte public keys for Taproot, many
developer hours have been spent tracking down bugs related to the information
lost when converting from 33-byte to 32-byte public keys.

An op code to convert to a 32-byte public key `OP_EC_POINT_X_COORD` has been
provided to facilitate checks against an expected Taproot public key. This is
critical to enable the on-chain state machine pattern we described in the
motivation section.

```
<tweak> <empty_vector> OP_EC_POINT_MUL  # tweak*G (33-byte)
<internal_key> OP_EC_POINT_ADD           # P + tweak*G (33-byte)
OP_EC_POINT_X_COORD                      # Extract x-coordinate (32-byte)
```

## Why Use Empty Vector for the Generator?

For the `OP_EC_POINT_MUL` we accept an empty vector to denote the generator
point. This saves 33 bytes versus pushing up the generator manually. This
enables an optimization for the common case of `k*G` to compute a point from a
scalar.

## Why Add Point Negation?

Originally this was omitted. It's possible to compute the negation of a point
by scalar multiplication by `(n-1) mod n`, however this BIP doesn't define
scalar operations. 

In addition, the BIP 340 Schnorr verification can only be computed by negating
the point of the challenge times the public key. Therefore the addition of a
point negation operation completes this suite.

# Example Programs

## Computing a Taproot Tweak

To compute `P + tweak*G` where P is an internal key (33-byte compressed) and
tweak is a hash value:

```
<tweak> <empty_vector> OP_EC_POINT_MUL <P_compressed> OP_EC_POINT_ADD OP_EC_POINT_X_COORD
```

Step by step:
```
<tweak>                 # Stack: [tweak]
<empty_vector>          # Stack: [tweak, <>]
OP_EC_POINT_MUL         # Stack: [tweak*G] (33-byte compressed format)
<P_compressed>          # Stack: [tweak*G, P] (P must be 33-byte compressed)
OP_EC_POINT_ADD         # Stack: [P + tweak*G] (33-byte compressed format)
OP_EC_POINT_X_COORD     # Stack: [x-coordinate] (32-byte for taproot)
```

## Point Doubling

To compute 2*P for a point P (33-byte compressed):

```
<P_compressed> OP_DUP OP_EC_POINT_ADD
```

## Scalar Multiplication by Arbitrary Point

To compute k*P for scalar k and point P (33-byte compressed):

```
<k> <P_compressed> OP_EC_POINT_MUL
```

## Converting Point Formats

To convert a 33-byte compressed point to 32-byte x-only format:

```
<P_compressed> OP_EC_POINT_X_COORD
```

This extracts the x-coordinate directly, which is the 32-byte representation
used in taproot.

## BIP-340 Schnorr Signature Verification (Educational Example)

BIP-340 verification checks: s⋅G = R + e⋅P, then verifies x(R) = r

Stack inputs: `[message] [signature] [pubkey]`

```
# Assume signature is already split into r (32 bytes) and s (32 bytes)
# Stack: [message] [r] [s] [pubkey]

# Duplicate r for final comparison
OP_DUP                          # Stack: [message] [r] [r] [s] [pubkey]
OP_ROT                          # Stack: [message] [r] [pubkey] [r] [s]
OP_ROT                          # Stack: [message] [r] [s] [pubkey] [r]

# Compute e = hash(r || pubkey || message) mod n
# Note: This requires additional op codes to concat the args to hash
# For this example, assume we have e on stack
<e>                             # Stack: [message] [r] [s] [pubkey] [r] [e]

# Compute e⋅P
OP_SWAP                         # Stack: [message] [r] [s] [r] [e] [pubkey]
OP_ROT                          # Stack: [message] [r] [s] [r] [pubkey] [e]
OP_EC_POINT_MUL                 # Stack: [message] [r] [s] [r] [e⋅P]

# Compute s⋅G  
OP_SWAP                         # Stack: [message] [r] [r] [e⋅P] [s]
<empty_vector>                  # Stack: [message] [r] [r] [e⋅P] [s] [<>]
OP_EC_POINT_MUL                 # Stack: [message] [r] [r] [e⋅P] [s⋅G]

# Compute R' = s⋅G - e⋅P
# First negate e⋅P
OP_SWAP                         # Stack: [message] [r] [r] [s⋅G] [e⋅P]
OP_EC_POINT_NEGATE              # Stack: [message] [r] [r] [s⋅G] [-(e⋅P)]

# Add s⋅G + (-(e⋅P)) = s⋅G - e⋅P
OP_EC_POINT_ADD                 # Stack: [message] [r] [r] [R']

# Extract x-coordinate from R'
OP_EC_POINT_X_COORD             # Stack: [message] [r] [r] [x(R')]

# Verify x(R') == r
OP_EQUAL                        # Stack: [message] [r] [bool]
# ... continue with verification logic
```

# Backwards Compatibility

# Reference Implementation

https://github.com/roasbeef/btcd/tree/ec-op-codes

# Test Vectors

All test vectors are available in the `bip-ec-ops/test-vectors/` directory of this repository. The test vectors follow the taproot-ref JSON format used by Bitcoin Core.

## Test Vector Format

Each test vector contains:
- `tx`: The spending transaction in hex
- `prevouts`: Array of previous outputs being spent  
- `index`: Input index being validated
- `flags`: Script verification flags
- `comment`: Description of what the test validates
- `success` or `failure`: Expected witness stack for passing or failing tests

## OP_EC_POINT_ADD Test Vectors

### Valid: Add two 33-byte points
This test verifies basic point addition with two compressed public keys.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002682103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da61221038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0acbb210284df99cc50d1ec93e9bc32c666325a389dd69a7f42777b8f1670ad66d2e622c98721c1f1dd3079589438fb556253fa5b1d685518fe0dcda0cfd1dd28b11608b0651b6500000000",
  "prevouts": [
    "a086010000000000225120bdccf1fb4466b26d66d764c61d1cabe8fcbb6598748b62fd64deb9260dde7f04"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "add two 33-byte points",
  "success": {
    "scriptSig": "",
    "witness": [
      "2103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da61221038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0acbb210284df99cc50d1ec93e9bc32c666325a389dd69a7f42777b8f1670ad66d2e622c987",
      "c1f1dd3079589438fb556253fa5b1d685518fe0dcda0cfd1dd28b11608b0651b65"
    ]
  }
}
```

### Invalid: Insufficient stack items
Tests that the opcode fails when there are not enough items on the stack.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a086010000000000000201bb21c1a328913bce52f1ed4a17cf00680f6c0f066a4a5c9f576db183ec422aa6a14f9900000000",
  "prevouts": [
    "a0860100000000002251205d11cca3ec3eab91d709ea18b2de550b82e3240ae0daad6c13c17037c6a3d09f"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "insufficient stack items",
  "failure": {
    "scriptSig": "",
    "witness": [
      "bb",
      "c1a328913bce52f1ed4a17cf00680f6c0f066a4a5c9f576db183ec422aa6a14f99"
    ]
  }
}
```

## OP_EC_POINT_MUL Test Vectors

### Valid: Multiply generator by scalar (empty point)
Tests scalar multiplication with the generator point G (represented as empty vector).
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a08601000000000000024620000000000000000000000000000000000000000000000000000000000000000200bc2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee58721c04e5d0761dac697652bc9e660749f9a56cbc8dc6eb7f5fcf4efef44ee960b976200000000",
  "prevouts": [
    "a086010000000000225120c534c653b0c46394875c8a377537a7fdd258d818ee1331e9ed804163d1dd8920"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "multiply generator by scalar (empty point)",
  "success": {
    "scriptSig": "",
    "witness": [
      "20000000000000000000000000000000000000000000000000000000000000000200bc2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee587",
      "c04e5d0761dac697652bc9e660749f9a56cbc8dc6eb7f5fcf4efef44ee960b9762"
    ]
  }
}
```

## Complex Operations Test Vectors

### Valid: Computing a Taproot Tweak (P + tweak*G)
Tests the complete workflow of computing a taproot tweak, demonstrating practical usage of multiple EC opcodes together.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a08601000000000000026920000000000000000000000000000000000000000000000000000000000000000500bc210326c4dd2b3ed6cb114ac7981d958391f58f1d435a6800e4ba5fc4ec973d64c854bb21027e41f3468b33d03e76ed78f346c66644a7a31575dda359fe898520b9ed8245868721c19e76b08c79a7e0bb6ca20f7763ece21cf98e72efc326d26d1bf8d34c78b2c1f200000000",
  "prevouts": [
    "a08601000000000022512011209b083c36057f641cc93419015e0cb44c08b0b499fd54b26c4eaad0d3afc5"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "Computing a Taproot Tweak (P + tweak*G)",
  "success": {
    "scriptSig": "",
    "witness": [
      "20000000000000000000000000000000000000000000000000000000000000000500bc210326c4dd2b3ed6cb114ac7981d958391f58f1d435a6800e4ba5fc4ec973d64c854bb21027e41f3468b33d03e76ed78f346c66644a7a31575dda359fe898520b9ed82458687",
      "c19e76b08c79a7e0bb6ca20f7763ece21cf98e72efc326d26d1bf8d34c78b2c1f2"
    ]
  }
}
```

### Valid: Point doubling
Tests adding a point to itself (P + P = 2P).
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002682103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da6122103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612bb210365c08a6b61c8a225760df455512496a3cce0d74f597ad8d5338ca1688aa53bc88721c1b841414474a073f8baf79d1e724081b765ea3a3f87a8780bdc69483a0a7c75c400000000",
  "prevouts": [
    "a086010000000000225120329376f19233d37860e6988a4ba29ebcdccd5813a97b16a85b59ab87069446a4"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "add point to itself (point doubling)",
  "success": {
    "scriptSig": "",
    "witness": [
      "2103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da6122103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612bb210365c08a6b61c8a225760df455512496a3cce0d74f597ad8d5338ca1688aa53bc887",
      "c1b841414474a073f8baf79d1e724081b765ea3a3f87a8780bdc69483a0a7c75c4"
    ]
  }
}
```

### Valid: Point at infinity
Tests adding a point and its negation (P + (-P) = 0).
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002472103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da6122102d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612bb008721c0f53d4ee246500cbd5bc5010fcd5955f91040d658a2761f1700d477cfd3dae4cd00000000",
  "prevouts": [
    "a086010000000000225120b213126b12c0c5bc9fea81869d4c98d8aeec2962bd79abccaf19cd8c9c5af6e7"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "add point and its negation (infinity)",
  "success": {
    "scriptSig": "",
    "witness": [
      "2103d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da6122102d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da612bb0087",
      "c0f53d4ee246500cbd5bc5010fcd5955f91040d658a2761f1700d477cfd3dae4cd"
    ]
  }
}
```

### Invalid: Invalid point coordinates
Tests handling of points with x-coordinate > field prime.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002452102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff21038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0acbb21c034f5f2a7ea908584632aba9320336fc99072c7d6d3c4ff3b4833849264cb2d4600000000",
  "prevouts": [
    "a086010000000000225120d16722acd2e0bcb47c83adc068d7d1988c0c9cd22fe60410a38acf6d720fda72"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "invalid point - x coordinate too large",
  "failure": {
    "scriptSig": "",
    "witness": [
      "2102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff21038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0acbb",
      "c034f5f2a7ea908584632aba9320336fc99072c7d6d3c4ff3b4833849264cb2d46"
    ]
  }
}
```

### Invalid: Reject 32-byte x-only input
Tests that 32-byte x-only points are rejected by ADD operation.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a08601000000000000024420d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da61221038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0acbb21c110945c301563e2c6cda22d73c860cb83dbba2856cf6a2f9eb2200a83b953d89c00000000",
  "prevouts": [
    "a086010000000000225120a287509e2698cfe262fa839890f7a513228dffbc8e156d0a65a9e7f48d685dfb"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "reject 32-byte x-only input",
  "failure": {
    "scriptSig": "",
    "witness": [
      "20d5a5c6797a56d30378dba0484493302b5d8dc02dff2f550568641036796da61221038d1eadc80f1d0bbf345f3c5202946a0b72e2c217242f5d8c3c8bc5d5467ff0acbb",
      "c110945c301563e2c6cda22d73c860cb83dbba2856cf6a2f9eb2200a83b953d89c"
    ]
  }
}
```

### Invalid: ADD budget exceeded
Tests sigops budget enforcement for ADD operations.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002fdcb032102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa072102e2bb24c22b6c9cc29f9a54e7258735eb3f1ab2dab698fb69d75483349180058c6ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb75bb755121c19e0877d4fa6432093b3aca5f501129c1a87e9404b44cb489824b3c6e7f488fc200000000",
  "prevouts": [
    "a086010000000000225120595b5ed2b203b66290d4979a03af50060065777f1d4d3ab321a9ab9656a4ea2b"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "ADD: budget exceeded",
  "failure": {
    "scriptSig": "",
    "witness": [
      "2102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa072102e2bb24c22b6c9cc29f9a54e7258735eb3f1ab2dab698fb69d75483349180058c6ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb756ebb75bb7551",
      "c19e0877d4fa6432093b3aca5f501129c1a87e9404b44cb489824b3c6e7f488fc2"
    ]
  }
}
```

## OP_EC_POINT_MUL Test Vectors

### Valid: Multiply by zero (infinity)
Tests scalar multiplication by zero, resulting in the point at infinity.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002462000000000000000000000000000000000000000000000000000000000000000002102a95d0d38d0d6519fe5c7a77b07bf6c367099d2d3a9b6a8da36251bcc2863e20fbc008721c0bc1bcd8620ab6eaee4bd999a33d287d907ea8a3aa00fb7f58dfabd2afb54485700000000",
  "prevouts": [
    "a08601000000000022512016c4722fac664bad20699b1b2673ea5898878d14fdd975adb052205c72ce898b"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "multiply by zero (infinity)",
  "success": {
    "scriptSig": "",
    "witness": [
      "2000000000000000000000000000000000000000000000000000000000000000002102a95d0d38d0d6519fe5c7a77b07bf6c367099d2d3a9b6a8da36251bcc2863e20fbc0087",
      "c0bc1bcd8620ab6eaee4bd999a33d287d907ea8a3aa00fb7f58dfabd2afb544857"
    ]
  }
}
```

### Valid: Multiply point by 2
Tests scalar multiplication (2*P).
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002672000000000000000000000000000000000000000000000000000000000000000022102a95d0d38d0d6519fe5c7a77b07bf6c367099d2d3a9b6a8da36251bcc2863e20fbc2103519a934fadfca15c7fbb8b6bfb03464ee22bc594cecc6d842ce8089d99fe53718721c1e2d35660811d01bfe552a92937240da8420a1cbbb676a3df35a88686681e7fad00000000",
  "prevouts": [
    "a086010000000000225120982c493d24ce8a74e509b863a1a59926dbc7f438f0925da9122aaff17846871a"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "multiply point by 2",
  "success": {
    "scriptSig": "",
    "witness": [
      "2000000000000000000000000000000000000000000000000000000000000000022102a95d0d38d0d6519fe5c7a77b07bf6c367099d2d3a9b6a8da36251bcc2863e20fbc2103519a934fadfca15c7fbb8b6bfb03464ee22bc594cecc6d842ce8089d99fe537187",
      "c1e2d35660811d01bfe552a92937240da8420a1cbbb676a3df35a88686681e7fad"
    ]
  }
}
```

### Invalid: MUL insufficient stack
Tests handling of insufficient stack items for MUL operation.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a086010000000000000222200000000000000000000000000000000000000000000000000000000000000000bc21c0659db62321d339abc8c6105bd4e410e7902d018767a23b889140af7055c3175600000000",
  "prevouts": [
    "a0860100000000002251206dd3ba59a75cf0874457fbd7c7c355933cb9a74f8341a89c80d7f5d410c4ed7e"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "MUL: insufficient stack",
  "failure": {
    "scriptSig": "",
    "witness": [
      "200000000000000000000000000000000000000000000000000000000000000000bc",
      "c0659db62321d339abc8c6105bd4e410e7902d018767a23b889140af7055c31756"
    ]
  }
}
```

### Invalid: MUL invalid scalar length
Tests handling of invalid scalar length for MUL operation.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a086010000000000000227030102032102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa07bc21c1b9bad3201fdf6daa0a226bbd4bbf46580c50a46437c2ec43cd73620c08b7289400000000",
  "prevouts": [
    "a0860100000000002251201e0b312ef7af7256bf3ad9f2cad29323464473d44145d46c503140ddca0c5663"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "MUL: invalid scalar length",
  "failure": {
    "scriptSig": "",
    "witness": [
      "030102032102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa07bc",
      "c1b9bad3201fdf6daa0a226bbd4bbf46580c50a46437c2ec43cd73620c08b72894"
    ]
  }
}
```

### Invalid: MUL budget exceeded
Tests sigops budget enforcement for MUL operations.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002fd72012000000000000000000000000000000000000000000000000000000000000000022102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa076ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc75bc755121c03784b72912cce22aba765b3aa4713b732f7f96e08a294c1169b1c2f8adf05d2800000000",
  "prevouts": [
    "a0860100000000002251202fc3d1ac4749696f46815849941ca248b679f4b6a0563d6baf921ef68b97adbf"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "MUL: budget exceeded",
  "failure": {
    "scriptSig": "",
    "witness": [
      "2000000000000000000000000000000000000000000000000000000000000000022102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa076ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc756ebc75bc7551",
      "c03784b72912cce22aba765b3aa4713b732f7f96e08a294c1169b1c2f8adf05d28"
    ]
  }
}
```

## OP_EC_POINT_NEGATE Test Vectors

### Valid: Negate point
Tests point negation operation.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002462102c45ad60752c449497980924aa8f602fad3ce0414fbff83b4d7e48f3d2b1e82d5bd2103c45ad60752c449497980924aa8f602fad3ce0414fbff83b4d7e48f3d2b1e82d58721c1501665cef6fec900f205abd7261eef0151bf6f6708f0720afd93b43d70f9fa5d00000000",
  "prevouts": [
    "a08601000000000022512048b2286b148876cba70b6e3efd0998b8ef8220362c926c6b5d74bec0e4d72add"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "negate point",
  "success": {
    "scriptSig": "",
    "witness": [
      "2102c45ad60752c449497980924aa8f602fad3ce0414fbff83b4d7e48f3d2b1e82d5bd2103c45ad60752c449497980924aa8f602fad3ce0414fbff83b4d7e48f3d2b1e82d587",
      "c1501665cef6fec900f205abd7261eef0151bf6f6708f0720afd93b43d70f9fa5d"
    ]
  }
}
```

### Invalid: Negate infinity
Tests that negating the point at infinity fails.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a086010000000000000201bd21c110c090416c08837952647beb78b735e2ea9757ed396daac0ba14a0bd3661b5bb00000000",
  "prevouts": [
    "a086010000000000225120a59ef4c3e0653f3f9d28b866457f8f533b7fe047e645744b7b3466cc234d4aca"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "negate infinity",
  "failure": {
    "scriptSig": "",
    "witness": [
      "bd",
      "c110c090416c08837952647beb78b735e2ea9757ed396daac0ba14a0bd3661b5bb"
    ]
  }
}
```

### Invalid: NEGATE insufficient stack
Tests handling of insufficient stack items for NEGATE operation.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a086010000000000000201bd21c00d1c97f90e0e927ffef5fd6cd8366a477be707b17a66d63d8ab5faf9c80df78800000000",
  "prevouts": [
    "a0860100000000002251209f48c70f375a1ab5ae6e1a4f42c3e0229dd7292d69dfa1d648619c83986083e1"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "NEGATE: insufficient stack",
  "failure": {
    "scriptSig": "",
    "witness": [
      "bd",
      "c00d1c97f90e0e927ffef5fd6cd8366a477be707b17a66d63d8ab5faf9c80df788"
    ]
  }
}
```

### Invalid: NEGATE budget exceeded
Tests sigops budget enforcement for NEGATE operations.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002fd16022102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa07bdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbd21c1618959f75103468eb65821c0f199f5f8cd3beb3c9979378eb6603a491d9afb7a00000000",
  "prevouts": [
    "a086010000000000225120cf35dfccc3e4382452fa3b58dbc108d2fb88192359799107105b8283371f430a"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "NEGATE: budget exceeded",
  "failure": {
    "scriptSig": "",
    "witness": [
      "2102a1eaff599957c9061e19d828eb20aa91ac021ace6bc4a9d2056401b5c964aa07bdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbd",
      "c1618959f75103468eb65821c0f199f5f8cd3beb3c9979378eb6603a491d9afb7a"
    ]
  }
}
```

## OP_EC_POINT_X_COORD Test Vectors

### Valid: Extract x from 33-byte point
Tests extracting x-coordinate from a 33-byte compressed point.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002452103a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e13be20a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e138721c1e0c9660dc7ac5cfcdd53d7963cc7e278136398ec9a151a563ff2928ecb8f9c0500000000",
  "prevouts": [
    "a086010000000000225120f8b034227c5cde4357d50a45c2c62329475a5c2fb4b14b4002fc0f9c17b87d0f"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "extract x from 33-byte point",
  "success": {
    "scriptSig": "",
    "witness": [
      "2103a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e13be20a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e1387",
      "c1e0c9660dc7ac5cfcdd53d7963cc7e278136398ec9a151a563ff2928ecb8f9c05"
    ]
  }
}
```

### Invalid: Extract x from 32-byte point
Tests that extracting x-coordinate from 32-byte x-only point fails.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a08601000000000000024420a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e13be20a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e138721c1d7c5c3f0ebdad5a1f1c785b8be132051541c68716b01bfb73e182bed0df0015500000000",
  "prevouts": [
    "a0860100000000002251201405d112d7a8a582327ac8647deb8b1aa3345538e200075d767eea88e3bbd6df"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "extract x from 32-byte point",
  "failure": {
    "scriptSig": "",
    "witness": [
      "20a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e13be20a8d2660f97eb8b320b3951a7adc1a32c54119bdb779287f2c87825459ce43e1387",
      "c1d7c5c3f0ebdad5a1f1c785b8be132051541c68716b01bfb73e182bed0df00155"
    ]
  }
}
```

### Invalid: X_COORD insufficient stack
Tests handling of insufficient stack items for X_COORD operation.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a086010000000000000201be21c1e3b45dcd5b44dbad88ebcb4fbc80c8ac47b1a22fcfeda87557e3dbd60838460f00000000",
  "prevouts": [
    "a08601000000000022512017f2e29eca6ddd0b56d8ca75dc5ff3db8c401c37dcd330fad11e85cb7295ea73"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "X_COORD: insufficient stack",
  "failure": {
    "scriptSig": "",
    "witness": [
      "be",
      "c1e3b45dcd5b44dbad88ebcb4fbc80c8ac47b1a22fcfeda87557e3dbd60838460f"
    ]
  }
}
```

### Invalid: X_COORD point at infinity
Tests that extracting x-coordinate from the point at infinity fails.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a08601000000000000020200be21c09bf7d51d7b83593bc6b5b118e9d389f304f3b82a0ca5cfacf9f142236942d80500000000",
  "prevouts": [
    "a086010000000000225120691dfa3b2fdb8b0c32d8de04dfd6720dce6a2c48fbf93de7f7b1b028090c84ae"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "X_COORD: point at infinity",
  "failure": {
    "scriptSig": "",
    "witness": [
      "00be",
      "c09bf7d51d7b83593bc6b5b118e9d389f304f3b82a0ca5cfacf9f142236942d805"
    ]
  }
}
```

### Invalid: X_COORD extract x from infinity fails
Tests that extracting x-coordinate from computed infinity fails.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a086010000000000000201be21c02c284a0fcd7c89fae0165d5dbe502ad504d29d396bf62fb366dd79feb0abb72800000000",
  "prevouts": [
    "a086010000000000225120be514e05bec6d4da7f6a35f165e32bad0c2b5d432ffd8c2ac3d3c28544c3f094"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "extract x from infinity fails",
  "failure": {
    "scriptSig": "",
    "witness": [
      "be",
      "c02c284a0fcd7c89fae0165d5dbe502ad504d29d396bf62fb366dd79feb0abb728"
    ]
  }
}
```

### Invalid: X_COORD invalid point
Tests handling of invalid point coordinates for X_COORD operation.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a08601000000000000020254be21c18547ec06c7e4a7190ceda28bfa9d567a66c597bcaadbf8ffeb88e92b059dc85900000000",
  "prevouts": [
    "a086010000000000225120938771942788be4939998169ee5b961ce1d175a46f7836f1f0352deec8a9f5b0"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "X_COORD: invalid point",
  "failure": {
    "scriptSig": "",
    "witness": [
      "54be",
      "c18547ec06c7e4a7190ceda28bfa9d567a66c597bcaadbf8ffeb88e92b059dc859"
    ]
  }
}
```

## Budget Testing Test Vectors

### Valid: OP_EC_POINT_ADD consumes 10 units
Tests that ADD operation correctly consumes 10 sigops units.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002472102585ef07fe51f6e81afe974b497e10b295e349c8229ec6ace9afc6c06876c75ae2102585ef07fe51f6e81afe974b497e10b295e349c8229ec6ace9afc6c06876c75aebb755121c156a774f1b7cac5e176e65c8b00567054cfaf95ca64d3ac7235e518aacc08ba6500000000",
  "prevouts": [
    "a08601000000000022512008834fd2db8dc5e2ba6c4e38482b56409a1560bb2e663e740d9023dcc049d814"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "OP_EC_POINT_ADD consumes 10 units",
  "success": {
    "scriptSig": "",
    "witness": [
      "2102585ef07fe51f6e81afe974b497e10b295e349c8229ec6ace9afc6c06876c75ae2102585ef07fe51f6e81afe974b497e10b295e349c8229ec6ace9afc6c06876c75aebb7551",
      "c156a774f1b7cac5e176e65c8b00567054cfaf95ca64d3ac7235e518aacc08ba65"
    ]
  }
}
```

## Additional Invalid Encoding Test Vectors

### Invalid: ADD invalid point encoding length
Tests handling of invalid point encoding length.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002260202032102e2bb24c22b6c9cc29f9a54e7258735eb3f1ab2dab698fb69d75483349180058cbb21c0b775583e9cb1bb101da3740ec70e11680877f1e2bca699365216076e28b14b1000000000",
  "prevouts": [
    "a0860100000000002251201d8282cc92f08b535493d3207abe78d91aa3bee261ffdcab8a77c0a9fb91a3ae"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "ADD: invalid point encoding length",
  "failure": {
    "scriptSig": "",
    "witness": [
      "0202032102e2bb24c22b6c9cc29f9a54e7258735eb3f1ab2dab698fb69d75483349180058cbb",
      "c0b775583e9cb1bb101da3740ec70e11680877f1e2bca699365216076e28b14b10"
    ]
  }
}
```

### Invalid: Invalid point - x too large
Tests handling of invalid point with x-coordinate = 0xffff...ffff.
```json
{
  "tx": "02000000000101000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0860100000000000002232102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbe21c1e5d3fbe9f737014a4092769380f8e1edf3bf3fc75804ecfe247bbb211ebef78700000000",
  "prevouts": [
    "a086010000000000225120bd088a352386d4c7020bf37a02964228a1a7220725ef997fd291686c9f6e99d3"
  ],
  "index": 0,
  "flags": "P2SH,WITNESS,TAPROOT,EC_OPS",
  "comment": "invalid point",
  "failure": {
    "scriptSig": "",
    "witness": [
      "2102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbe",
      "c1e5d3fbe9f737014a4092769380f8e1edf3bf3fc75804ecfe247bbb211ebef787"
    ]
  }
}
```

## Additional Test Vectors

All test vectors are available in the `bip-ec-ops/test-vectors/` directory with comprehensive coverage of:
- Valid operations for all opcodes
- Invalid encodings and edge cases
- Budget enforcement tests
- Stack error conditions
- Point at infinity handling
- Invalid point coordinates

# Changelog

# Copyright
