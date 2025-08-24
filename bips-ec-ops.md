```
  BIP: ????
  Layer: Consensus (soft fork)
  Title: Elliptic Curve Opcodes
  Author: Olaoluwa Osuntokun <laolu32@gmail.com>
  Comments-URI: ???
  Status: Draft
  Type: Standards Track
  Created: 2025-08-22
  License: BSD-3-Clause
```


# Abstract

This document specifies a series of Elliptic Curve opcodes for secp256k1. These
op codes permit Bitcoin Script to carry out the individual Elliptic Curve
operations that are used in routine signature generation and validation. When
combined with op codes such as `OP_CAT` this suite of op code enables a higher
degree of expressively via composition, as they enable to creation of on-chain
state machines, by enabling Bitcoin Script programs to recompute a Tapscript
output public key, from an internal key and a tweak.

# Motivation

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
of a Taspcript tree, while the actual program being executed is committed to in
the right sub-tree. State can be verified via inclusion proofs passed into the
witness, which can then be executed against the program portion in the right
sub-tree.

Aside from enabling this on-chain state machine paradigm, the addition of
routine Elliptic Curve op codes into Bitcoin Script enables dynamic computation
related to Elliptic Curves. Example use cases include: native blinded signature
verification, musig key aggregation, partial musig2 signature verification,
adapter signature operations, JIT DLC computations, and generically a large
class of Sigma Protocol based on Elliptic Curves.


# Design

Only 33-byte public keys are accepted by the set of defined op codes. All op
codes return 33-byte compressed EC points.

The point-at-infinity is represented by an empty byte slice.

Points can be converted into their 32-byte x-only counterpart via a dedicated
op code.

All scalars are encoded as a 32-byte big-endian integer. All scalar values are
required to be less than the `secp256k1` curve order.

The existing sig op cost model introduced by BIP 342 is maintained. Each
introduced op code is assigned a cost designed to ensure that it's more
expensive to re-create common operations (such as signature verification) using
these op codes, than via the dedicated `OP_CEHCKSIG` op code


# Specification

Depictions of the stack below are always represented from to to bottom. Given
a stack of `[x] [y]`, the first element to be popped off is `[x]`.

## `OP_SUCESS` Assignment

The following existing `OP_SUCESS` reserved op codes are re-allocated to create
our new elliptic curve op codes: 
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
1. If at least two elements aren't on the stack, then execution MUST fail.
2. Pop the top two stack elements.
3. Validate both point elements as valid elliptic curve points.
4. Compute the elliptic curve point addition: `result = point1 + point2`.
5. If either validation fails, script execution MUST fail immediately.
6. If the result is the point at infinity:
   - Push an empty vector (0 bytes) onto the stack.
7. Otherwise:
   - Encode the result in 33-byte compressed format.
   - Push the encoded result onto the stack.

## `OP_EC_POINT_MUL`

**Stack Input**: `[scalar] [point]`

**Stack Output**: `[scalar * point]`

Pops a scalar value and an elliptic curve point from the stack, computes scalar
multiplication, and pushes the result in 33-byte compressed format.

### Execution Rules
1. If at least two elements aren't on the stack, then execution MUST fail.
2. Pop the top two stack elements.
3. Validate the point as a valid elliptic curve point.
4. Validate the scalar as a valid scalar value.
5. If either validation fails, script execution MUST fail immediately.
6. Special case: If point is an empty vector (0 bytes):
   - Interpret as the secp256k1 generator point G.
   - This enables efficient computation of `scalar * G`.
7. Compute the scalar multiplication: `result = scalar * point`.
8. If the result is the point at infinity:
   - Push an empty vector (0 bytes) onto the stack.
9. Otherwise:
   - Encode the result in 33-byte compressed format.
   - Push the encoded result onto the stack.

## `OP_EC_POINT_NEGATE`

**Stack Input**: `[point]` (top element)

**Stack Output**: `[-point]`

Pops an elliptic curve point from the stack, computes its negation, and pushes
the result in 33-byte compressed format.

### Execution Rules
1. If at least a single item isn't on top of the stack, then execution MUST fail.
2. Pop the top stack element
3. Validate the point as a valid elliptic curve point
4. If validation fails, script execution MUST fail immediately
5. Special case: If point is an empty vector (0 bytes):
   - Push an empty vector back (negation of infinity is infinity)
6. Compute the point negation: `result = -point`
   - For point (x, y), the negation is (x, p - y)
7. Encode the result in 33-byte compressed format
8. Push the encoded result onto the stack

## `OP_EC_POINT_X_COORD`

**Stack Input**: `[point]` (top element)

**Stack Output**: `[x_coordinate]`

Pops an elliptic curve point from the stack and pushes its x-coordinate.

### Execution Rules
1. If at least a single item isn't on top of the stack, then execution MUST fail.
2. Pop the top stack element.
3. Validate the element as a valid elliptic curve point.
4. If validation fails, script execution MUST fail immediately.
5. Special case: If point is an empty vector (0 bytes):
   - Script execution MUST fail (cannot extract x-coordinate from infinity).
6. Extract the x-coordinate from the point.
7. Push the x-coordinate as a 32-byte big-endian value onto the stack.

## Resource Limits

As mentioned above, each op code will consume from the per-input sig op budget:
- `OP_EC_POINT_ADD`: Consumes 10 units from the sigops budget.
- `OP_EC_POINT_MUL`: Consumes 30 units from the sigops budget.
- `OP_EC_POINT_NEGATE`: Consumes 5 units from the sigops budget.
- `OP_EC_POINT_X_COORD`: Consumes 1 unit from the sigops budget.

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
`OP_CEHCKSIG`. This ensures that it requires more resources to use the op codes
for this purpose than normally.

This 52% premium provides strong economic incentive to use the optimized
OP_CHECKSIG for signature verification rather than reimplementing it manually.

## Why Are Only 33-byte Points Accepted?

Accepting only 33-byte points simplified usage of these op codes. Otherwise,
chained operations may require the tracking/offset of the parity bit.
Additionally since the advent of 32-byte public keys for Taproot, many
developer hours have been spent tracking down bugs related to the information
lost of converting from 33 byte to 32 byte public keys.

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
by scalar multiplication by `(n-1) mod p`, however this BIP doesn't defined
scalar operations. 

In addition, the BIP 340 schnorr verification can only be computed by negating
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

# Changelog

# Copyright
