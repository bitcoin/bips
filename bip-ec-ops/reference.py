#!/usr/bin/env python3
"""Reference implementation for BIP-EC-OPS: Elliptic Curve Operations for Bitcoin Script"""

from typing import Tuple, Optional

# secp256k1 parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Generator point
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

# Core elliptic curve operations
def is_infinite(P: Optional[Point]) -> bool:
    """Check if point is at infinity."""
    return P is None

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    """Add two elliptic curve points."""
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if P1[0] == P2[0]:
        if P1[1] != P2[1]:
            return None  # Point at infinity
        # Point doubling
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p
    else:
        # Point addition
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    x3 = (lam * lam - P1[0] - P2[0]) % p
    y3 = (lam * (P1[0] - x3) - P1[1]) % p
    return (x3, y3)

def point_mul(P: Optional[Point], k: int) -> Optional[Point]:
    """Multiply point by scalar."""
    if k == 0:
        return None
    R = None
    for i in range(256):
        if (k >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def point_negate(P: Optional[Point]) -> Optional[Point]:
    """Negate an elliptic curve point."""
    if P is None:
        return None
    return (P[0], (p - P[1]) % p)

# Encoding/decoding functions
def decode_compressed_point(data: bytes) -> Optional[Point]:
    """Decode a 33-byte compressed point."""
    if len(data) != 33:
        raise ValueError(f"Invalid compressed point length: {len(data)}")
    
    prefix = data[0]
    if prefix not in [0x02, 0x03]:
        raise ValueError(f"Invalid compression prefix: {prefix:02x}")
    
    x = int.from_bytes(data[1:33], byteorder='big')
    if x >= p:
        raise ValueError(f"X coordinate >= field prime")
    
    # Compute y from x
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    
    if pow(y, 2, p) != y_sq:
        raise ValueError(f"Invalid point: not on curve")
    
    # Choose correct y based on prefix
    if (y & 1) != (prefix & 1):
        y = p - y
    
    return (x, y)

def encode_compressed_point(P: Point) -> bytes:
    """Encode point as 33-byte compressed format."""
    prefix = 0x03 if P[1] & 1 else 0x02
    return bytes([prefix]) + P[0].to_bytes(32, byteorder='big')

def extract_x_coordinate(P: Point) -> bytes:
    """Extract x-coordinate as 32 bytes."""
    return P[0].to_bytes(32, byteorder='big')

# Bitcoin Script opcode implementations
def op_ec_point_add(stack: list) -> None:
    """
    OP_EC_POINT_ADD implementation
    Stack: [point2] [point1] -> [point1 + point2]
    """
    if len(stack) < 2:
        raise ValueError("OP_EC_POINT_ADD requires 2 stack elements")
    
    # Pop elements (top first)
    point2_bytes = stack.pop()
    point1_bytes = stack.pop()
    
    # Validate and decode points
    if len(point1_bytes) != 33:
        raise ValueError(f"Invalid point1 length: {len(point1_bytes)}")
    if len(point2_bytes) != 33:
        raise ValueError(f"Invalid point2 length: {len(point2_bytes)}")
    
    P1 = decode_compressed_point(point1_bytes)
    P2 = decode_compressed_point(point2_bytes)
    
    # Perform addition
    result = point_add(P1, P2)
    
    # Push result
    if result is None:
        stack.append(b'')  # Point at infinity
    else:
        stack.append(encode_compressed_point(result))

def op_ec_point_mul(stack: list) -> None:
    """
    OP_EC_POINT_MUL implementation
    Stack: [scalar] [point] -> [scalar * point]
    """
    if len(stack) < 2:
        raise ValueError("OP_EC_POINT_MUL requires 2 stack elements")
    
    # Pop elements (top first)
    scalar_bytes = stack.pop()
    point_bytes = stack.pop()
    
    # Validate scalar
    if len(scalar_bytes) != 32:
        raise ValueError(f"Invalid scalar length: {len(scalar_bytes)}")
    
    scalar = int.from_bytes(scalar_bytes, byteorder='big')
    if scalar >= n:
        raise ValueError(f"Scalar >= curve order")
    
    # Handle point
    if len(point_bytes) == 0:
        # Empty vector means generator point G
        point = G
    elif len(point_bytes) == 33:
        point = decode_compressed_point(point_bytes)
    else:
        raise ValueError(f"Invalid point length: {len(point_bytes)}")
    
    # Perform multiplication
    result = point_mul(point, scalar)
    
    # Push result
    if result is None:
        stack.append(b'')  # Point at infinity
    else:
        stack.append(encode_compressed_point(result))

def op_ec_point_negate(stack: list) -> None:
    """
    OP_EC_POINT_NEGATE implementation
    Stack: [point] -> [-point]
    """
    if len(stack) < 1:
        raise ValueError("OP_EC_POINT_NEGATE requires 1 stack element")
    
    # Pop element
    point_bytes = stack.pop()
    
    # Handle empty vector (infinity)
    if len(point_bytes) == 0:
        stack.append(b'')  # -infinity = infinity
        return
    
    # Validate and decode point
    if len(point_bytes) != 33:
        raise ValueError(f"Invalid point length: {len(point_bytes)}")
    
    point = decode_compressed_point(point_bytes)
    
    # Perform negation
    result = point_negate(point)
    
    # Push result
    if result is None:
        stack.append(b'')
    else:
        stack.append(encode_compressed_point(result))

def op_ec_point_x_coord(stack: list) -> None:
    """
    OP_EC_POINT_X_COORD implementation
    Stack: [point] -> [x_coordinate]
    """
    if len(stack) < 1:
        raise ValueError("OP_EC_POINT_X_COORD requires 1 stack element")
    
    # Pop element
    point_bytes = stack.pop()
    
    # Cannot extract x from infinity
    if len(point_bytes) == 0:
        raise ValueError("Cannot extract x-coordinate from point at infinity")
    
    # Validate and decode point
    if len(point_bytes) != 33:
        raise ValueError(f"Invalid point length: {len(point_bytes)}")
    
    point = decode_compressed_point(point_bytes)
    
    # Extract and push x-coordinate
    stack.append(extract_x_coordinate(point))

# Example: Computing a taproot tweak
def compute_taproot_tweak_example():
    """Example: Computing P + tweak*G using stack-based execution."""
    # Sample internal key (33-byte compressed)
    internal_key = bytes.fromhex("02" + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    
    # Sample tweak (32 bytes)
    tweak = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
    
    # Simulate script execution: <tweak> <empty_vector> OP_EC_POINT_MUL <P> OP_EC_POINT_ADD OP_EC_POINT_X_COORD
    stack = []
    
    # Push tweak and empty vector (for G)
    stack.append(b'')  # empty vector for G
    stack.append(tweak)
    
    # OP_EC_POINT_MUL: compute tweak*G
    op_ec_point_mul(stack)
    print(f"After OP_EC_POINT_MUL: stack has {len(stack)} element(s)")
    
    # Push internal key
    stack.append(internal_key)
    
    # OP_EC_POINT_ADD: compute P + tweak*G
    op_ec_point_add(stack)
    print(f"After OP_EC_POINT_ADD: stack has {len(stack)} element(s)")
    
    # OP_EC_POINT_X_COORD: extract x-coordinate for taproot
    op_ec_point_x_coord(stack)
    print(f"After OP_EC_POINT_X_COORD: stack has {len(stack)} element(s)")
    
    # Result is 32-byte x-coordinate on top of stack
    return stack[0]

# Test vectors
def run_test_vectors():
    """Run basic test vectors for all opcodes using stack-based execution."""
    
    print("Testing OP_EC_POINT_ADD...")
    # Test: Add G + G = 2*G
    G_compressed = encode_compressed_point(G)
    stack = [G_compressed, G_compressed]
    op_ec_point_add(stack)
    # Result should be 2*G
    expected = encode_compressed_point(point_mul(G, 2))
    assert stack[0] == expected, f"Expected {expected.hex()}, got {stack[0].hex()}"
    print("  ✓ Point addition test passed")
    
    print("\nTesting OP_EC_POINT_MUL...")
    # Test: Scalar multiplication with G
    stack = [
        b'',  # Empty vector for G
        bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
    ]
    op_ec_point_mul(stack)
    # Result should be 2*G
    expected = encode_compressed_point(point_mul(G, 2))
    assert stack[0] == expected
    print("  ✓ Scalar multiplication test passed")
    
    print("\nTesting OP_EC_POINT_NEGATE...")
    # Test: Point negation
    stack = [bytes.fromhex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")]
    op_ec_point_negate(stack)
    # Negated point should have opposite y parity
    assert stack[0][0] == 0x03  # Changed from 0x02 to 0x03
    print("  ✓ Point negation test passed")
    
    print("\nTesting OP_EC_POINT_X_COORD...")
    # Test: Extract x-coordinate
    stack = [bytes.fromhex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")]
    op_ec_point_x_coord(stack)
    expected = bytes.fromhex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
    assert stack[0] == expected
    print("  ✓ X-coordinate extraction test passed")
    
    print("\nTesting point at infinity...")
    # Test: Adding point to its negation gives infinity
    P = bytes.fromhex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
    stack = [P]
    op_ec_point_negate(stack)
    neg_P = stack[0]
    
    stack = [P, neg_P]
    op_ec_point_add(stack)
    assert stack[0] == b'', "P + (-P) should equal infinity"
    print("  ✓ Point at infinity test passed")
    
    print("\nTesting error conditions...")
    # Test: Insufficient stack elements
    try:
        stack = [bytes.fromhex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")]
        op_ec_point_add(stack)
        assert False, "Should have raised error for insufficient stack"
    except ValueError as e:
        assert "requires 2 stack elements" in str(e)
        print("  ✓ Stack underflow check passed")
    
    # Test: Invalid scalar length
    try:
        stack = [
            b'',  # G
            bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000")  # 31 bytes
        ]
        op_ec_point_mul(stack)
        assert False, "Should have raised error for invalid scalar"
    except ValueError as e:
        assert "Invalid scalar length" in str(e)
        print("  ✓ Invalid scalar length check passed")
    
    print("\n✅ All test vectors passed!")

if __name__ == "__main__":
    # Run test vectors
    run_test_vectors()
    
    # Example usage
    print("\n" + "="*50)
    print("Example: Computing taproot tweak")
    print("="*50)
    result = compute_taproot_tweak_example()
    print(f"Taproot output key (x-only): {result.hex()}")