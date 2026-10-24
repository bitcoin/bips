from typing import Tuple, Optional
import hashlib
import hmac

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
half_order = (n - 1) // 2

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

# A signature is the integer pair (r, s)
Signature = Tuple[int, int]

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, byteorder="big")

def bytes_le(l: int, x: int) -> bytes:
    return x.to_bytes(l, byteorder="little")

def fill_bytes(l: int, x: int) -> bytes:
    return bytes([x]) * l

def pubkey_gen(seckey: bytes) -> Point:
    if len(seckey) != 32:
        raise ValueError('The secret key must be a 32-byte array.')
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return P

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def nonce_rfc6979(seckey: bytes, msghash: bytes, extra: bytes, count: int) -> bytes:
    """
    There are two auxiliary inputs here which are both effectively counters, but
    serve different purposes.

    `extra`: in the event that a high-r signature is produced, we inject `extra` to produce
    a different nonce that may produce a low-r signature. It is the grind counter's
    encoding, see `grind_extra`.

    `count`: in the event that the nonce is either invalid *OR* produces an invalid signature
    (both are cryptographically unreachable events), `sign` increments `count` to produce a
    different nonce which may (will almost certainly) be valid and produce a valid signature.

    `K` and `V` are the internal state variables of the RFC 6979 generator and carry its
    names. Both are 32-byte arrays rather than curve points, and `K` is unrelated to the
    nonce `k`.
    """
    if len(seckey) != 32:
        raise ValueError('The secret key must be a 32-byte array.')
    if len(msghash) != 32:
        raise ValueError('The message hash must be a 32-byte array.')

    # RFC 6979 section 3.2d feeds bits2octets(h1), i.e. the message hash reduced
    # modulo n, not the raw hash. libsecp256k1 does the same (`msgmod32` in
    # `nonce_function_rfc6979`). The two differ only when int(msghash) >= n.
    h = bytes_from_int(int_from_bytes(msghash) % n)

    V = fill_bytes(32, 0x01)
    K = fill_bytes(32, 0x00)

    K = hmac_sha256(K, V + b'\x00' + seckey + h + extra)
    V = hmac_sha256(K, V)
    K = hmac_sha256(K, V + b'\x01' + seckey + h + extra)
    V = hmac_sha256(K, V)

    V = hmac_sha256(K, V)

    for _ in range(count):
        K = hmac_sha256(K, V + b'\x00')
        V = hmac_sha256(K, V)
        V = hmac_sha256(K, V)

    return V


def sign(seckey: bytes, msghash: bytes, extra: bytes) -> Signature:
    """See `nonce_rfc6979` for the difference between `extra` and `count`."""
    if len(seckey) != 32:
        raise ValueError('The secret key must be a 32-byte array.')
    if len(msghash) != 32:
        raise ValueError('The message hash must be a 32-byte array.')

    d = int_from_bytes(seckey)
    if not (1 <= d <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')

    for count in range(2**32):
        nonce = nonce_rfc6979(seckey, msghash, extra, count)
        k = int_from_bytes(nonce)
        if not (1 <= k <= n - 1):
            continue
        R = point_mul(G, k)
        assert R is not None
        r = x(R) % n
        if r == 0:
            continue
        s = (pow(k, -1, n) * (d * r + int_from_bytes(msghash))) % n
        if s == 0:
            continue
        return (r, s)
    raise RuntimeError('No valid signature found below the attempt counter limit.')

def verify(sig: Signature, pubkey: Optional[Point], msghash: bytes) -> bool:
    if len(msghash) != 32:
        raise ValueError('The message hash must be a 32-byte array.')

    if is_infinite(pubkey):
        return False
    assert pubkey is not None

    if x(pubkey) >= p or y(pubkey) >= p:
        return False

    if (y(pubkey) ** 2) % p != (x(pubkey) ** 3 + 7) % p:
        return False

    (r, s) = sig

    if r <= 0 or r >= n:
        return False

    if s <= 0 or s >= n:
        return False

    w = pow(s, -1, n)

    u1 = (w * int_from_bytes(msghash)) % n
    u2 = (w * r) % n
    R = point_add(point_mul(G, u1), point_mul(pubkey, u2))

    if is_infinite(R):
        return False
    assert R is not None

    if x(R) % n != r:
        return False

    return True

def grind_extra(i: int) -> bytes:
    """The additional data corresponding to the grind counter."""
    if not (0 <= i <= 2**32 - 1):
        raise ValueError('The grind counter must be an integer in the range 0..2^32-1.')
    return b'' if i == 0 else bytes_le(4, i) + fill_bytes(28, 0x00)

def is_low_r(sig: Signature) -> bool:
    """Can also be written as bytes_from_int(r)[0] < 0x80"""
    (r, _) = sig
    return r < 2**255

def normalize_low_s(sig: Signature) -> Signature:
    (r, s) = sig
    return (r, n - s) if s > half_order else (r, s)

def deterministic_sign(seckey: bytes, msghash: bytes) -> Signature:
    if len(seckey) != 32:
        raise ValueError('The secret key must be a 32-byte array.')
    if not (1 <= int_from_bytes(seckey) <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')

    (r, s) = sign(seckey, msghash, grind_extra(0))
    i = 1
    while r >= 2**255:
        if i >= 2**32:
            raise RuntimeError('No low-r signature found below the grind counter limit.')
        (r, s) = sign(seckey, msghash, grind_extra(i))
        i += 1

    (r, s) = normalize_low_s((r, s))

    P = pubkey_gen(seckey)
    if not verify((r, s), P, msghash):
        raise RuntimeError('The created signature is invalid.')
    return (r, s)
