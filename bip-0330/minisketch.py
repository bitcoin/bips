#!/usr/bin/env python3

######## ENCODING and DECODING ########

FIELD_BITS = 32
FIELD_MODULUS = (1 << FIELD_BITS) + 0b10001101

def mul2(x):
    """Compute 2*x in GF(2^FIELD_BITS)"""
    return (x << 1) ^ (FIELD_MODULUS if x.bit_length() >= FIELD_BITS else 0)

def mul(x, y):
    """Compute x*y in GF(2^FIELD_BITS)"""
    ret = 0
    for bit in [(x >> i) & 1 for i in range(x.bit_length())]:
        ret ^= bit * y
        y = mul2(y)
    return ret

######## ENCODING only ########

def sketch(shortids, capacity):
    """Compute the bytes of a sketch for given shortids and given capacity."""
    odd_sums = [0 for _ in range(capacity)]
    for shortid in shortids:
        squared = mul(shortid, shortid)
        for i in range(capacity):
            odd_sums[i] ^= shortid
            shortid = mul(shortid, squared)
    return b''.join(elem.to_bytes(4, 'little') for elem in odd_sums)

######## DECODING only ########

import random

def inv(x):
    """Compute 1/x in GF(2^FIELD_BITS)"""
    t = x
    for i in range(FIELD_BITS - 2):
        t = mul(mul(t, t), x)
    return mul(t, t)


def berlekamp_massey(s):
    """Given a sequence of LFSR outputs, find the coefficients of the LFSR."""
    C, B, L, m, b = [1], [1], 0, 1, 1
    for n in range(len(s)):
        d = s[n]
        for i in range(1, L + 1):
            d ^= mul(C[i], s[n - i])
        if d == 0:
            m += 1
        else:
            T = list(C)
            while len(C) <= len(B) + m:
                C += [0]
            t = mul(d, inv(b))
            for i in range(len(B)):
                C[i + m] ^= mul(t, B[i])
            if 2 * L <= n:
                L, B, b, m = n + 1 - L, T, d, 1
            else:
                m += 1
    return C[0:L + 1]

def poly_monic(p):
    """Return the monic multiple of p, or 0 if the input is 0."""
    if len(p) == 0:
        return []
    i = inv(p[-1])
    return [mul(v, i) for v in p]

def poly_divmod(m, p):
    """Compute the polynomial quotient p/m, and replace p with p mod m."""
    assert(len(m) > 0 and m[-1] == 1)
    div = [0 for _ in range(len(p) - len(m) + 1)]
    while len(p) >= len(m):
        div[len(p) - len(m)] = p[-1]
        for i in range(len(m)):
            p[len(p) - len(m) + i] ^= mul(p[-1], m[i])
        assert(p[-1] == 0)
        p.pop()
    while (len(p) > 0 and p[-1] == 0):
        p.pop()
    return div

def poly_gcd(a, b):
    """Compute the GCD of a and b (destroys the inputs)."""
    if len(a) < len(b):
        a, b = b, a
    while len(b):
        if len(b) == 1:
            return [1]
        b = poly_monic(b)
        poly_divmod(b, a)
        a, b = b, a
    return a

def poly_sqr(p):
    """Compute the coefficients of the square of polynomial with coefficients p."""
    return [0 if i & 1 else mul(p[i // 2], p[i // 2]) for i in range(2 * len(p))]

def poly_trace(m, a):
    """Compute the coefficients of the trace polynomial of (a*x) mod m."""
    out = [0, a]
    for i in range(FIELD_BITS - 1):
        out = poly_sqr(out)
        while len(out) < 2:
            out += [0]
        out[1] = a
        poly_divmod(m, out)
    return out

def find_roots_inner(p, a):
    """Recursive helper function for find_roots (destroys p). a is randomizer."""
    # p must be monic
    assert(len(p) > 0 and p[-1] == 1)
    # Deal with degree 0 and degree 1 inputs
    if len(p) == 1:
        return []
    elif len(p) == 2:
        return [p[0]]
    # Otherwise, split p in left*right using paramater a_vals[0].
    t = poly_monic(poly_trace(p, a))
    left = poly_gcd(list(p), t)
    right = poly_divmod(list(left), p)
    # Invoke recursion with the remaining a_vals.
    ret_right = find_roots_inner(right, mul2(a))
    ret_left = find_roots_inner(left, mul2(a))
    # Concatenate roots
    return ret_left + ret_right

def find_roots(p):
    """Find the roots of polynomial with coefficients p."""
    # Compute x^(2^FIELD_BITS)+x mod p in a roundabout way.
    t = poly_trace(p, 1)
    t2 = poly_sqr(t)
    for i in range(len(t)):
        t2[i] ^= t[i]
    poly_divmod(p, t2)
    # If distinct from 0, p is not fully factorizable into non-repeating roots.
    if len(t2):
        return None
    # Invoke the recursive splitting algorithm
    return find_roots_inner(list(p), random.randrange(1, 2**32-1))

def decode(sketch):
    """Recover the shortids from a sketch."""
    odd_sums = [int.from_bytes(sketch[i*4:(i+1)*4], 'little') for i in range(len(sketch) // 4)]
    sums = []
    for i in range(len(odd_sums) * 2):
        if i & 1:
            sums.append(mul(sums[(i-1)//2], sums[(i-1)//2]))
        else:
            sums.append(odd_sums[(i+1)//2])
    return find_roots(list(reversed(berlekamp_massey(sums))))

