import hashlib
import binascii

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Points are tuples of X and Y coordinates and the point at infinity is
# represented by the None keyword.
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def tagged_hash(tag, msg):
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def is_infinity(P):
    return P is None

def x(P):
    return P[0]

def y(P):
    return P[1]

def point_add(P1, P2):
    if (P1 is None):
        return P2
    if (P2 is None):
        return P1
    if (x(P1) == x(P2) and y(P1) != y(P2)):
        return None
    if (P1 == P2):
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P, n):
    R = None
    for i in range(256):
        if ((n >> i) & 1):
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x):
    return x.to_bytes(32, byteorder="big")

def bytes_from_point(P):
    return bytes_from_int(x(P))

def xor_bytes(b0, b1):
    return bytes(x ^ y for (x, y) in zip(b0, b1))

def lift_x_square_y(b):
    x = int_from_bytes(b)
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return [x, y]

def lift_x_even_y(b):
    P = lift_x_square_y(b)
    if P is None:
        return None
    else:
        return [x(P), y(P) if y(P) % 2 == 0 else p - y(P)]

def int_from_bytes(b):
    return int.from_bytes(b, byteorder="big")

def hash_sha256(b):
    return hashlib.sha256(b).digest()

def is_square(x):
    return pow(x, (p - 1) // 2, p) == 1

def has_square_y(P):
    return not is_infinity(P) and is_square(y(P))

def has_even_y(P):
    return y(P) % 2 == 0

def pubkey_gen(seckey):
    x = int_from_bytes(seckey)
    if not (1 <= x <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, x)
    return bytes_from_point(P)

def schnorr_sign(msg, seckey0, aux_rand):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    seckey0 = int_from_bytes(seckey0)
    if not (1 <= seckey0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    P = point_mul(G, seckey0)
    seckey = seckey0 if has_even_y(P) else n - seckey0
    t = xor_bytes(bytes_from_int(seckey), tagged_hash("BIP340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP340/nonce", t + bytes_from_point(P) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    k = n - k0 if not has_square_y(R) else k0
    e = int_from_bytes(tagged_hash("BIP340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * seckey) % n)
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError('The signature does not pass verification.')
    return sig

def schnorr_verify(msg, pubkey, sig):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x_even_y(pubkey)
    if (P is None):
        return False
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (r >= p or s >= n):
        return False
    e = int_from_bytes(tagged_hash("BIP340/challenge", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if R is None or not has_square_y(R) or x(R) != r:
        return False
    return True

#
# The following code is only used to verify the test vectors.
#
import csv

def test_vectors():
    all_passed = True
    with open('test-vectors.csv', newline='') as csvfile:
        reader = csv.reader(csvfile)
        reader.__next__()
        for row in reader:
            (index, seckey, pubkey, aux_rand, msg, sig, result, comment) = row
            pubkey = bytes.fromhex(pubkey)
            msg = bytes.fromhex(msg)
            sig = bytes.fromhex(sig)
            result = result == 'TRUE'
            print('\nTest vector #%-3i: ' % int(index))
            if seckey != '':
                seckey = bytes.fromhex(seckey)
                pubkey_actual = pubkey_gen(seckey)
                if pubkey != pubkey_actual:
                    print(' * Failed key generation.')
                    print('   Expected key:', pubkey.hex().upper())
                    print('     Actual key:', pubkey_actual.hex().upper())
                aux_rand = bytes.fromhex(aux_rand)
                sig_actual = schnorr_sign(msg, seckey, aux_rand)
                if sig == sig_actual:
                    print(' * Passed signing test.')
                else:
                    print(' * Failed signing test.')
                    print('   Expected signature:', sig.hex().upper())
                    print('     Actual signature:', sig_actual.hex().upper())
                    all_passed = False
            result_actual = schnorr_verify(msg, pubkey, sig)
            if result == result_actual:
                print(' * Passed verification test.')
            else:
                print(' * Failed verification test.')
                print('   Expected verification result:', result)
                print('     Actual verification result:', result_actual)
                if comment:
                    print('   Comment:', comment)
                all_passed = False
    print()
    if all_passed:
        print('All test vectors passed.')
    else:
        print('Some test vectors failed.')
    return all_passed

if __name__ == '__main__':
    test_vectors()
