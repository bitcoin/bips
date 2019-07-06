import hashlib
import binascii

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def point_add(P1, P2):
    if (P1 is None):
        return P2
    if (P2 is None):
        return P1
    if (P1[0] == P2[0] and P1[1] != P2[1]):
        return None
    if (P1 == P2):
        lam = (3 * P1[0] * P1[0] * pow(2 * P1[1], p - 2, p)) % p
    else:
        lam = ((P2[1] - P1[1]) * pow(P2[0] - P1[0], p - 2, p)) % p
    x3 = (lam * lam - P1[0] - P2[0]) % p
    return (x3, (lam * (P1[0] - x3) - P1[1]) % p)

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
    return (b'\x03' if P[1] & 1 else b'\x02') + bytes_from_int(P[0])

def point_from_bytes(b):
    if b[0:1] in [b'\x02', b'\x03']:
        odd = b[0] - 0x02
    else:
        return None
    x = int_from_bytes(b[1:33])
    y_sq = (pow(x, 3, p) + 7) % p
    y0 = pow(y_sq, (p + 1) // 4, p)
    if pow(y0, 2, p) != y_sq:
        return None
    y = p - y0 if y0 & 1 != odd else y0
    return [x, y]

def int_from_bytes(b):
    return int.from_bytes(b, byteorder="big")

def hash_sha256(b):
    return hashlib.sha256(b).digest()

def jacobi(x):
    return pow(x, (p - 1) // 2, p)

def schnorr_sign(msg, seckey):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if not (1 <= seckey <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    k0 = int_from_bytes(hash_sha256(bytes_from_int(seckey) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    k = n - k0 if (jacobi(R[1]) != 1) else k0
    e = int_from_bytes(hash_sha256(bytes_from_int(R[0]) + bytes_from_point(point_mul(G, seckey)) + msg)) % n
    return bytes_from_int(R[0]) + bytes_from_int((k + e * seckey) % n)

def schnorr_verify(msg, pubkey, sig):
    if len(msg) != 32:
        raise ValueError('The message must be a 32-byte array.')
    if len(pubkey) != 33:
        raise ValueError('The public key must be a 33-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = point_from_bytes(pubkey)
    if (P is None):
        return False
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (r >= p or s >= n):
        return False
    e = int_from_bytes(hash_sha256(sig[0:32] + bytes_from_point(P) + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if R is None or jacobi(R[1]) != 1 or R[0] != r:
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
            (index, seckey, pubkey, msg, sig, result, comment) = row
            pubkey = bytes.fromhex(pubkey)
            msg = bytes.fromhex(msg)
            sig = bytes.fromhex(sig)
            result = result == 'TRUE'
            print('\nTest vector #%-3i: ' % int(index))
            if seckey != '':
                seckey = int(seckey, 16)
                sig_actual = schnorr_sign(msg, seckey)
                if sig == sig_actual:
                    print(' * Passed signing test.')
                else:
                    print(' * Failed signing test.')
                    print('   Excepted signature:', sig.hex())
                    print('     Actual signature:', sig_actual.hex())
                    all_passed = False
            result_actual = schnorr_verify(msg, pubkey, sig)
            if result == result_actual:
                print(' * Passed verification test.')
            else:
                print(' * Failed verification test.')
                print('   Excepted verification result:', result)
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
