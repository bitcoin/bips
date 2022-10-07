import sys
import random
import hashlib
import hmac

### BIP-340 tagged hash

def TaggedHash(tag, data):
    """Compute BIP-340 tagged hash with specified tag string of data."""
    ss = hashlib.sha256(tag.encode('utf-8')).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()

### HKDF-SHA256

def hmac_sha256(key, data):
    """Compute HMAC-SHA256 from specified byte arrays key and data."""
    return hmac.new(key, data, hashlib.sha256).digest()

def hkdf_sha256(length, ikm, salt, info):
    """Derive a key using HKDF-SHA256."""
    if len(salt) == 0:
        salt = bytes([0] * 32)
    prk = hmac_sha256(salt, ikm)
    t = b""
    okm = b""
    for i in range((length + 32 - 1) // 32):
        t = hmac_sha256(prk, t + info + bytes([i + 1]))
        okm += t
    return okm[:length]

### secp256k1 field/group elements

def modinv(a, n):
    """Compute the modular inverse of a modulo n using the extended Euclidean
    Algorithm. See https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers.
    """
    a = a % n
    if a == 0:
        return 0
    if sys.hexversion >= 0x3080000:
        # More efficient version available in Python 3.8.
        return pow(a, -1, n)
    t1, t2 = 0, 1
    r1, r2 = n, a
    while r2 != 0:
        q = r1 // r2
        t1, t2 = t2, t1 - q * t2
        r1, r2 = r2, r1 - q * r2
    if r1 > 1:
        return None
    if t1 < 0:
        t1 += n
    return t1

class FE:
    """Objects of this class represent elements of the field GF(2**256 - 2**32 - 977).

    They are represented internally in numerator / denominator form, in order to delay inversions.
    """

    SIZE = 2**256 - 2**32 - 977

    def __init__(self, a=0, b=1):
        """Initialize an FE as a/b; both a and b can be ints or field elements."""
        if isinstance(b, FE):
            if isinstance(a, FE):
                self.num = (a.num * b.den) % FE.SIZE
                self.den = (a.den * b.num) % FE.SIZE
            else:
                self.num = (a * b.den) % FE.SIZE
                self.den = a.num
        else:
            b = b % FE.SIZE
            assert b != 0
            if isinstance(a, FE):
                self.num = a.num
                self.den = (a.den * b) % FE.SIZE
            else:
                self.num = a % FE.SIZE
                self.den = b

    def __add__(self, a):
        """Compute the sum of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self.num * a.den + self.den * a.num, self.den * a.den)
        else:
            return FE(self.num + self.den * a, self.den)

    def __radd__(self, a):
        """Compute the sum of an integer and a field element."""
        return FE(self.num + self.den * a, self.den)

    def __sub__(self, a):
        """Compute the difference of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self.num * a.den - self.den * a.num, self.den * a.den)
        else:
            return FE(self.num - self.den * a, self.den)

    def __rsub__(self, a):
        """Compute the difference between an integer and a field element."""
        return FE(self.den * a - self.num, self.den)

    def __mul__(self, a):
        """Compute the product of two field elements (second may be int)."""
        if isinstance(a, FE):
            return FE(self.num * a.num, self.den * a.den)
        else:
            return FE(self.num * a, self.den)

    def __rmul__(self, a):
        """Compute the product of an integer with a field element."""
        return FE(self.num * a, self.den)

    def __truediv__(self, a):
        """Compute the ratio of two field elements (second may be int)."""
        return FE(self, a)

    def __rtruediv__(self, a):
        """Compute the ratio of an integer and a field element."""
        return FE(a, self)

    def __pow__(self, a):
        """Raise a field element to a (positive) integer power."""
        return FE(pow(self.num, a, FE.SIZE), pow(self.den, a, FE.SIZE))

    def __neg__(self):
        """Negate a field element."""
        return FE(-self.num, self.den)

    def __int__(self):
        """Convert a field element to an integer. The result is cached."""
        if self.den != 1:
            self.num = (self.num * modinv(self.den, FE.SIZE)) % FE.SIZE
            self.den = 1
        return self.num

    def sqrt(self):
        """Compute the square root of a field element.

        Due to the fact that our modulus is of the form (p % 4) == 3, the Tonelli-Shanks
        algorithm (https://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm) is simply
        raising the argument to the power (p + 3) / 4."""
        v = int(self)
        s = pow(v, (FE.SIZE + 1) // 4, FE.SIZE)
        if s**2 % FE.SIZE == v:
            return FE(s)
        return None

    def is_square(self):
        """Determine if this field element has a square root."""
        # Compute the Jacobi symbol of (self / p). Since our modulus is prime, this
        # is the same as the Legendre symbol, which determines quadratic residuosity.
        # See https://en.wikipedia.org/wiki/Jacobi_symbol for the algorithm.
        n, k, t = (self.num * self.den) % FE.SIZE, FE.SIZE, 0
        if n == 0:
            return True
        while n != 0:
            while n & 1 == 0:
                n >>= 1
                r = k & 7
                t ^= (r == 3 or r == 5)
            n, k = k, n
            t ^= (n & k & 3 == 3)
            n = n % k
        assert k == 1
        return not t

    def __eq__(self, a):
        """Check whether two field elements are equal (second may be an int)."""
        if isinstance(a, FE):
            return (self.num * a.den - self.den * a.num) % FE.SIZE == 0
        else:
            return (self.num - self.den * a) % FE.SIZE == 0

    def to_bytes(self):
        """Convert a field element to 32-byte big endian encoding."""
        return int(self).to_bytes(32, 'big')

    @staticmethod
    def from_bytes(b):
        """Convert a 32-byte big endian encoding of a field element to an FE."""
        v = int.from_bytes(b, 'big')
        if v >= FE.SIZE:
            return None
        return FE(v)

class GE:
    """Objects of this class represent points (group elements) on the secp256k1 curve.

    The point at infinity is represented as None."""

    ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    ORDER_HALF = ORDER // 2

    def __init__(self, x, y):
        """Initialize a group element with specified x and y coordinates (must be on curve)."""
        fx = FE(x)
        fy = FE(y)
        assert fy**2 == fx**3 + 7
        self.x = fx
        self.y = fy

    def double(self):
        """Compute the double of a point."""
        l = 3 * self.x**2 / (2 * self.y)
        x3 = l**2 - 2 * self.x
        y3 = l * (self.x - x3) - self.y
        return GE(x3, y3)

    def __add__(self, a):
        """Add two points, or a point and infinity, together."""
        if a is None:
            # Adding point at infinity
            return self
        if self.x != a.x:
            # Adding distinct x coordinates
            l = (a.y - self.y) / (a.x - self.x)
            x3 = l**2 - self.x - a.x
            y3 = l * (self.x - x3) - self.y
            return GE(x3, y3)
        elif self.y == a.y:
            # Adding point to itself
            return self.double()
        else:
            # Adding point to its negation
            return None

    def __radd__(self, a):
        """Add infinity to a point."""
        assert a is None
        return self

    def __mul__(self, a):
        """Multiply a point with an integer (scalar multiplication)."""
        r = None
        for i in range(a.bit_length() - 1, -1, -1):
            if r is not None:
                r = r.double()
            if (a >> i) & 1:
                r += self
        return r

    def __rmul__(self, a):
        """Multiply an integer with a point (scalar multiplication)."""
        return self * a

    @staticmethod
    def lift_x(x):
        """Take an FE, and return the point with that as X coordinate, and square Y."""
        y = (FE(x)**3 + 7).sqrt()
        if y is None:
            return None
        return GE(x, y)

    @staticmethod
    def is_valid_x(x):
        """Determine whether the provided field element is a valid X coordinate."""
        return (FE(x)**3 + 7).is_square()

SECP256K1_G = GE(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

### ElligatorSwift

# Precomputed constant square root of -3 modulo p.
MINUS_3_SQRT = FE(-3).sqrt()

def xswiftec(u, t):
    """Decode field elements (u, t) to an X coordinate on the curve."""
    if u == 0:
        u = FE(1)
    if t == 0:
        t = FE(1)
    if u**3 + t**2 + 7 == 0:
        t = 2 * t
    X = (u**3 + 7 - t**2) / (2 * t)
    Y = (X + t) / (MINUS_3_SQRT * u)
    for x in (u + 4 * Y**2, (-X / Y - u) / 2, (X / Y - u) / 2):
        if GE.is_valid_x(x):
            return x
    assert False

def xswiftec_inv(x, u, case):
    """Given x and u, find t such that xswiftec(u, t) = x, or return None.

    Case selects which of the up to 8 results to return."""

    if case & 2 == 0:
        if GE.is_valid_x(-x - u):
            return None
        v = x if case & 1 == 0 else -x - u
        s = -(u**3 + 7) / (u**2 + u*v + v**2)
    else:
        s = x - u
        if s == 0:
            return None
        r = (-s * (4 * (u**3 + 7) + 3 * s * u**2)).sqrt()
        if r is None:
            return None
        if case & 1:
            if r == 0:
                return None
            r = -r
        v = (-u + r / s) / 2
    w = s.sqrt()
    if w is None:
        return None
    if case & 4:
        w = -w
    return w * (u * (MINUS_3_SQRT - 1) / 2 - v)

def xelligatorswift(x):
    """Given a field element X on the curve, find (u, t) that encode them."""
    while True:
        u = FE(random.randrange(1, GE.ORDER))
        case = random.randrange(0, 8)
        t = xswiftec_inv(x, u, case)
        if t is not None:
            return u, t

def ellswift_create():
    """Generate a (privkey, ellswift_pubkey) pair."""
    priv = random.randrange(1, GE.ORDER)
    u, t = xelligatorswift((priv * SECP256K1_G).x)
    return priv.to_bytes(32, 'big'), u.to_bytes() + t.to_bytes()

def ellswift_ecdh_xonly(pubkey_theirs, privkey):
    """Compute X coordinate of shared ECDH point between elswift pubkey and privkey."""
    u = FE(int.from_bytes(pubkey_theirs[:32], 'big'))
    t = FE(int.from_bytes(pubkey_theirs[32:], 'big'))
    d = int.from_bytes(privkey, 'big')
    return (d * GE.lift_x(xswiftec(u, t))).x.to_bytes()

### Poly1305

class Poly1305:
    """Class representing a running poly1305 computation."""
    MODULUS = 2**130 - 5

    def __init__(self, key):
        self.r = int.from_bytes(key[:16], 'little') & 0xffffffc0ffffffc0ffffffc0fffffff
        self.s = int.from_bytes(key[16:], 'little')
        self.acc = 0

    def add(self, msg, length=None, pad=False):
        """Add a message of any length. Input so far must be a multiple of 16 bytes."""
        length = len(msg) if length is None else length
        for i in range((length + 15) // 16):
            chunk = msg[i * 16:i * 16 + min(16, length - i * 16)]
            val = int.from_bytes(chunk, 'little') + 256**(16 if pad else len(chunk))
            self.acc = (self.r * (self.acc + val)) % Poly1305.MODULUS
        return self

    def tag(self):
        """Compute the poly1305 tag."""
        return ((self.acc + self.s) & 0xffffffffffffffffffffffffffffffff).to_bytes(16, 'little')

### ChaCha20

CHACHA20_INDICES = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)
)

CHACHA20_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

def rotl32(v, bits):
    """Rotate the 32-bit value v left by bits bits."""
    return ((v << bits) & 0xffffffff) | (v >> (32 - bits))

def chacha20_doubleround(s):
    """Apply a ChaCha20 double round to 16-element state array s.

    See https://cr.yp.to/chacha/chacha-20080128.pdf and https://tools.ietf.org/html/rfc8439
    """
    for a, b, c, d in CHACHA20_INDICES:
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 7)

def chacha20_block(key, nonce, cnt):
    """Compute the 64-byte output of the ChaCha20 block function.

    Takes as input a 32-byte key, 12-byte nonce, and 32-bit integer counter.
    """
    # Initial state.
    init = [0 for _ in range(16)]
    for i in range(4):
        init[i] = CHACHA20_CONSTANTS[i]
    for i in range(8):
        init[4 + i] = int.from_bytes(key[4 * i:4 * (i+1)], 'little')
    init[12] = cnt
    for i in range(3):
        init[13 + i] = int.from_bytes(nonce[4 * i:4 * (i+1)], 'little')
    # Perform 20 rounds.
    state = [v for v in init]
    for _ in range(10):
        chacha20_doubleround(state)
    # Add initial values back into state.
    for i in range(16):
        state[i] = (state[i] + init[i]) & 0xffffffff
    # Produce byte output
    return b''.join(state[i].to_bytes(4, 'little') for i in range(16))

### ChaCha20Poly1305

def aead_chacha20_poly1305_encrypt(key, nonce, aad, plaintext):
    """Encrypt a plaintext using ChaCha20Poly1305."""
    ret = bytearray()
    msg_len = len(plaintext)
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(plaintext[j + 64 * i] ^ keystream[j])
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    poly1305.add(aad, pad=True).add(ret, pad=True)
    poly1305.add(len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little'))
    ret += poly1305.tag()
    return bytes(ret)

def aead_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext):
    """Decrypt a ChaCha20Poly1305 ciphertext."""
    if len(ciphertext) < 16:
        return None
    msg_len = len(ciphertext) - 16
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    poly1305.add(aad, pad=True)
    poly1305.add(ciphertext, length=msg_len, pad=True)
    poly1305.add(len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little'))
    if ciphertext[-16:] != poly1305.tag():
        return None
    ret = bytearray()
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(ciphertext[j + 64 * i] ^ keystream[j])
    return bytes(ret)

### FSChaCha20{,Poly1305}

REKEY_INTERVAL = 224 # packets

class FSChaCha20Poly1305:
    """Rekeying wrapper AEAD around ChaCha20Poly1305."""

    def __init__(self, initial_key):
        self.key = initial_key
        self.packet_counter = 0

    def crypt(self, aad, text, is_decrypt):
        nonce = ((self.packet_counter % REKEY_INTERVAL).to_bytes(4, 'little') +
                 (self.packet_counter // REKEY_INTERVAL).to_bytes(8, 'little'))
        if is_decrypt:
            ret = aead_chacha20_poly1305_decrypt(self.key, nonce, aad, text)
        else:
            ret = aead_chacha20_poly1305_encrypt(self.key, nonce, aad, text)
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0:
            rekey_nonce = b"\xFF\xFF\xFF\xFF" + nonce[4:]
            newkey1 = aead_chacha20_poly1305_encrypt(self.key, rekey_nonce, b"", b"\x00" * 32)[:32]
            newkey2 = chacha20_block(self.key, rekey_nonce, 1)[:32]
            assert newkey1 == newkey2
            self.key = newkey1
        self.packet_counter += 1
        return ret

    def decrypt(self, aad, ciphertext):
        return self.crypt(aad, ciphertext, True)

    def encrypt(self, aad, plaintext):
        return self.crypt(aad, plaintext, False)


class FSChaCha20:
    """Rekeying wrapper stream cipher around ChaCha20."""

    def __init__(self, initial_key):
        self.key = initial_key
        self.block_counter = 0
        self.chunk_counter = 0
        self.keystream = b''

    def get_keystream_bytes(self, nbytes):
        while len(self.keystream) < nbytes:
            nonce = ((0).to_bytes(4, 'little') +
                     (self.chunk_counter // REKEY_INTERVAL).to_bytes(8, 'little'))
            self.keystream += chacha20_block(self.key, nonce, self.block_counter)
            self.block_counter += 1
        ret = self.keystream[:nbytes]
        self.keystream = self.keystream[nbytes:]
        return ret

    def crypt(self, chunk):
        ks = self.get_keystream_bytes(len(chunk))
        ret = bytes([ks[i] ^ chunk[i] for i in range(len(chunk))])
        if ((self.chunk_counter + 1) % REKEY_INTERVAL) == 0:
            self.key = self.get_keystream_bytes(32)
            self.block_counter = 0
        self.chunk_counter += 1
        return ret

### Shared secret computation

def v2_ecdh(priv, ellswift_theirs, ellswift_ours, initiating):
    """Compute BIP324 shared secret."""

    ecdh_point_x32 = ellswift_ecdh_xonly(ellswift_theirs, priv)
    if initiating:
        # Initiating, place our public key encoding first.
        return TaggedHash("bip324_ellswift_xonly_ecdh",
            ellswift_ours + ellswift_theirs + ecdh_point_x32)
    else:
        # Responding, place their public key encoding first.
        return TaggedHash("bip324_ellswift_xonly_ecdh",
            ellswift_theirs + ellswift_ours + ecdh_point_x32)

### Key derivation

NETWORK_MAGIC = b'\xf9\xbe\xb4\xd9'

def initialize_v2_transport(ecdh_secret, initiating):
    """Return a peer object with various BIP324 derived keys and ciphers."""

    peer = {}
    salt = b'bitcoin_v2_shared_secret' + NETWORK_MAGIC
    for name, length in (
        ('initiator_L', 32), ('initiator_P', 32), ('responder_L', 32), ('responder_P', 32),
        ('garbage_terminators', 32), ('session_id', 32)):
        peer[name] = hkdf_sha256(
            salt=salt, ikm=ecdh_secret, info=name.encode('utf-8'), length=length)
    peer['initiator_garbage_terminator'] = peer['garbage_terminators'][:16]
    peer['responder_garbage_terminator'] = peer['garbage_terminators'][16:]
    del peer['garbage_terminators']
    if initiating:
        peer['send_L'] = FSChaCha20(peer['initiator_L'])
        peer['send_P'] = FSChaCha20Poly1305(peer['initiator_P'])
        peer['send_garbage_terminator'] = peer['initiator_garbage_terminator']
        peer['recv_L'] = FSChaCha20(peer['responder_L'])
        peer['recv_P'] = FSChaCha20Poly1305(peer['responder_P'])
        peer['recv_garbage_terminator'] = peer['responder_garbage_terminator']
    else:
        peer['send_L'] = FSChaCha20(peer['responder_L'])
        peer['send_P'] = FSChaCha20Poly1305(peer['responder_P'])
        peer['send_garbage_terminator'] = peer['responder_garbage_terminator']
        peer['recv_L'] = FSChaCha20(peer['initiator_L'])
        peer['recv_P'] = FSChaCha20Poly1305(peer['initiator_P'])
        peer['recv_garbage_terminator'] = peer['initiator_garbage_terminator']

    return peer

### Packet encryption

LENGTH_FIELD_LEN = 3
HEADER_LEN = 1
IGNORE_BIT_POS = 7

def v2_enc_packet(peer, contents, aad=b'', ignore=False):
    """Encrypt a BIP324 packet."""

    assert len(contents) <= 2**24 - 1
    header = (ignore << IGNORE_BIT_POS).to_bytes(HEADER_LEN, 'little')
    plaintext = header + contents
    aead_ciphertext = peer['send_P'].encrypt(aad, plaintext)
    enc_plaintext_len = peer['send_L'].crypt(len(contents).to_bytes(LENGTH_FIELD_LEN, 'little'))
    return enc_plaintext_len + aead_ciphertext
