# TODO: remove this file, and use trusted dealer BIP's reference code instead, after it gets published.

# Implementation of the Trusted Dealer Key Generation approach for FROST mentioned
# in https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/ (Appendix D).
#
# It's worth noting that this isn't the only compatible method (with BIP FROST Signing),
# there are alternative key generation methods available, such as BIP-FROST-DKG:
# https://github.com/BlockstreamResearch/bip-frost-dkg

from typing import Tuple, List
import unittest
import secrets

from secp256k1lab.secp256k1 import G, GE, Scalar
from frost_ref.signing import derive_interpolating_value
from frost_ref import PlainPk


# evaluates poly using Horner's method, assuming coeff[0] corresponds
# to the coefficient of highest degree term
def polynomial_evaluate(coeffs: List[Scalar], x: Scalar) -> Scalar:
    res = Scalar(0)
    for coeff in coeffs:
        res = res * x + coeff
    return res


def secret_share_combine(shares: List[Scalar], ids: List[int]) -> Scalar:
    assert len(shares) == len(ids)
    secret = Scalar(0)
    for share, my_id in zip(shares, ids):
        lam = derive_interpolating_value(ids, my_id)
        secret += share * lam
    return secret


def secret_share_shard(secret: Scalar, coeffs: List[Scalar], n: int) -> List[Scalar]:
    coeffs = coeffs + [secret]

    secshares = []
    # ids are 0-indexed (0..n-1), but polynomial is evaluated at x = id + 1
    # because p(0) = secret
    for i in range(n):
        x_i = Scalar(i + 1)
        y_i = polynomial_evaluate(coeffs, x_i)
        assert y_i != 0
        secshares.append(y_i)
    return secshares


def trusted_dealer_keygen(
    thresh_sk_: bytes, n: int, t: int
) -> Tuple[PlainPk, List[bytes], List[PlainPk]]:
    assert 2 <= t <= n

    thresh_sk = Scalar.from_bytes_nonzero_checked(thresh_sk_)
    # Key generation protocols are allowed to generate plain public keys (i.e., non-xonly)
    thresh_pk_ = thresh_sk * G
    assert not thresh_pk_.infinity
    thresh_pk = PlainPk(thresh_pk_.to_bytes_compressed())

    coeffs = []
    for _ in range(t - 1):
        coeffs.append(Scalar.from_bytes_nonzero_checked(secrets.token_bytes(32)))

    secshares_ = secret_share_shard(thresh_sk, coeffs, n)
    secshares = [x.to_bytes() for x in secshares_]

    pubshares_ = [x * G for x in secshares_]
    pubshares = [PlainPk(X.to_bytes_compressed()) for X in pubshares_]

    return (thresh_pk, secshares, pubshares)


# Test vector from RFC draft.
# section F.5 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/
class Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.n = 3
        self.t = 2
        self.poly = [
            Scalar(0xFBF85EADAE3058EA14F19148BB72B45E4399C0B16028ACAF0395C9B03C823579),
            Scalar(0x0D004150D27C3BF2A42F312683D35FAC7394B1E9E318249C1BFE7F0795A83114),
        ]
        # id[i] = i + 1, where i is the index in this list
        self.secshares = [
            Scalar(0x08F89FFE80AC94DCB920C26F3F46140BFC7F95B493F8310F5FC1EA2B01F4254C),
            Scalar(0x04F0FEAC2EDCEDC6CE1253B7FAB8C86B856A797F44D83D82A385554E6E401984),
            Scalar(0x00E95D59DD0D46B0E303E500B62B7CCB0E555D49F5B849F5E748C071DA8C0DBC),
        ]
        self.secret = 0x0D004150D27C3BF2A42F312683D35FAC7394B1E9E318249C1BFE7F0795A83114

    def test_polynomial_evaluate(self) -> None:
        coeffs = self.poly.copy()
        expected_secret = self.secret

        self.assertEqual(int(polynomial_evaluate(coeffs, Scalar(0))), expected_secret)

    def test_secret_share_combine(self) -> None:
        secshares = self.secshares.copy()
        expected_secret = self.secret

        # ids 0 and 1
        self.assertEqual(
            secret_share_combine([secshares[0], secshares[1]], [0, 1]), expected_secret
        )
        # ids 1 and 2
        self.assertEqual(
            secret_share_combine([secshares[1], secshares[2]], [1, 2]), expected_secret
        )
        # ids 0 and 2
        self.assertEqual(
            secret_share_combine([secshares[0], secshares[2]], [0, 2]), expected_secret
        )
        # all ids
        self.assertEqual(secret_share_combine(secshares, [0, 1, 2]), expected_secret)

    def test_trusted_dealer_keygen(self) -> None:
        thresh_sk_ = secrets.token_bytes(32)
        n = 5
        t = 3
        thresh_pk_, secshares_, pubshares_ = trusted_dealer_keygen(thresh_sk_, n, t)

        thresh_sk = Scalar.from_bytes_nonzero_checked(thresh_sk_)
        thresh_pk = GE.from_bytes_compressed(thresh_pk_)
        secshares = [Scalar.from_bytes_nonzero_checked(s) for s in secshares_]
        pubshares = [GE.from_bytes_compressed(p) for p in pubshares_]

        self.assertEqual(thresh_pk, thresh_sk * G)

        self.assertEqual(secret_share_combine(secshares, list(range(n))), thresh_sk)
        self.assertEqual(len(secshares), n)
        self.assertEqual(len(pubshares), n)
        for i in range(len(pubshares)):
            with self.subTest(i=i):
                self.assertEqual(pubshares[i], secshares[i] * G)


if __name__ == "__main__":
    unittest.main()
