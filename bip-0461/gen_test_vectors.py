"""Generate the low-R grinding test vectors."""

import csv
import os
import sys
from reference import (
    bytes_from_int,
    G,
    deterministic_sign,
    grind_extra,
    is_low_r,
    n,
    normalize_low_s,
    p,
    point_add,
    point_mul,
    pubkey_gen,
    sign,
    verify,
)

FILENAME_SIGN_TEST = os.path.join(sys.path[0], 'sign_test_vectors.csv')
FILENAME_VERIFY_TEST = os.path.join(sys.path[0], 'verify_test_vectors.csv')

# (secret key, message hash, comment)
SIGN_CASES = [
    (0x12bef4612f311c38408e662304f22ef64792e80561b0a8adecd2074687e12bf1, 0xec888dbfce53624100e889809bce7d3cbe677b56a15968c5964d8d3690f57bff, "grinding stops at counter 7"),
    (0x4889e538d453c1b6834f66d70274c770e689210505c34fc5caad70fa29c8ad99, 2**256 - 1, "msghash%n=2^256-1-n"),
    (0x4889e538d453c1b6834f66d70274c770e689210505c34fc5caad70fa29c8ad99, n, "msghash%n=0"),
]

# Secret keys outside 1..n-1, for which signing must fail.
INVALID_SECKEY_CASES = [
    (0, "sk=0"),
    (n, "sk=n"),
    (p, "sk=p, which is above n"),
]

def pubkey_hex(P):
    """Serialize a public key in SEC 1 format: uncompressed, or the single byte 00
    for the point at infinity."""
    if P is None:
        return "00"
    return "04" + f"{P[0]:064x}" + f"{P[1]:064x}"

def sig_hex(sig):
    return (bytes_from_int(sig[0]) + bytes_from_int(sig[1])).hex()

def signed_cases():
    """Record the signature and grind counter of each case."""
    cases = []
    for sk, msg, comment in SIGN_CASES:
        seckey, msghash = bytes_from_int(sk), bytes_from_int(msg)
        for count in range(2**32):
            sig = sign(seckey, msghash, grind_extra(count))
            if is_low_r(sig):
                break
        # `sign` returns s unnormalized; normalization happens once after grinding
        sig = normalize_low_s(sig)
        assert deterministic_sign(seckey, msghash) == sig
        cases.append((sk, msg, comment, sig, count))
    return cases

def sign_vectors(cases):
    """Generate the valid and invalid signing vectors."""
    for sk, msg, comment, sig, _ in cases:
        assert is_low_r(sig)
        yield {
            "seckey": f"{sk:064x}",
            "msghash": f"{msg:064x}",
            "sig": sig_hex(sig),
            "comment": comment,
        }
    msg = cases[0][1]  # nonzero, so a missing key check can't loop forever on s = 0
    for sk, comment in INVALID_SECKEY_CASES:
        raised = False
        try:
            deterministic_sign(bytes_from_int(sk), bytes_from_int(msg))
        except ValueError:
            raised = True
        assert raised
        # An empty signature means signing must fail for this secret key.
        yield {
            "seckey": f"{sk:064x}",
            "msghash": f"{msg:064x}",
            "sig": "",
            "comment": comment,
        }

def verify_row(P, msg, sig, result, comment):
    assert verify(sig, P, bytes_from_int(msg)) is result
    return {
        "pubkey": pubkey_hex(P),
        "msghash": f"{msg:064x}",
        "sig": sig_hex(sig),
        "result": "TRUE" if result else "FALSE",
        "comment": comment,
    }

def verify_vectors(cases):
    """Generate the valid and invalid verification vectors."""
    for sk, msg, _, sig, _ in cases:
        yield verify_row(pubkey_gen(bytes_from_int(sk)), msg, sig, True, "")
    sk, msg = cases[0][:2]
    yield verify_row(pubkey_gen(bytes_from_int(sk)), msg, cases[1][3], False,
                     "signature made with a different key and message")

    sk, msg, _, sig, count = cases[0]
    P = pubkey_gen(bytes_from_int(sk))
    r, s = sig

    # This case required grinding for a low-r, so we can inject an earlier
    # counter to get a valid high-r signature, which should verify.
    assert count > 0
    high_r = normalize_low_s(sign(bytes_from_int(sk), bytes_from_int(msg), grind_extra(0)))
    assert not is_low_r(high_r)
    yield verify_row(P, msg, high_r, True,
                     "high-r signature: low-r is a signing policy, not a validity rule")

    # s outside 1..n-1, and r = s = 0.
    yield verify_row(P, msg, (r, 0), False, "s=0")
    yield verify_row(P, msg, (r, n), False, "s=n")
    yield verify_row(P, msg, (0, 0), False,
                     "r = s = 0; a verifier missing the zero checks can accept this for "
                     "any key and message, as in CVE-2022-21449")

    # Pubkey which will verify under the given `msghash`/`sig` pair if it receives
    # no explicit on-curve check.
    Q = (2, 3)
    assert Q[1] ** 2 % p != (Q[0] ** 3 + 7) % p
    assert point_mul(Q, 6) is None
    u2 = 1
    forged_R = point_mul(Q, u2)
    assert forged_R is not None
    forged_r = forged_R[0] % n
    forged_s = (forged_r * pow(u2, -1, n)) % n
    assert 1 <= forged_r <= n - 1 and 1 <= forged_s <= n - 1
    yield verify_row(Q, 0, (forged_r, forged_s), False,
                     "public key not on the curve, with a signature that verifies "
                     "if the on-curve check is skipped")

    x_one = (1, pow(1 + 7, (p + 1) // 4, p))
    y_one = (pow((1 - 7) % p, (p + 2) // 9, p), 1)
    for key, wide_key, comment in [
        (x_one, (x_one[0] + p, x_one[1]),
         "public key x = p+1; accepted if coordinates are reduced mod p instead of rejected"),
        (y_one, (y_one[0], y_one[1] + p),
         "public key y = p+1; accepted if coordinates are reduced mod p instead of rejected"),
    ]:
        assert key[1] ** 2 % p == (key[0] ** 3 + 7) % p and max(wide_key) < 2**256
        key_R = point_add(G, key)
        assert key_R is not None
        key_r = key_R[0] % n
        assert verify((key_r, key_r), key, bytes_from_int(key_r))
        yield verify_row(wide_key, key_r, (key_r, key_r), False, comment)

    yield verify_row(None, msg, sig, False, "public key is the point at infinity")

    # Vector that produces R as the point at infinity.
    infinite_r_msg = (-r * sk) % n
    assert (infinite_r_msg + r * sk) % n == 0 and infinite_r_msg != 0
    yield verify_row(P, infinite_r_msg, sig, False, "u1*G + u2*P is the point at infinity")

    # Vector with x(R) greater than n, unreachable in practice (n + 2, since
    # x = n gives r = 0).
    big_x = n + 2
    big_y = pow((big_x ** 3 + 7) % p, (p + 1) // 4, p)
    assert big_y ** 2 % p == (big_x ** 3 + 7) % p
    big_R = (big_x, big_y)
    big_P = point_add(big_R, (G[0], p - G[1]))
    assert big_P is not None and big_x % n == 2
    yield verify_row(big_P, 2, (2, 2), True,
                     "x(R) = n+2; fails if x(R) is compared to r without reducing mod n")
    # The same signature with r or s moved out of range.
    yield verify_row(big_P, 2, (2 + n, 2), False,
                     "r = n+2; accepted if r is reduced mod n instead of rejected")
    yield verify_row(big_P, 2, (2, 2 + n), False,
                     "s = n+2; accepted if s is reduced mod n instead of rejected")

def gen_all(fil, fields, vectors):
    writer = csv.DictWriter(fil, fields)
    writer.writeheader()
    for row in vectors:
        writer.writerow(row)

if __name__ == "__main__":
    cases = signed_cases()
    print(f"Generating {FILENAME_SIGN_TEST}...")
    with open(FILENAME_SIGN_TEST, "w", newline='', encoding="utf-8") as fil_sign:
        gen_all(fil_sign, ["seckey", "msghash", "sig", "comment"],
                sign_vectors(cases))
    print(f"Generating {FILENAME_VERIFY_TEST}...")
    with open(FILENAME_VERIFY_TEST, "w", newline='', encoding="utf-8") as fil_verify:
        gen_all(fil_verify, ["pubkey", "msghash", "sig", "result", "comment"], verify_vectors(cases))
