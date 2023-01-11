"""Generate the BIP-0324 test vectors."""

import csv
import hashlib
import os
import sys
from reference import (
    FE,
    GE,
    MINUS_3_SQRT,
    hkdf_sha256,
    SECP256K1_G,
    ellswift_decode,
    ellswift_ecdh_xonly,
    xswiftec_inv,
    xswiftec,
    v2_ecdh,
    initialize_v2_transport,
    v2_enc_packet
)

FILENAME_PACKET_TEST = os.path.join(sys.path[0], 'packet_encoding_test_vectors.csv')
FILENAME_XSWIFTEC_INV_TEST = os.path.join(sys.path[0], 'xswiftec_inv_test_vectors.csv')
FILENAME_ELLSWIFT_DECODE_TEST = os.path.join(sys.path[0], 'ellswift_decode_test_vectors.csv')

def xswiftec_flagged(u, t, simplified=False):
    """A variant of xswiftec which also returns 'flags', describing conditions encountered."""
    flags = []
    if u == 0:
        flags.append("u%p=0")
        u = FE(1)
    if t == 0:
        flags.append("t%p=0")
        t = FE(1)
    if u**3 + t**2 + 7 == 0:
        flags.append("(u'^3+t'^2+7)%p=0")
        t = 2 * t
    X = (u**3 + 7 - t**2) / (2 * t)
    Y = (X + t) / (MINUS_3_SQRT * u)
    if X == 0:
        if not simplified:
            flags.append("(u'^3-t'^2+7)%p=0")
    x3 = u + 4 * Y**2
    if GE.is_valid_x(x3):
        flags.append("valid_x(x3)")
    x2 = (-X / Y - u) / 2
    if GE.is_valid_x(x2):
        flags.append("valid_x(x2)")
    x1 = (X / Y - u) / 2
    if GE.is_valid_x(x1):
        flags.append("valid_x(x1)")
    for x in (x3, x2, x1):
        if GE.is_valid_x(x):
            break
    return x, flags


def ellswift_create_deterministic(seed, features):
    """This is a variant of ellswift_create which doesn't use randomness.

    features is an integer selecting some properties of the result:
    - (f & 3) == 0: only x1 is valid on decoding (see xswiftec{_flagged})
    - (f & 3) == 1: only x2 is valid on decoding
    - (f & 3) == 2: only x3 is valid on decoding
    - (f & 3) == 3: x1,x2,x3 are all valid on decoding
    - (f & 4) == 4: u >= p
    - (f & 8) == 8: u mod n == 0

    Returns privkey, ellswift
    """

    cnt = 0
    while True:
        sec = hkdf_sha256(32, seed, (cnt).to_bytes(4, 'little'), b"sec")
        xval = (int.from_bytes(sec, 'big') * SECP256K1_G).x
        cnt += 1
        if features & 8:
            u = 0
            if features & 4:
                u += FE.SIZE
        else:
            udat = hkdf_sha256(64, seed, (cnt).to_bytes(4, 'little'), b"u")
            if features & 4:
                u = FE.SIZE + 1 + int.from_bytes(udat, 'big') % (2**256 - FE.SIZE - 1)
            else:
                u = 1 + int.from_bytes(udat, 'big') % (FE.SIZE - 1)
        case = hkdf_sha256(1, seed, (cnt).to_bytes(4, 'little'), b"case")[0] & 7
        coru = FE(u) + ((features & 8) == 8)
        t = xswiftec_inv(xval, coru, case)
        if t is None:
            continue
        assert xswiftec(FE(u), t) == xval
        x2, flags = xswiftec_flagged(FE(u), t)
        assert x2 == xval
        have_x1 = "valid_x(x1)" in flags
        have_x2 = "valid_x(x2)" in flags
        have_x3 = "valid_x(x3)" in flags
        if (features & 4) == 0 and not (have_x1 and not have_x2 and not have_x3):
            continue
        if (features & 4) == 1 and not (not have_x1 and have_x2 and not have_x3):
            continue
        if (features & 4) == 2 and not (not have_x1 and not have_x2 and have_x3):
            continue
        if (features & 4) == 3 and not (have_x1 and have_x2 and have_x3):
            continue
        return sec, u.to_bytes(32, 'big') + t.to_bytes()

def ellswift_decode_flagged(ellswift, simplified=False):
    """Decode a 64-byte ElligatorSwift encoded coordinate, returning byte array + flag string."""
    uv = int.from_bytes(ellswift[:32], 'big')
    tv = int.from_bytes(ellswift[32:], 'big')
    x, flags = xswiftec_flagged(FE(uv), FE(tv))
    if not simplified:
        if uv >= FE.SIZE:
            flags.append("u>=p")
        if tv >= FE.SIZE:
            flags.append("t>=p")
    return int(x).to_bytes(32, 'big'), ";".join(flags)

def random_fe_int(_, seed, i, p):
    """Function to use in tuple_expand, generating a random integer in 0..p-1."""
    rng_out = hkdf_sha256(64, seed, i.to_bytes(4, 'little'), b"v%i_fe" % p)
    return int.from_bytes(rng_out, 'big') % FE.SIZE

def random_fe_int_high(_, seed, i, p):
    """Function to use in tuple_expand, generating a random integer in p..2^256-1."""
    rng_out = hkdf_sha256(64, seed, i.to_bytes(4, 'little'), b"v%i_fe_high" % p)
    return FE.SIZE + int.from_bytes(rng_out, 'big') % (2**256 - FE.SIZE)

def fn_of(p_in, fn):
    """Function to use in tuple_expand, to pick one variable in function of another."""
    def inner(vs, _seed, _i, p):
        assert p != p_in
        if isinstance(vs[p_in], int):
            return fn(vs[p_in])
        return None
    return inner

def tuple_expand(out, tuplespec, prio, seed=None, cnt=1):
    """Given a tuple specification, expand it cnt times, and add results to out.

    Expansion is defined recursively:
    - If any of the spec elements is a list, each element of the list results
      in an expansion (by replacing the list with its element).
    - If any of the spec elements is a function, that function is invoked with
      (spec, seed, expansion count, index in spec) as arguments. If the function
      needs to wait for other indices to be expanded, it can return None.

    The output consists of (prio, expansion count, SHA256(result), result, seed)
    tuples."""

    def recurse(vs, seed, i, change_pos=None, change=None):
        if change_pos is not None:
            vs = list(vs)
            vs[change_pos] = change
        for p, v in enumerate(vs):
            if v is None:
                return
            if isinstance(v, list):
                for ve in v:
                    recurse(vs, seed, i, p, ve)
                return
            if callable(v):
                res = v(vs, seed, i, p)
                if res is not None:
                    recurse(vs, seed, i, p, res)
                    return
        h = hashlib.sha256()
        for v in vs:
            h.update(int(v).to_bytes(32, 'big'))
        out.append((prio, i, h.digest(), vs, seed))
    for i in range(cnt):
        recurse(tuplespec, seed, i)

def gen_ellswift_decode_cases(seed, simplified=False):
    """Generate a set of interesting (ellswift, x, flags) ellswift decoding cases."""
    inputs = []

    # Aggregate for use in tuple_expand, expanding to int in 0..p-1, and one in p..2^256-1.
    RANDOM_VAL = [random_fe_int, random_fe_int_high]
    # Aggregate for use in tuple_expand, expanding to integers which %p equal 0.
    ZERO_VAL = [0, FE.SIZE]
    # Helpers for constructing u and t values such that u^3+t^2+7=0 or u^3-t^2+7=0.
    T_FOR_SUM_ZERO = fn_of(0, lambda u: (-FE(u)**3 - 7).sqrts())
    T_FOR_DIFF_ZERO = fn_of(0, lambda u: (FE(u)**3 + 7).sqrts())
    U_FOR_SUM_ZERO = fn_of(1, lambda t: (-FE(t)**2 - 7).cbrts())
    U_FOR_DIFF_ZERO = fn_of(1, lambda t: (FE(t)**2 - 7).cbrts())

    tuple_expand(inputs, [RANDOM_VAL, RANDOM_VAL], 0, seed + b"random", 64)
    tuple_expand(inputs, [RANDOM_VAL, T_FOR_SUM_ZERO], 1, seed + b"t=sqrt(-u^3-7)", 64)
    tuple_expand(inputs, [U_FOR_SUM_ZERO, RANDOM_VAL], 1, seed + b"u=cbrt(-t^2-7)", 64)
    tuple_expand(inputs, [RANDOM_VAL, T_FOR_DIFF_ZERO], 1, seed + b"t=sqrt(u^3+7)", 64)
    tuple_expand(inputs, [U_FOR_DIFF_ZERO, RANDOM_VAL], 1, seed + b"u=cbrt(t^2-7)", 64)
    tuple_expand(inputs, [ZERO_VAL, RANDOM_VAL], 2, seed + b"u=0", 64)
    tuple_expand(inputs, [RANDOM_VAL, ZERO_VAL], 2, seed + b"t=0", 64)
    tuple_expand(inputs, [ZERO_VAL, FE(8).sqrts()], 3, seed + b"u=0;t=sqrt(8)")
    tuple_expand(inputs, [FE(-8).cbrts(), ZERO_VAL], 3, seed + b"t=0;u=cbrt(-8)")
    tuple_expand(inputs, [FE(-6).cbrts(), ZERO_VAL], 3, seed + b"t=0;u=cbrt(-6)")
    tuple_expand(inputs, [ZERO_VAL, ZERO_VAL], 3, seed + b"u=0;t=0")
    # Unused.
    tuple_expand(inputs, [ZERO_VAL, FE(-8).sqrts()], 4, seed + b"u=0;t=sqrt(-8)")

    seen = set()
    cases = []
    for _prio, _cnt, _hash, vs, _seed in sorted(inputs):
        inp = int(vs[0]).to_bytes(32, 'big') + int(vs[1]).to_bytes(32, 'big')
        outp, flags = ellswift_decode_flagged(inp, simplified)
        if flags not in seen:
            cases.append((inp, outp, flags))
            seen.add(flags)

    return cases

def gen_all_ellswift_decode_vectors(fil):
    """Generate all xelligatorswift decoding test vectors."""

    cases = gen_ellswift_decode_cases(b"")
    writer = csv.DictWriter(fil, ["ellswift", "x", "comment"])
    writer.writeheader()
    for val, x, flags in sorted(cases):
        writer.writerow({"ellswift": val.hex(), "x": x.hex(), "comment": flags})

def xswiftec_inv_flagged(x, u, case):
    """A variant of xswiftec_inv which also returns flags, describing conditions encountered."""

    flags = []

    if case & 2 == 0:
        if GE.is_valid_x(-x - u):
            flags.append("bad[valid_x(-x-u)]")
            return None, flags
        v = x if case & 1 == 0 else -x - u
        if v == 0:
            flags.append("info[v=0]")
        s = -(u**3 + 7) / (u**2 + u*v + v**2)
        assert s != 0 # would imply X=0 on curve
    else:
        s = x - u
        if s == 0:
            flags.append("bad[s=0]")
            return None, flags
        q = (-s * (4 * (u**3 + 7) + 3 * s * u**2))
        if q == 0:
            flags.append("info[q=0]")
        r = q.sqrt()
        if r is None:
            flags.append("bad[non_square(q)]")
            return None, flags
        if case & 1:
            if r == 0:
                flags.append("bad[r=0]")
                return None, flags
            r = -r
        v = (-u + r / s) / 2
        if v == 0:
            flags.append("info[v=0]")
    w = s.sqrt()
    assert w != 0
    if w is None:
        flags.append("bad[non_square(s)]")
        return None, flags
    if case & 4:
        w = -w
    Y = w / 2
    assert Y != 0
    X = 2 * Y * (v + u / 2)
    if X == 0:
        flags.append("info[X=0]")
    flags.append("ok")
    return w * (u * (MINUS_3_SQRT - 1) / 2 - v), flags

def xswiftec_inv_combo_flagged(x, u):
    """Compute the aggregate results and flags from xswiftec_inv_flagged for case=0..7."""
    ts = []
    allflags = []
    for case in range(8):
        t, flags = xswiftec_inv_flagged(x, u, case)
        if t is not None:
            assert x == xswiftec(u, t)
        ts.append(t)
        allflags.append(f"case{case}:{'&'.join(flags)}")
    return ts, ";".join(allflags)

def gen_all_xswiftec_inv_vectors(fil):
    """Generate all xswiftec_inv test vectors."""

    # Two constants used below. Compute them only once.
    C1 = (FE(MINUS_3_SQRT) - 1) / 2
    C2 = (-FE(MINUS_3_SQRT) - 1) / 2
    # Helper functions that pick x and u with special properties.
    TRIGGER_Q_ZERO = fn_of(1, lambda u: (FE(u)**3 + 28) / (FE(-3) * FE(u)**2))
    TRIGGER_DIVZERO_A = fn_of(1, lambda u: FE(u) * C1)
    TRIGGER_DIVZERO_B = fn_of(1, lambda u: FE(u) * C2)
    TRIGGER_V_ZERO = fn_of(1, lambda u: FE(-7) / FE(u)**2)
    TRIGGER_X_ZERO = fn_of(0, lambda x: FE(-2) * FE(x))

    inputs = []
    tuple_expand(inputs, [random_fe_int, random_fe_int], 0, b"uniform", 256)
    tuple_expand(inputs, [TRIGGER_Q_ZERO, random_fe_int], 1, b"x=-(u^3+28)/(3*u^2)", 64)
    tuple_expand(inputs, [TRIGGER_V_ZERO, random_fe_int], 1, b"x=-7/u^2", 512)
    tuple_expand(inputs, [random_fe_int, fn_of(0, lambda x: x)], 2, b"u=x", 64)
    tuple_expand(inputs, [random_fe_int, fn_of(0, lambda x: -FE(x))], 2, b"u=-x", 64)
    # Unused.
    tuple_expand(inputs, [TRIGGER_DIVZERO_A, random_fe_int], 3, b"x=u*(sqrt(-3)-1)/2", 64)
    tuple_expand(inputs, [TRIGGER_DIVZERO_B, random_fe_int], 3, b"x=u*(-sqrt(-3)-1)/2", 64)
    tuple_expand(inputs, [random_fe_int, TRIGGER_X_ZERO], 3, b"u=-2x", 64)

    seen = set()
    cases = []
    for _prio, _cnt, _hash, vs, _seed in sorted(inputs):
        x, u = FE(vs[0]), FE(vs[1])
        if u == 0:
            continue
        if not GE.is_valid_x(x):
            continue
        ts, flags = xswiftec_inv_combo_flagged(x, u)
        if flags not in seen:
            cases.append((int(u), int(x), ts, flags))
            seen.add(flags)

    writer = csv.DictWriter(fil, ["u", "x"] + [f"case{c}_t" for c in range(8)] + ["comment"])
    writer.writeheader()
    for u, x, ts, flags in sorted(cases):
        row = {"u": FE(u), "x": FE(x), "comment": flags}
        for c in range(8):
            if ts[c] is not None:
                row[f"case{c}_t"] = FE(ts[c])
        writer.writerow(row)

def gen_packet_encoding_vector(case):
    """Given a dict case with specs, construct a packet_encoding test vector as a CSV line."""
    ikm = str(case).encode('utf-8')
    in_initiating = case["init"]
    in_ignore = int(case["ignore"])
    in_priv_ours, in_ellswift_ours = ellswift_create_deterministic(ikm, case["features"])
    mid_x_ours = (int.from_bytes(in_priv_ours, 'big') * SECP256K1_G).x.to_bytes()
    assert mid_x_ours == ellswift_decode(in_ellswift_ours)
    in_ellswift_theirs = case["theirs"]
    in_contents = hkdf_sha256(case["contentlen"], ikm, b"contents", b"")
    contents = in_contents * case["multiply"]
    in_aad = hkdf_sha256(case["aadlen"], ikm, b"aad", b"")
    mid_shared_secret = v2_ecdh(in_priv_ours, in_ellswift_theirs, in_ellswift_ours, in_initiating)

    peer = initialize_v2_transport(mid_shared_secret, in_initiating)
    for _ in range(case["idx"]):
        v2_enc_packet(peer, b"")
    ciphertext = v2_enc_packet(peer, contents, in_aad, case["ignore"])
    long_msg = len(ciphertext) > 128

    return {
        "in_idx": case['idx'],
        "in_priv_ours": in_priv_ours.hex(),
        "in_ellswift_ours": in_ellswift_ours.hex(),
        "in_ellswift_theirs": in_ellswift_theirs.hex(),
        "in_initiating": int(in_initiating),
        "in_contents": in_contents.hex(),
        "in_multiply": case['multiply'],
        "in_aad": in_aad.hex(),
        "in_ignore": in_ignore,
        "mid_x_ours": mid_x_ours.hex(),
        "mid_x_theirs": ellswift_decode(in_ellswift_theirs).hex(),
        "mid_x_shared": ellswift_ecdh_xonly(in_ellswift_theirs, in_priv_ours).hex(),
        "mid_shared_secret": mid_shared_secret.hex(),
        "mid_initiator_l": peer['initiator_L'].hex(),
        "mid_initiator_p": peer['initiator_P'].hex(),
        "mid_responder_l": peer['responder_L'].hex(),
        "mid_responder_p": peer['responder_P'].hex(),
        "mid_send_garbage_terminator": peer["send_garbage_terminator"].hex(),
        "mid_recv_garbage_terminator": peer["recv_garbage_terminator"].hex(),
        "out_session_id": peer["session_id"].hex(),
        "out_ciphertext": "" if long_msg else ciphertext.hex(),
        "out_ciphertext_endswith": ciphertext[-128:].hex() if long_msg else ""
    }

def gen_all_packet_encoding_vectors(fil):
    """Return a list of CSV lines, one for each packet encoding vector."""

    ellswift = gen_ellswift_decode_cases(b"simplified_", simplified=True)
    ellswift.sort(key=lambda x: hashlib.sha256(b"simplified:" + x[0]).digest())

    fields = [
        "in_idx", "in_priv_ours", "in_ellswift_ours", "in_ellswift_theirs", "in_initiating",
        "in_contents", "in_multiply", "in_aad", "in_ignore", "mid_x_ours", "mid_x_theirs",
        "mid_x_shared", "mid_shared_secret", "mid_initiator_l", "mid_initiator_p",
        "mid_responder_l", "mid_responder_p", "mid_send_garbage_terminator",
        "mid_recv_garbage_terminator", "out_session_id", "out_ciphertext", "out_ciphertext_endswith"
    ]

    writer = csv.DictWriter(fil, fields)
    writer.writeheader()
    for case in [
        {"init": True, "contentlen": 1, "multiply": 1, "aadlen": 0, "ignore": False, "idx": 1,
         "theirs": ellswift[0][0], "features": 0},
        {"init": False, "contentlen": 17, "multiply": 1, "aadlen": 0, "ignore": False, "idx": 999,
         "theirs": ellswift[1][0], "features": 1},
        {"init": True, "contentlen": 63, "multiply": 1, "aadlen": 4095, "ignore": False, "idx": 0,
         "theirs": ellswift[2][0], "features": 2},
        {"init": False, "contentlen": 128, "multiply": 1, "aadlen": 0, "ignore": True, "idx": 223,
         "theirs": ellswift[3][0], "features": 3},
        {"init": True, "contentlen": 193, "multiply": 1, "aadlen": 0, "ignore": False, "idx": 448,
         "theirs": ellswift[4][0], "features": 4},
        {"init": False, "contentlen": 41, "multiply": 97561, "aadlen": 0, "ignore": False,
         "idx": 673, "theirs": ellswift[5][0], "features": 5},
        {"init": True, "contentlen": 241, "multiply": 69615, "aadlen": 0, "ignore": True,
         "idx": 1024, "theirs": ellswift[6][0], "features": 6},
    ]:
        writer.writerow(gen_packet_encoding_vector(case))

if __name__ == "__main__":
    print(f"Generating {FILENAME_PACKET_TEST}...")
    with open(FILENAME_PACKET_TEST, "w", encoding="utf-8") as fil_packet:
        gen_all_packet_encoding_vectors(fil_packet)
    print(f"Generating {FILENAME_XSWIFTEC_INV_TEST}...")
    with open(FILENAME_XSWIFTEC_INV_TEST, "w", encoding="utf-8") as fil_xswiftec_inv:
        gen_all_xswiftec_inv_vectors(fil_xswiftec_inv)
    print(f"Generating {FILENAME_ELLSWIFT_DECODE_TEST}...")
    with open(FILENAME_ELLSWIFT_DECODE_TEST, "w", encoding="utf-8") as fil_ellswift_decode:
        gen_all_ellswift_decode_vectors(fil_ellswift_decode)
