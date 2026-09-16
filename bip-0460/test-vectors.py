#!/usr/bin/env python3
"""
Test vector generator for the CISA Taproot key path BIP (witness v2).

Generates two files:
  wallet-test-vectors.json     scriptPubKey/address derivation, sighash
                               computation, and witness construction
  consensus-test-vectors.json  transaction level valid/invalid cases

WARNING: All keys and nonces in this file are deterministic and publicly
known. They exist only to make the vectors reproducible. Never use this
code or these values in production.
"""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "secp256k1lab/src"))
sys.path.insert(0, str(Path(__file__).parent))

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.util import tagged_hash

import halfagg
import fullagg

# Marker bytes
MARKER_HALFAGG = 0xBC
MARKER_FULLAGG = 0xBD

# Sighash epoch for aggregated witness v2 signature messages
SIGHASH_EPOCH = 0x01

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

AUX_ZERO = bytes(32)


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def sha256(b):
    return hashlib.sha256(b).digest()


def ser_compact_size(n):
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b"\xfd" + n.to_bytes(2, "little")
    if n < 0x100000000:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


class TxIn:
    def __init__(self, txid, vout, sequence=0xFFFFFFFF):
        self.txid = txid  # 32 bytes, internal byte order
        self.vout = vout
        self.sequence = sequence

    def outpoint(self):
        return self.txid + self.vout.to_bytes(4, "little")


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def serialize(self):
        return self.amount.to_bytes(8, "little") + ser_compact_size(
            len(self.script_pubkey)
        ) + self.script_pubkey


class Tx:
    def __init__(self, vin, vout, version=2, locktime=0):
        self.version = version
        self.locktime = locktime
        self.vin = vin
        self.vout = vout
        self.witnesses = [[] for _ in vin]

    def serialize_unsigned(self):
        out = self.version.to_bytes(4, "little")
        out += ser_compact_size(len(self.vin))
        for txin in self.vin:
            out += txin.outpoint() + b"\x00" + txin.sequence.to_bytes(4, "little")
        out += ser_compact_size(len(self.vout))
        for txout in self.vout:
            out += txout.serialize()
        out += self.locktime.to_bytes(4, "little")
        return out

    def serialize_signed(self):
        out = self.version.to_bytes(4, "little")
        out += b"\x00\x01"
        out += ser_compact_size(len(self.vin))
        for txin in self.vin:
            out += txin.outpoint() + b"\x00" + txin.sequence.to_bytes(4, "little")
        out += ser_compact_size(len(self.vout))
        for txout in self.vout:
            out += txout.serialize()
        for witness in self.witnesses:
            out += ser_compact_size(len(witness))
            for element in witness:
                out += ser_compact_size(len(element)) + element
        out += self.locktime.to_bytes(4, "little")
        return out


# ---------------------------------------------------------------------------
# Taproot style key derivation
# ---------------------------------------------------------------------------

def tweak_keypair(seckey32):
    d0 = Scalar.from_bytes_checked(seckey32)
    P = d0 * G
    d = d0 if P.has_even_y() else -d0
    internal_pubkey = P.to_bytes_xonly()
    t = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal_pubkey))
    Q = (d + t) * G
    tweaked_seckey = (d + t).to_bytes()
    return internal_pubkey, t.to_bytes(), tweaked_seckey, Q.to_bytes_xonly()


def v2_script_pubkey(output_key32):
    return bytes([0x52, 0x20]) + output_key32


# ---------------------------------------------------------------------------
# Bech32m (adapted from the BIP 350 reference implementation)
# ---------------------------------------------------------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32m_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def v2_address(output_key32, hrp="bc"):
    data = [2] + convertbits(output_key32, 8, 5)
    combined = data + bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


# ---------------------------------------------------------------------------
# Witness v2 common signature message
# ---------------------------------------------------------------------------

def sigmsg_common(tx, spent_utxos, input_index, hash_type, ext_flag, annex=None):
    """Compute SigMsg(hash_type, ext_flag) as defined in BIP 341."""
    assert len(spent_utxos) == len(tx.vin)
    anyonecanpay = bool(hash_type & SIGHASH_ANYONECANPAY)
    base_type = hash_type & 3

    msg = bytes([hash_type])
    msg += tx.version.to_bytes(4, "little")
    msg += tx.locktime.to_bytes(4, "little")
    if not anyonecanpay:
        msg += sha256(b"".join(txin.outpoint() for txin in tx.vin))
        msg += sha256(b"".join(u.amount.to_bytes(8, "little") for u in spent_utxos))
        msg += sha256(
            b"".join(
                ser_compact_size(len(u.script_pubkey)) + u.script_pubkey
                for u in spent_utxos
            )
        )
        msg += sha256(
            b"".join(txin.sequence.to_bytes(4, "little") for txin in tx.vin)
        )
    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        msg += sha256(b"".join(txout.serialize() for txout in tx.vout))
    spend_type = 2 * ext_flag + (1 if annex is not None else 0)
    msg += bytes([spend_type])
    if anyonecanpay:
        txin = tx.vin[input_index]
        utxo = spent_utxos[input_index]
        msg += txin.outpoint()
        msg += utxo.amount.to_bytes(8, "little")
        msg += ser_compact_size(len(utxo.script_pubkey)) + utxo.script_pubkey
        msg += txin.sequence.to_bytes(4, "little")
    else:
        msg += input_index.to_bytes(4, "little")
    if annex is not None:
        msg += sha256(ser_compact_size(len(annex)) + annex)
    if base_type == SIGHASH_SINGLE:
        msg += sha256(tx.vout[input_index].serialize())
    return msg


def sigmsg_v2(tx, spent_utxos, input_index, hash_type, agg_mode, annex=None):
    """Compute hash_TapSighash(0x01 || agg_mode || SigMsg(hash_type, 0))."""
    msg = sigmsg_common(tx, spent_utxos, input_index, hash_type, 0, annex)
    return tagged_hash("TapSighash", bytes([SIGHASH_EPOCH, agg_mode]) + msg)


def sigmsg_tapscript(tx, spent_utxos, input_index, hash_type, tapleaf_hash,
                     annex=None):
    """Compute the unchanged BIP 342 tapscript signature message,
    hash_TapSighash(0x00 || SigMsg(hash_type, 1) || ext)."""
    msg = sigmsg_common(tx, spent_utxos, input_index, hash_type, 1, annex)
    ext = tapleaf_hash + b"\x00" + b"\xff\xff\xff\xff"
    return tagged_hash("TapSighash", bytes([0x00]) + msg + ext)


def sigmsg_v1(tx, spent_utxos, input_index, hash_type, annex=None):
    """Compute the unchanged BIP 341 key path signature message,
    hash_TapSighash(0x00 || SigMsg(hash_type, 0))."""
    msg = sigmsg_common(tx, spent_utxos, input_index, hash_type, 0, annex)
    return tagged_hash("TapSighash", bytes([0x00]) + msg)


# ---------------------------------------------------------------------------
# Witness element construction
# ---------------------------------------------------------------------------

def marker_element(marker, hash_type=SIGHASH_DEFAULT, sig=b""):
    element = sig
    if hash_type != SIGHASH_DEFAULT:
        element += bytes([hash_type])
    return element + bytes([marker])


def optout_element(sig, hash_type=SIGHASH_DEFAULT):
    if hash_type == SIGHASH_DEFAULT:
        return sig
    return sig + bytes([hash_type])


def halfagg_member(nonce_share, hash_type=SIGHASH_DEFAULT):
    if hash_type == SIGHASH_DEFAULT:
        return nonce_share
    return nonce_share + bytes([hash_type])


def fullagg_member(hash_type=SIGHASH_DEFAULT):
    if hash_type == SIGHASH_DEFAULT:
        return b""
    return bytes([hash_type])


def halfagg_final(aggsig, hash_type=SIGHASH_DEFAULT):
    return marker_element(MARKER_HALFAGG, hash_type, aggsig[-64:])


# ---------------------------------------------------------------------------
# Deterministic test data
# ---------------------------------------------------------------------------

def test_seckey(i):
    return tagged_hash("CISA/test/key", bytes([i]))


def test_prevout_txid(i):
    return sha256(b"CISA vector prevout " + bytes([i]))


def test_fullagg_secnonce(i):
    # Test-only deterministic nonces. Nonces must be fresh uniform
    # randomness in any real signing session.
    r1 = Scalar.from_bytes_wrapping(tagged_hash("CISA/test/nonce", bytes([i, 0])))
    r2 = Scalar.from_bytes_wrapping(tagged_hash("CISA/test/nonce", bytes([i, 1])))
    return (r1, r2), (r1 * G, r2 * G)


def test_garbage(label, length=32):
    out = b""
    i = 0
    while len(out) < length:
        out += tagged_hash("CISA/test/garbage", label + bytes([i]))
        i += 1
    return out[:length]


def test_offcurve_x(label):
    # Deterministically find 32 bytes that are not a valid x coordinate.
    i = 0
    while True:
        cand = tagged_hash("CISA/test/offcurve", label + bytes([i]))
        try:
            GE.from_bytes_xonly(cand)
        except ValueError:
            return cand
        i += 1


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------

def sign_optout(tx, utxos, idx, tweaked_seckey, hash_type):
    m = sigmsg_v1(tx, utxos, idx, hash_type)
    sig = schnorr_sign(m, tweaked_seckey, AUX_ZERO)
    return m, sig


def sign_halfagg_group(tx, utxos, members):
    """members: list of (input_index, tweaked_seckey, hash_type).
    Returns (msgs, plain_sigs, aggsig)."""
    triples = []
    msgs = []
    for idx, sk, ht in members:
        m = sigmsg_v2(tx, utxos, idx, ht, MARKER_HALFAGG)
        sig = schnorr_sign(m, sk, AUX_ZERO)
        pk = utxos[idx].script_pubkey[2:]
        triples.append((pk, m, sig))
        msgs.append(m)
    aggsig = halfagg.Aggregate(triples)
    assert halfagg.VerifyAggregate(aggsig, [(pk, m) for pk, m, _ in triples])
    return msgs, [t[2] for t in triples], aggsig


def sign_fullagg_group(tx, utxos, members, msg_mode=MARKER_FULLAGG,
                       nonce_offset=0, annexes=None):
    """members: list of (input_index, tweaked_seckey, hash_type).
    msg_mode overrides the marker committed in the signature messages,
    with None selecting the plain BIP 341 message, used by negative
    vectors exercising the mode commitment.
    nonce_offset varies the deterministic test nonces between sessions.
    annexes optionally maps input indices to their annex.
    Returns (msgs, secnonces, pubnonces, sig64)."""
    pks = []
    msgs = []
    secnonces = []
    pubnonces = []
    for i, (idx, sk, ht) in enumerate(members):
        annex = annexes.get(idx) if annexes else None
        if msg_mode is None:
            m = sigmsg_v1(tx, utxos, idx, ht, annex=annex)
        else:
            m = sigmsg_v2(tx, utxos, idx, ht, msg_mode, annex=annex)
        msgs.append(m)
        pks.append(GE.from_bytes_xonly(utxos[idx].script_pubkey[2:]))
        secnonce, pubnonce = test_fullagg_secnonce(i + nonce_offset)
        secnonces.append(secnonce)
        pubnonces.append(pubnonce)
    aggnonce = fullagg.NonceAgg(pubnonces)
    psigs = []
    for i, (idx, sk, ht) in enumerate(members):
        d = Scalar.from_bytes_checked(sk)
        psig = fullagg.Sign(secnonces[i], d, msgs[i], aggnonce, pks, msgs, pubnonces)
        psigs.append(psig)
    R, s = fullagg.SigAgg(aggnonce, pks, msgs, pubnonces, psigs)
    assert fullagg.Verify(pks, msgs, (R, s))
    sig64 = R.to_bytes_xonly() + s.to_bytes()
    return msgs, secnonces, pubnonces, sig64


# ---------------------------------------------------------------------------
# Vector construction
# ---------------------------------------------------------------------------

def hexlify(b):
    return b.hex()


def make_wallet_vectors():
    vectors = {"scriptPubKey": [], "keyPathSpending": []}

    # scriptPubKey and address derivation
    for i in range(2):
        seckey = test_seckey(i)
        internal_pubkey, tweak, tweaked_seckey, output_key = tweak_keypair(seckey)
        spk = v2_script_pubkey(output_key)
        vectors["scriptPubKey"].append(
            {
                "given": {"internalPubkey": hexlify(internal_pubkey)},
                "intermediary": {
                    "tweak": hexlify(tweak),
                    "tweakedPubkey": hexlify(output_key),
                },
                "expected": {
                    "scriptPubKey": hexlify(spk),
                    "address": v2_address(output_key),
                },
            }
        )

    # Case 1: opted-out input plus a two-member half-aggregation group
    keys = [tweak_keypair(test_seckey(i)) for i in range(3)]
    utxos = [
        TxOut(100_000_000 + i * 1_000_000, v2_script_pubkey(k[3]))
        for i, k in enumerate(keys)
    ]
    tx = Tx(
        vin=[TxIn(test_prevout_txid(i), 0) for i in range(3)],
        vout=[TxOut(299_000_000, v2_script_pubkey(keys[0][3]))],
    )
    m0, sig0 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_ALL)
    msgs, sigs, aggsig = sign_halfagg_group(
        tx, utxos, [(1, keys[1][2], SIGHASH_DEFAULT), (2, keys[2][2], SIGHASH_DEFAULT)]
    )
    tx.witnesses[0] = [optout_element(sig0, SIGHASH_ALL)]
    tx.witnesses[1] = [halfagg_member(sigs[0][:32])]
    tx.witnesses[2] = [halfagg_final(aggsig)]

    case1 = {
        "description": "Opted-out input with SIGHASH_ALL alongside a "
        "two-member half-aggregation group with SIGHASH_DEFAULT",
        "given": {
            "rawUnsignedTx": hexlify(tx.serialize_unsigned()),
            "utxosSpent": [
                {"scriptPubKey": hexlify(u.script_pubkey), "amountSats": u.amount}
                for u in utxos
            ],
        },
        "inputSpending": [],
        "auxiliary": {"aggregateSignature": hexlify(aggsig)},
        "expected": {"rawSignedTx": hexlify(tx.serialize_signed())},
    }
    input_data = [
        (0, None, SIGHASH_ALL, m0),
        (1, MARKER_HALFAGG, SIGHASH_DEFAULT, msgs[0]),
        (2, MARKER_HALFAGG, SIGHASH_DEFAULT, msgs[1]),
    ]
    for idx, marker, ht, m in input_data:
        case1["inputSpending"].append(
            {
                "given": {
                    "txinIndex": idx,
                    "internalPrivkey": hexlify(test_seckey(idx)),
                    "aggMode": None if marker is None else f"0x{marker:02x}",
                    "hashType": ht,
                },
                "intermediary": {
                    "internalPubkey": hexlify(keys[idx][0]),
                    "tweak": hexlify(keys[idx][1]),
                    "tweakedPrivkey": hexlify(keys[idx][2]),
                    "sigHash": hexlify(m),
                },
                "expected": {"witness": [hexlify(e) for e in tx.witnesses[idx]]},
            }
        )
    vectors["keyPathSpending"].append(case1)

    # Case 2: two-member full-aggregation group
    keys = [tweak_keypair(test_seckey(i + 3)) for i in range(2)]
    utxos = [
        TxOut(50_000_000, v2_script_pubkey(keys[0][3])),
        TxOut(70_000_000, v2_script_pubkey(keys[1][3])),
    ]
    tx = Tx(
        vin=[TxIn(test_prevout_txid(i + 3), 1) for i in range(2)],
        vout=[TxOut(119_000_000, v2_script_pubkey(keys[0][3]))],
    )
    msgs, secnonces, pubnonces, sig64 = sign_fullagg_group(
        tx, utxos, [(0, keys[0][2], SIGHASH_ALL), (1, keys[1][2], SIGHASH_ALL)]
    )
    tx.witnesses[0] = [fullagg_member(SIGHASH_ALL)]
    tx.witnesses[1] = [marker_element(MARKER_FULLAGG, SIGHASH_ALL, sig64)]

    case2 = {
        "description": "Two-member full-aggregation group with SIGHASH_ALL "
        "(using deterministic nonces)",
        "given": {
            "rawUnsignedTx": hexlify(tx.serialize_unsigned()),
            "utxosSpent": [
                {"scriptPubKey": hexlify(u.script_pubkey), "amountSats": u.amount}
                for u in utxos
            ],
        },
        "inputSpending": [],
        "auxiliary": {
            "secnonces": [
                hexlify(r1.to_bytes() + r2.to_bytes()) for r1, r2 in secnonces
            ],
            "pubnonces": [
                hexlify(R1.to_bytes_compressed() + R2.to_bytes_compressed())
                for R1, R2 in pubnonces
            ],
            "aggregateSignature": hexlify(sig64),
        },
        "expected": {"rawSignedTx": hexlify(tx.serialize_signed())},
    }
    for idx in range(2):
        case2["inputSpending"].append(
            {
                "given": {
                    "txinIndex": idx,
                    "internalPrivkey": hexlify(test_seckey(idx + 3)),
                    "aggMode": f"0x{MARKER_FULLAGG:02x}",
                    "hashType": SIGHASH_ALL,
                },
                "intermediary": {
                    "internalPubkey": hexlify(keys[idx][0]),
                    "tweak": hexlify(keys[idx][1]),
                    "tweakedPrivkey": hexlify(keys[idx][2]),
                    "sigHash": hexlify(msgs[idx]),
                },
                "expected": {"witness": [hexlify(e) for e in tx.witnesses[idx]]},
            }
        )
    vectors["keyPathSpending"].append(case2)

    # Case 3: script path spend of a witness v2 output (BIP 341/342 rules
    # unchanged). Same leaf and keys as the consensus scriptpath-valid
    # case, so the two files cross-check.
    script_seckey = test_seckey(20)
    script_pk = (Scalar.from_bytes_checked(script_seckey) * G).to_bytes_xonly()
    script = bytes([0x20]) + script_pk + bytes([0xAC])  # <pk> OP_CHECKSIG
    tapleaf_hash = tagged_hash(
        "TapLeaf", bytes([0xC0]) + ser_compact_size(len(script)) + script
    )
    internal_seckey = test_seckey(21)
    internal_x = (Scalar.from_bytes_checked(internal_seckey) * G).to_bytes_xonly()
    t = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal_x + tapleaf_hash))
    Q = GE.from_bytes_xonly(internal_x) + t * G
    control = bytes([0xC0 | (0 if Q.has_even_y() else 1)]) + internal_x
    spk = v2_script_pubkey(Q.to_bytes_xonly())
    utxos = [TxOut(100_000_000, spk)]
    dest_key = tweak_keypair(test_seckey(0))[3]
    tx = Tx(
        vin=[TxIn(test_prevout_txid(33), 0)],
        vout=[TxOut(99_000_000, v2_script_pubkey(dest_key))],
    )
    m_script = sigmsg_tapscript(tx, utxos, 0, SIGHASH_DEFAULT, tapleaf_hash)
    sig_script = schnorr_sign(m_script, script_seckey, AUX_ZERO)
    assert schnorr_verify(m_script, script_pk, sig_script)
    tx.witnesses[0] = [sig_script, script, control]

    vectors["scriptPathSpending"] = [
        {
            "description": "Script path spend of a witness v2 output with a "
            "single CHECKSIG leaf, following BIP 341/342 unchanged",
            "given": {
                "rawUnsignedTx": hexlify(tx.serialize_unsigned()),
                "utxosSpent": [
                    {"scriptPubKey": hexlify(u.script_pubkey),
                     "amountSats": u.amount}
                    for u in utxos
                ],
                "internalPubkey": hexlify(internal_x),
                "script": hexlify(script),
                "leafVersion": "0xc0",
                "hashType": SIGHASH_DEFAULT,
            },
            "intermediary": {
                "leafHash": hexlify(tapleaf_hash),
                "tweak": hexlify(t.to_bytes()),
                "tweakedPubkey": hexlify(Q.to_bytes_xonly()),
                "controlBlock": hexlify(control),
                "sigHash": hexlify(m_script),
            },
            "expected": {
                "scriptPubKey": hexlify(spk),
                "address": v2_address(Q.to_bytes_xonly()),
                "witness": [hexlify(e) for e in tx.witnesses[0]],
                "rawSignedTx": hexlify(tx.serialize_signed()),
            },
        }
    ]

    return vectors


def make_consensus_vectors():
    cases = []

    def add_case(case_id, description, tx, utxos, valid, failure_reason=None):
        case = {
            "id": case_id,
            "description": description,
            "prevouts": [
                {"scriptPubKey": hexlify(u.script_pubkey), "amountSats": u.amount}
                for u in utxos
            ],
            "tx": hexlify(tx.serialize_signed()),
            "valid": valid,
        }
        if failure_reason is not None:
            case["failureReason"] = failure_reason
        cases.append(case)

    def fresh_setup(num_inputs, key_offset=0):
        keys = [tweak_keypair(test_seckey(i + key_offset)) for i in range(num_inputs)]
        utxos = [
            TxOut(100_000_000, v2_script_pubkey(k[3])) for k in keys
        ]
        tx = Tx(
            vin=[TxIn(test_prevout_txid(i + key_offset), 0) for i in range(num_inputs)],
            vout=[TxOut(num_inputs * 100_000_000 - 1_000_000,
                        v2_script_pubkey(keys[0][3]))],
        )
        return keys, utxos, tx

    # 1: valid two-member half-aggregation group with explicit sighash
    # forms
    keys, utxos, tx = fresh_setup(2)
    _, sigs1, aggsig = sign_halfagg_group(
        tx, utxos, [(0, keys[0][2], SIGHASH_ALL), (1, keys[1][2], SIGHASH_ALL)]
    )
    tx.witnesses[0] = [halfagg_member(sigs1[0][:32], SIGHASH_ALL)]
    tx.witnesses[1] = [halfagg_final(aggsig, SIGHASH_ALL)]
    add_case("halfagg-valid", "Two-member half-aggregation group, SIGHASH_ALL",
             tx, utxos, True)

    # 2: valid two-member full-aggregation group
    keys, utxos, tx = fresh_setup(2, key_offset=3)
    _, _, _, sig64 = sign_fullagg_group(
        tx, utxos, [(0, keys[0][2], SIGHASH_ALL), (1, keys[1][2], SIGHASH_ALL)]
    )
    tx.witnesses[0] = [fullagg_member(SIGHASH_ALL)]
    tx.witnesses[1] = [marker_element(MARKER_FULLAGG, SIGHASH_ALL, sig64)]
    add_case("fullagg-valid", "Two-member full-aggregation group, SIGHASH_ALL",
             tx, utxos, True)
    fullagg_base = (keys, utxos, tx, sig64)

    # 3: valid mix of opted-out input and half-aggregation group
    keys, utxos, tx = fresh_setup(3, key_offset=6)
    _, sig0 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_DEFAULT)
    _, sigs3, aggsig3 = sign_halfagg_group(
        tx, utxos, [(1, keys[1][2], SIGHASH_DEFAULT), (2, keys[2][2], SIGHASH_DEFAULT)]
    )
    tx.witnesses[0] = [optout_element(sig0)]
    tx.witnesses[1] = [halfagg_member(sigs3[0][:32])]
    tx.witnesses[2] = [halfagg_final(aggsig3)]
    add_case("mixed-valid",
             "Opted-out input alongside a two-member half-aggregation group",
             tx, utxos, True)

    # 4: invalid, undefined marker byte
    keys, utxos, tx = fresh_setup(3, key_offset=6)
    tx.witnesses[0] = [sig0 + bytes([0xBB])]
    tx.witnesses[1] = [halfagg_member(sigs3[0][:32])]
    tx.witnesses[2] = [halfagg_final(aggsig3)]
    add_case("marker-undefined", "65-byte witness element ending in the "
             "undefined marker value 0xbb", tx, utxos, False,
             "undefined marker byte")

    # 5: invalid, explicit 0x00 sighash byte on a group member
    keys, utxos, tx = fresh_setup(3, key_offset=6)
    tx.witnesses[0] = [optout_element(sig0)]
    tx.witnesses[1] = [sigs3[0][:32] + bytes([0x00])]
    tx.witnesses[2] = [halfagg_final(aggsig3)]
    add_case("member-explicit-default", "Half-aggregation member encodes "
             "SIGHASH_DEFAULT explicitly as a 0x00 sighash byte",
             tx, utxos, False, "explicit 0x00 sighash byte")

    # 6: invalid, aggregation group without a final input
    keys, utxos, tx = fresh_setup(2)
    tx.witnesses[0] = [halfagg_member(sigs1[0][:32])]
    tx.witnesses[1] = [halfagg_member(sigs1[1][:32])]
    add_case("group-no-final", "Half-aggregation members without an input "
             "carrying the marker and the s value", tx, utxos, False,
             "aggregation group has no final input")

    # 7: invalid, member after the group final
    keys, utxos, tx = fresh_setup(3, key_offset=9)
    _, sigs7, aggsig7 = sign_halfagg_group(
        tx, utxos, [(0, keys[0][2], SIGHASH_DEFAULT), (1, keys[1][2], SIGHASH_DEFAULT)]
    )
    tx.witnesses[0] = [halfagg_member(sigs7[0][:32])]
    tx.witnesses[1] = [halfagg_final(aggsig7)]
    tx.witnesses[2] = [halfagg_member(sigs7[1][:32])]
    add_case("member-after-final", "Half-aggregation member appears after "
             "the group's final input", tx, utxos, False,
             "member after group final")

    # 8: invalid, 2-byte element. No defined form has two bytes.
    keys, utxos, tx = fresh_setup(2)
    _, sig1_8 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [bytes([SIGHASH_ALL, MARKER_HALFAGG])]
    tx.witnesses[1] = [optout_element(sig1_8)]
    add_case("element-length-undefined", "2-byte witness element ending in "
             "a marker byte, matching no defined structure", tx, utxos,
             False, "marker and length match no defined structure")

    # 9: invalid, cross-mode fold (mode commitment)
    # Opted-out signatures over the plain BIP 341 message are packaged
    # as a half-aggregation group. The group structure is well formed
    # but aggregate verification fails because the group messages commit
    # to the aggregation mode.
    keys, utxos, tx = fresh_setup(2, key_offset=12)
    triples = []
    for idx in range(2):
        m_optout = sigmsg_v1(tx, utxos, idx, SIGHASH_DEFAULT)
        sig = schnorr_sign(m_optout, keys[idx][2], AUX_ZERO)
        pk = utxos[idx].script_pubkey[2:]
        triples.append((pk, m_optout, sig))
    aggsig9 = halfagg.Aggregate(triples)
    consensus_msgs = [
        (utxos[i].script_pubkey[2:],
         sigmsg_v2(tx, utxos, i, SIGHASH_DEFAULT, MARKER_HALFAGG))
        for i in range(2)
    ]
    assert not halfagg.VerifyAggregate(aggsig9, consensus_msgs)
    tx.witnesses[0] = [halfagg_member(triples[0][2][:32])]
    tx.witnesses[1] = [halfagg_final(aggsig9)]
    add_case("cross-mode-fold", "Opted-out signatures folded into a "
             "half-aggregation group by a third party", tx, utxos, False,
             "aggregate signature invalid, messages commit to the "
             "aggregation mode")

    # 10: invalid, empty witness
    keys, utxos, tx = fresh_setup(2)
    _, sig1 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = []
    tx.witnesses[1] = [optout_element(sig1)]
    add_case("empty-witness", "Witness v2 input with an empty witness",
             tx, utxos, False, "empty witness")

    # 11: invalid, explicit 0x00 sighash byte on an opted-out signature.
    # Complements case 5, which covers the marked form.
    keys, utxos, tx = fresh_setup(2)
    _, sig0 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_DEFAULT)
    _, sig1 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [sig0 + bytes([0x00])]
    tx.witnesses[1] = [optout_element(sig1)]
    add_case("optout-explicit-default", "Opted-out input encodes "
             "SIGHASH_DEFAULT explicitly as a 0x00 sighash byte",
             tx, utxos, False, "explicit 0x00 sighash byte")

    # 12: valid, opted-out 64-byte signature ending in the marker byte
    # 0xbc, ground via the auxiliary randomness
    keys, utxos, tx = fresh_setup(2)
    m0 = sigmsg_v1(tx, utxos, 0, SIGHASH_DEFAULT)
    aux_i = 0
    while True:
        aux = tagged_hash("CISA/test/aux", aux_i.to_bytes(2, "little"))
        sig0 = schnorr_sign(m0, keys[0][2], aux)
        if sig0[63] == MARKER_HALFAGG:
            break
        aux_i += 1
    _, sig1 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [optout_element(sig0)]
    tx.witnesses[1] = [optout_element(sig1)]
    add_case("optout-sig-ends-in-marker", "Opted-out 64-byte signature "
             "whose last byte equals the half-aggregation marker 0xbc",
             tx, utxos, True)

    # 13: valid, half-aggregation group member carrying a signed annex
    keys, utxos, tx = fresh_setup(2, key_offset=15)
    annex = bytes([0x50]) + b"CISA annex test"
    m0 = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG, annex=annex)
    m1 = sigmsg_v2(tx, utxos, 1, SIGHASH_DEFAULT, MARKER_HALFAGG)
    pk0 = utxos[0].script_pubkey[2:]
    pk1 = utxos[1].script_pubkey[2:]
    sig0 = schnorr_sign(m0, keys[0][2], AUX_ZERO)
    sig1 = schnorr_sign(m1, keys[1][2], AUX_ZERO)
    aggsig_annex = halfagg.Aggregate([(pk0, m0, sig0), (pk1, m1, sig1)])
    assert halfagg.VerifyAggregate(aggsig_annex, [(pk0, m0), (pk1, m1)])
    tx.witnesses[0] = [halfagg_member(sig0[:32]), annex]
    tx.witnesses[1] = [halfagg_final(aggsig_annex)]
    add_case("annex-committed-valid", "Half-aggregation group whose first "
             "member carries an annex that is committed in its signature "
             "message", tx, utxos, True)

    # 14: invalid, annex stripped from the transaction of case 13
    keys, utxos, tx = fresh_setup(2, key_offset=15)
    m0_stripped = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG)
    assert not halfagg.VerifyAggregate(
        aggsig_annex, [(pk0, m0_stripped), (pk1, m1)]
    )
    tx.witnesses[0] = [halfagg_member(sig0[:32])]
    tx.witnesses[1] = [halfagg_final(aggsig_annex)]
    add_case("annex-stripped", "Annex removed by a third party from the "
             "transaction of annex-committed-valid", tx, utxos, False,
             "signature message committed to the annex")

    # 15: valid, witness v2 script path spend (BIP 341/342 rules unchanged)
    script_seckey = test_seckey(20)
    script_pk = (Scalar.from_bytes_checked(script_seckey) * G).to_bytes_xonly()
    script = bytes([0x20]) + script_pk + bytes([0xAC])  # <pk> OP_CHECKSIG
    tapleaf_hash = tagged_hash(
        "TapLeaf", bytes([0xC0]) + ser_compact_size(len(script)) + script
    )
    internal_seckey = test_seckey(21)
    d0 = Scalar.from_bytes_checked(internal_seckey)
    P_int = d0 * G
    internal_x = P_int.to_bytes_xonly()
    t = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal_x + tapleaf_hash))
    Q = GE.from_bytes_xonly(internal_x) + t * G
    control = bytes([0xC0 | (0 if Q.has_even_y() else 1)]) + internal_x
    keys, utxos, tx = fresh_setup(2, key_offset=18)
    utxos[0] = TxOut(100_000_000, v2_script_pubkey(Q.to_bytes_xonly()))
    m_script = sigmsg_tapscript(tx, utxos, 0, SIGHASH_DEFAULT, tapleaf_hash)
    sig_script = schnorr_sign(m_script, script_seckey, AUX_ZERO)
    assert schnorr_verify(m_script, script_pk, sig_script)
    _, sig1 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [sig_script, script, control]
    tx.witnesses[1] = [optout_element(sig1)]
    add_case("scriptpath-valid", "Witness v2 script path spend of a single "
             "CHECKSIG leaf under BIP 341/342 rules, alongside an opted-out "
             "key path input", tx, utxos, True)

    # 16: invalid, cross-mode messages in a full-aggregation group
    # The signers run a full-aggregation session over plain BIP 341
    # messages and the result is placed in a 0xbd witness. Unlike case 9
    # there is no public fold operation for full-agg, this checks that
    # verifiers derive the messages with the 0xbd marker on this path too.
    keys, utxos, tx = fresh_setup(2, key_offset=22)
    _, _, _, sig64_16 = sign_fullagg_group(
        tx, utxos,
        [(0, keys[0][2], SIGHASH_DEFAULT), (1, keys[1][2], SIGHASH_DEFAULT)],
        msg_mode=None,
    )
    pks16 = [GE.from_bytes_xonly(u.script_pubkey[2:]) for u in utxos]
    consensus_msgs16 = [
        sigmsg_v2(tx, utxos, i, SIGHASH_DEFAULT, MARKER_FULLAGG) for i in range(2)
    ]
    R16 = GE.from_bytes_xonly(sig64_16[:32])
    s16 = Scalar.from_bytes_checked(sig64_16[32:])
    assert not fullagg.Verify(pks16, consensus_msgs16, (R16, s16))
    tx.witnesses[0] = [fullagg_member()]
    tx.witnesses[1] = [marker_element(MARKER_FULLAGG, sig=sig64_16)]
    add_case("cross-mode-fullagg", "Full-aggregation signature created over "
             "plain BIP 341 messages, placed in a full-aggregation group",
             tx, utxos, False,
             "aggregate signature invalid, messages commit to the "
             "aggregation mode")

    # 17: invalid, 97-byte 0xbd element. Marker 0xbd admits lengths 65
    # and 66 only, so parsing fails in pass 1 regardless of the content.
    # fresh_setup(2, key_offset=3) recreates the transaction from case 2
    # deterministically, so the aggregate signature from that case
    # corresponds to this tx.
    _, _, _, sig64 = fullagg_base
    keys, utxos, tx = fresh_setup(2, key_offset=3)
    tx.witnesses[0] = [fullagg_member(SIGHASH_ALL)]
    tx.witnesses[1] = [marker_element(MARKER_FULLAGG, sig=sig64 + bytes(32))]
    add_case("fullagg-size-mismatch", "Full-aggregation final input carries "
             "96 bytes before the marker (97-byte 0xbd element, matches no "
             "defined witness structure)", tx, utxos, False,
             "marker and length match no defined structure")

    # 18: valid, mixed transaction mirroring Example 4 of the BIP: two
    # opted-out inputs with explicit sighash types, a half-aggregation
    # group and a full-aggregation group with interleaved indices. Also
    # covers a valid SIGHASH_SINGLE member with a corresponding output.
    keys, utxos, tx = fresh_setup(7, key_offset=24)
    tx.vout = [
        TxOut(350_000_000, v2_script_pubkey(keys[0][3])),
        TxOut(349_000_000, v2_script_pubkey(keys[1][3])),
    ]
    _, sig0 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_DEFAULT)
    _, sig5 = sign_optout(tx, utxos, 5, keys[5][2],
                          SIGHASH_NONE | SIGHASH_ANYONECANPAY)
    _, sigs18, aggsig18 = sign_halfagg_group(
        tx, utxos,
        [(1, keys[1][2], SIGHASH_SINGLE), (4, keys[4][2], SIGHASH_DEFAULT)],
    )
    _, _, _, sig64_18 = sign_fullagg_group(
        tx, utxos,
        [(2, keys[2][2], SIGHASH_DEFAULT), (3, keys[3][2], SIGHASH_DEFAULT),
         (6, keys[6][2], SIGHASH_DEFAULT)],
    )
    tx.witnesses[0] = [optout_element(sig0)]
    tx.witnesses[1] = [halfagg_member(sigs18[0][:32], SIGHASH_SINGLE)]
    tx.witnesses[2] = [fullagg_member()]
    tx.witnesses[3] = [fullagg_member()]
    tx.witnesses[4] = [halfagg_final(aggsig18)]
    tx.witnesses[5] = [optout_element(sig5,
                                      SIGHASH_NONE | SIGHASH_ANYONECANPAY)]
    tx.witnesses[6] = [marker_element(MARKER_FULLAGG, sig=sig64_18)]
    add_case("two-groups-valid", "Mixed transaction mirroring Example 4 of "
             "the BIP: two opted-out inputs, a half-aggregation group with "
             "a SIGHASH_SINGLE member, and a full-aggregation group, with "
             "interleaved input indices", tx, utxos, True)

    # 19: invalid, SIGHASH_SINGLE without a corresponding output. Input 1
    # signals SIGHASH_SINGLE but the transaction has only one output, so
    # computing SigMsg fails per the BIP 341 failure conditions, which are
    # incorporated by reference. The witness is structurally well formed
    # and carries a syntactically valid signature (created over the
    # SIGHASH_ALL flavored message), so the only reason for rejection is
    # the missing corresponding output.
    keys, utxos, tx = fresh_setup(2, key_offset=31)
    _, sig0 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_DEFAULT)
    m_all = sigmsg_v1(tx, utxos, 1, SIGHASH_ALL)
    sig1_19 = schnorr_sign(m_all, keys[1][2], AUX_ZERO)
    tx.witnesses[0] = [optout_element(sig0)]
    tx.witnesses[1] = [optout_element(sig1_19, SIGHASH_SINGLE)]
    add_case("sighash-single-no-output", "Opted-out input uses "
             "SIGHASH_SINGLE at input index 1 of a single-output "
             "transaction", tx, utxos, False,
             "SIGHASH_SINGLE input without corresponding output")

    # 20: invalid, two final inputs in one half-aggregation group. Each
    # element carries a valid single-member final, so the failure is
    # purely structural. Distinct from case 7, where the element after
    # the final is a member.
    keys, utxos, tx = fresh_setup(2, key_offset=34)
    _, _, agg_a = sign_halfagg_group(tx, utxos, [(0, keys[0][2], SIGHASH_DEFAULT)])
    _, _, agg_b = sign_halfagg_group(tx, utxos, [(1, keys[1][2], SIGHASH_DEFAULT)])
    tx.witnesses[0] = [halfagg_final(agg_a)]
    tx.witnesses[1] = [halfagg_final(agg_b)]
    add_case("halfagg-two-finals", "Two inputs each carrying a 65-byte "
             "half-aggregation final element", tx, utxos, False,
             "more than one final input in a group")

    # 21: invalid, two final inputs in one full-aggregation group
    keys, utxos, tx = fresh_setup(2, key_offset=36)
    _, _, _, sig_a = sign_fullagg_group(
        tx, utxos, [(0, keys[0][2], SIGHASH_DEFAULT)], nonce_offset=10)
    _, _, _, sig_b = sign_fullagg_group(
        tx, utxos, [(1, keys[1][2], SIGHASH_DEFAULT)], nonce_offset=11)
    tx.witnesses[0] = [marker_element(MARKER_FULLAGG, sig=sig_a)]
    tx.witnesses[1] = [marker_element(MARKER_FULLAGG, sig=sig_b)]
    add_case("fullagg-two-finals", "Two inputs each carrying a 65-byte "
             "full-aggregation final element", tx, utxos, False,
             "more than one final input in a group")

    # 22: invalid, full-aggregation members without a final input
    # (full-agg analog of case 6)
    keys, utxos, tx = fresh_setup(2, key_offset=38)
    tx.witnesses[0] = [fullagg_member()]
    tx.witnesses[1] = [fullagg_member()]
    add_case("fullagg-no-final", "Full-aggregation members without an input "
             "carrying the marker and the aggregate signature", tx, utxos,
             False, "aggregation group has no final input")

    # 23: invalid, full-agg member after the final
    # (full-agg analog of case 7)
    keys, utxos, tx = fresh_setup(3, key_offset=40)
    _, _, _, sig64_23 = sign_fullagg_group(
        tx, utxos,
        [(0, keys[0][2], SIGHASH_DEFAULT), (1, keys[1][2], SIGHASH_DEFAULT)],
        nonce_offset=12)
    tx.witnesses[0] = [fullagg_member()]
    tx.witnesses[1] = [marker_element(MARKER_FULLAGG, sig=sig64_23)]
    tx.witnesses[2] = [fullagg_member()]
    add_case("fullagg-member-after-final", "Full-aggregation member appears "
             "after the group's final input", tx, utxos, False,
             "member after group final")

    # 24: valid, single-member half-aggregation group. The 65-byte
    # element matches an explicit sighash opted-out signature in length
    # and is distinguished by its 0xbc last byte.
    keys, utxos, tx = fresh_setup(1, key_offset=43)
    _, _, aggsig24 = sign_halfagg_group(
        tx, utxos, [(0, keys[0][2], SIGHASH_DEFAULT)])
    tx.witnesses[0] = [halfagg_final(aggsig24)]
    add_case("halfagg-single-member", "Half-aggregation group with a single "
             "member carrying a 64-byte aggregate in a 65-byte element",
             tx, utxos, True)

    # 25: valid, single-member full-aggregation group
    keys, utxos, tx = fresh_setup(1, key_offset=44)
    _, _, _, sig64_25 = sign_fullagg_group(
        tx, utxos, [(0, keys[0][2], SIGHASH_DEFAULT)], nonce_offset=13)
    tx.witnesses[0] = [marker_element(MARKER_FULLAGG, sig=sig64_25)]
    add_case("fullagg-single-member", "Full-aggregation group with a single "
             "member", tx, utxos, True)

    # 26: invalid, single witness element starting with the annex prefix.
    # An annex requires at least two witness elements, so this parses as
    # a key path element that matches no defined structure.
    keys, utxos, tx = fresh_setup(2, key_offset=45)
    _, sig1_26 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [bytes([0x50]) + b"CISA annex test"]
    tx.witnesses[1] = [optout_element(sig1_26)]
    add_case("annex-lookalike", "Single witness element starting with the "
             "annex prefix 0x50", tx, utxos, False,
             "matches no defined structure, a single element is never "
             "an annex")

    # 27: valid, annex on the final input of a group. The annex must be
    # stripped before the final element is interpreted. Complements case
    # 13, which has the annex on a member input.
    keys, utxos, tx = fresh_setup(2, key_offset=47)
    annex27 = bytes([0x50]) + b"CISA annex test"
    m0_27 = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG)
    m1_27 = sigmsg_v2(tx, utxos, 1, SIGHASH_DEFAULT, MARKER_HALFAGG,
                      annex=annex27)
    pk0 = utxos[0].script_pubkey[2:]
    pk1 = utxos[1].script_pubkey[2:]
    sig0_27 = schnorr_sign(m0_27, keys[0][2], AUX_ZERO)
    sig1_27 = schnorr_sign(m1_27, keys[1][2], AUX_ZERO)
    agg27 = halfagg.Aggregate([(pk0, m0_27, sig0_27), (pk1, m1_27, sig1_27)])
    assert halfagg.VerifyAggregate(agg27, [(pk0, m0_27), (pk1, m1_27)])
    tx.witnesses[0] = [halfagg_member(sig0_27[:32])]
    tx.witnesses[1] = [halfagg_final(agg27), annex27]
    add_case("annex-on-final", "Half-aggregation group whose final input "
             "carries an annex that is committed in its signature message",
             tx, utxos, True)

    # 28: invalid, undefined sighash value. Cases 5 and 11 cover the
    # explicit 0x00 encoding rule, this covers a value outside the
    # defined set. The signature bytes are irrelevant, parsing fails
    # first.
    keys, utxos, tx = fresh_setup(2, key_offset=49)
    m0_28 = sigmsg_v1(tx, utxos, 0, SIGHASH_DEFAULT)
    sig0_28 = schnorr_sign(m0_28, keys[0][2], AUX_ZERO)
    _, sig1_28 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [sig0_28 + bytes([0x04])]
    tx.witnesses[1] = [optout_element(sig1_28)]
    add_case("sighash-value-undefined", "Opted-out input with the undefined "
             "sighash value 0x04", tx, utxos, False,
             "undefined sighash type")

    # 29: invalid, 33-byte element ending in 0xbc. It parses as a
    # half-aggregation member whose sighash byte is the marker value,
    # which is not a valid sighash type.
    keys, utxos, tx = fresh_setup(2, key_offset=51)
    _, sig0_29 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_DEFAULT)
    _, _, agg29 = sign_halfagg_group(
        tx, utxos, [(1, keys[1][2], SIGHASH_DEFAULT)])
    tx.witnesses[0] = [optout_element(sig0_29)]
    tx.witnesses[1] = [agg29[:32] + bytes([MARKER_HALFAGG])]
    add_case("member-sighash-is-marker", "33-byte element ending in the "
             "marker 0xbc, a half-aggregation member with an invalid "
             "sighash byte", tx, utxos, False, "undefined sighash type")

    # 30: valid, witness v2 output whose witness program is not 32 bytes.
    # Such outputs remain unencumbered by the BIP, so the witness content
    # is unconstrained, even an undefined marker byte.
    keys, utxos, tx = fresh_setup(2, key_offset=53)
    program33 = test_garbage(b"33-byte program", 33)
    utxos[0] = TxOut(100_000_000, bytes([0x52, 0x21]) + program33)
    _, sig1_30 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [bytes([0xBE])]
    tx.witnesses[1] = [optout_element(sig1_30)]
    add_case("program-not-32-bytes", "Witness v2 output with a 33-byte "
             "witness program spent with an arbitrary witness", tx, utxos,
             True)

    # 31: invalid, opted-out witness program is not a valid x coordinate.
    # BIP 340 verification fails at lift_x.
    keys, utxos, tx = fresh_setup(2, key_offset=55)
    utxos[0] = TxOut(100_000_000,
                     bytes([0x52, 0x20]) + test_offcurve_x(b"optout"))
    _, sig1_31 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [optout_element(test_garbage(b"offcurve sig", 64))]
    tx.witnesses[1] = [optout_element(sig1_31)]
    add_case("program-offcurve-optout", "Opted-out input whose witness "
             "program is not a valid x-only public key", tx, utxos, False,
             "witness program is not a valid x-only public key")

    # 32: invalid, group member witness program is not a valid x
    # coordinate. VerifyAggregate fails at lift_x of the first pubkey, so
    # the aggregate content is irrelevant.
    keys, utxos, tx = fresh_setup(2, key_offset=57)
    utxos[0] = TxOut(100_000_000,
                     bytes([0x52, 0x20]) + test_offcurve_x(b"group"))
    m1_32 = sigmsg_v2(tx, utxos, 1, SIGHASH_DEFAULT, MARKER_HALFAGG)
    sig1_32 = schnorr_sign(m1_32, keys[1][2], AUX_ZERO)
    agg32 = test_garbage(b"offcurve r0", 32) + sig1_32
    assert not halfagg.VerifyAggregate(agg32, [
        (utxos[0].script_pubkey[2:],
         sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG)),
        (utxos[1].script_pubkey[2:], m1_32),
    ])
    tx.witnesses[0] = [halfagg_member(agg32[:32])]
    tx.witnesses[1] = [halfagg_final(agg32)]
    add_case("program-offcurve-in-group", "Half-aggregation group member "
             "whose witness program is not a valid x-only public key",
             tx, utxos, False,
             "witness program is not a valid x-only public key")

    # 33: valid, script path spend with an unknown leaf version (0xc2).
    # Unknown leaf versions succeed unconditionally under BIP 341,
    # preserving the upgrade hook in witness v2.
    keys, utxos, tx = fresh_setup(2, key_offset=59)
    internal_seckey33 = test_seckey(200)
    internal_x33 = (Scalar.from_bytes_checked(internal_seckey33) * G).to_bytes_xonly()
    script33 = bytes([0x51])
    leaf33 = tagged_hash(
        "TapLeaf", bytes([0xC2]) + ser_compact_size(len(script33)) + script33)
    t33 = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal_x33 + leaf33))
    Q33 = GE.from_bytes_xonly(internal_x33) + t33 * G
    control33 = bytes([0xC2 | (0 if Q33.has_even_y() else 1)]) + internal_x33
    utxos[0] = TxOut(100_000_000, v2_script_pubkey(Q33.to_bytes_xonly()))
    _, sig1_33 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [script33, control33]
    tx.witnesses[1] = [optout_element(sig1_33)]
    add_case("scriptpath-unknown-leaf-version", "Witness v2 script path "
             "spend with unknown leaf version 0xc2, which succeeds "
             "unconditionally per BIP 341", tx, utxos, True)

    # 34: valid, script path leaf containing an OP_SUCCESS opcode. The
    # script byte 0xbc is OP_SUCCESS188 in tapscript and has no marker
    # meaning inside a script.
    keys, utxos, tx = fresh_setup(2, key_offset=61)
    internal_seckey34 = test_seckey(201)
    internal_x34 = (Scalar.from_bytes_checked(internal_seckey34) * G).to_bytes_xonly()
    script34 = bytes([MARKER_HALFAGG])
    leaf34 = tagged_hash(
        "TapLeaf", bytes([0xC0]) + ser_compact_size(len(script34)) + script34)
    t34 = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal_x34 + leaf34))
    Q34 = GE.from_bytes_xonly(internal_x34) + t34 * G
    control34 = bytes([0xC0 | (0 if Q34.has_even_y() else 1)]) + internal_x34
    utxos[0] = TxOut(100_000_000, v2_script_pubkey(Q34.to_bytes_xonly()))
    _, sig1_34 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [script34, control34]
    tx.witnesses[1] = [optout_element(sig1_34)]
    add_case("scriptpath-op-success", "Witness v2 script path spend whose "
             "leaf script is OP_SUCCESS188 (byte 0xbc), which succeeds "
             "unconditionally per BIP 342", tx, utxos, True)

    # 35: valid, mixed witness v1 and v2 transaction mirroring Example 3
    # of the BIP. Input 0 spends a taproot output with an unchanged
    # BIP 341 key path signature (epoch 0x00, no marker).
    keys, utxos, tx = fresh_setup(3, key_offset=63)
    utxos[0] = TxOut(100_000_000, bytes([0x51, 0x20]) + keys[0][3])
    m0_35 = sigmsg_v1(tx, utxos, 0, SIGHASH_DEFAULT)
    sig0_35 = schnorr_sign(m0_35, keys[0][2], AUX_ZERO)
    _, sigs35, agg35 = sign_halfagg_group(
        tx, utxos,
        [(1, keys[1][2], SIGHASH_DEFAULT), (2, keys[2][2], SIGHASH_DEFAULT)])
    tx.witnesses[0] = [sig0_35]
    tx.witnesses[1] = [halfagg_member(sigs35[0][:32])]
    tx.witnesses[2] = [halfagg_final(agg35)]
    add_case("v1-v2-mixed", "Witness v1 key path input alongside a "
             "two-member witness v2 half-aggregation group, mirroring "
             "Example 3 of the BIP", tx, utxos, True)

    # 36: invalid, explicit sighash byte stripped by a third party. Input
    # 0 signed with explicit SIGHASH_ALL, the witness is malleated to the
    # 32-byte form, so the verifier derives the SIGHASH_DEFAULT flavored
    # message. Complements case 14, which strips the annex.
    keys, utxos, tx = fresh_setup(2, key_offset=66)
    msgs36, sigs36, agg36 = sign_halfagg_group(
        tx, utxos,
        [(0, keys[0][2], SIGHASH_ALL), (1, keys[1][2], SIGHASH_DEFAULT)])
    m0_default = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG)
    assert not halfagg.VerifyAggregate(agg36, [
        (utxos[0].script_pubkey[2:], m0_default),
        (utxos[1].script_pubkey[2:], msgs36[1]),
    ])
    tx.witnesses[0] = [halfagg_member(sigs36[0][:32])]
    tx.witnesses[1] = [halfagg_final(agg36)]
    add_case("sighash-byte-stripped", "Explicit SIGHASH_ALL byte removed "
             "from a group member by a third party", tx, utxos, False,
             "signature message committed to the sighash type")

    # 37: invalid, single empty witness element. It parses as a
    # full-aggregation member and the group has no final input. Distinct
    # from case 10, where the witness stack itself is empty.
    keys, utxos, tx = fresh_setup(2, key_offset=68)
    _, sig1_37 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [b""]
    tx.witnesses[1] = [optout_element(sig1_37)]
    add_case("empty-element-no-final", "Witness v2 input whose only witness "
             "element is empty, a full-aggregation member without a final "
             "input", tx, utxos, False,
             "aggregation group has no final input")

    # 38: invalid, SIGHASH_SINGLE group member without a corresponding
    # output. Complements case 19, which covers the opted-out path. The
    # witness is structurally well formed (66-byte final element) and
    # the signature bytes are created over the SIGHASH_ALL flavored
    # message, so the only reason for rejection is the missing output.
    keys, utxos, tx = fresh_setup(2, key_offset=70)
    pk0 = utxos[0].script_pubkey[2:]
    pk1 = utxos[1].script_pubkey[2:]
    m0_38 = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG)
    m1_38 = sigmsg_v2(tx, utxos, 1, SIGHASH_ALL, MARKER_HALFAGG)
    sig0_38 = schnorr_sign(m0_38, keys[0][2], AUX_ZERO)
    sig1_38 = schnorr_sign(m1_38, keys[1][2], AUX_ZERO)
    agg38 = halfagg.Aggregate([(pk0, m0_38, sig0_38), (pk1, m1_38, sig1_38)])
    tx.witnesses[0] = [halfagg_member(sig0_38[:32])]
    tx.witnesses[1] = [halfagg_final(agg38, SIGHASH_SINGLE)]
    add_case("sighash-single-no-output-group", "Half-aggregation group "
             "member uses SIGHASH_SINGLE at input index 1 of a "
             "single-output transaction", tx, utxos, False,
             "SIGHASH_SINGLE input without corresponding output")

    # 39: invalid, two witness elements where the last is not an annex.
    # With two elements and no annex prefix this is a script path spend,
    # and the 1-byte last element is not a valid control block.
    keys, utxos, tx = fresh_setup(2, key_offset=72)
    m0_39 = sigmsg_v1(tx, utxos, 0, SIGHASH_DEFAULT)
    sig0_39 = schnorr_sign(m0_39, keys[0][2], AUX_ZERO)
    _, sig1_39 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [sig0_39, bytes([0x60])]
    tx.witnesses[1] = [optout_element(sig1_39)]
    add_case("two-elements-no-annex", "Keypath-looking element followed by "
             "a second element that is not an annex, making this a script "
             "path spend with an invalid control block", tx, utxos, False,
             "invalid control block size")

    # 40: invalid, half-aggregation flavored signature placed as a bare
    # 64-byte opted-out element
    keys, utxos, tx = fresh_setup(2, key_offset=74)
    m0_agg = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG)
    sig0_40 = schnorr_sign(m0_agg, keys[0][2], AUX_ZERO)
    m0_plain = sigmsg_v1(tx, utxos, 0, SIGHASH_DEFAULT)
    assert not schnorr_verify(m0_plain, utxos[0].script_pubkey[2:], sig0_40)
    _, sig1_40 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [optout_element(sig0_40)]
    tx.witnesses[1] = [optout_element(sig1_40)]
    add_case("agg-mode-sig-as-optout", "Signature created over the "
             "half-aggregation flavored message used as a bare opted-out "
             "signature", tx, utxos, False,
             "signature invalid, message commits to the aggregation mode")

    # 41: valid, 8-member half-aggregation group, exercising the nonce
    # share assembly across many inputs
    keys, utxos, tx = fresh_setup(8, key_offset=76)
    members41 = [(i, keys[i][2], SIGHASH_DEFAULT) for i in range(8)]
    _, sigs41, agg41 = sign_halfagg_group(tx, utxos, members41)
    for i in range(7):
        tx.witnesses[i] = [halfagg_member(sigs41[i][:32])]
    tx.witnesses[7] = [halfagg_final(agg41)]
    add_case("halfagg-large-group", "8-member half-aggregation group",
             tx, utxos, True)

    # 42: valid, script path spend whose first stack element is a 1-byte
    # 0xbc marker lookalike. With three witness elements this is a script
    # path spend, so marker interpretation does not apply. The leaf
    # script drops the element and pushes true.
    keys, utxos, tx = fresh_setup(2, key_offset=84)
    internal_seckey42 = test_seckey(202)
    internal_x42 = (Scalar.from_bytes_checked(internal_seckey42) * G).to_bytes_xonly()
    script42 = bytes([0x75, 0x51])  # OP_DROP OP_1
    leaf42 = tagged_hash(
        "TapLeaf", bytes([0xC0]) + ser_compact_size(len(script42)) + script42)
    t42 = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal_x42 + leaf42))
    Q42 = GE.from_bytes_xonly(internal_x42) + t42 * G
    control42 = bytes([0xC0 | (0 if Q42.has_even_y() else 1)]) + internal_x42
    utxos[0] = TxOut(100_000_000, v2_script_pubkey(Q42.to_bytes_xonly()))
    _, sig1_42 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [bytes([MARKER_HALFAGG]), script42, control42]
    tx.witnesses[1] = [optout_element(sig1_42)]
    add_case("scriptpath-marker-lookalike", "Script path spend whose first "
             "stack element is a 1-byte 0xbc marker lookalike, which has "
             "no marker meaning outside key path spends", tx, utxos, True)

    # 43: valid, both group members spend outputs with the same witness
    # program (address reuse). The messages differ by input index and
    # neither scheme deduplicates keys.
    keys, utxos, tx = fresh_setup(4, key_offset=86)
    utxos[1] = TxOut(100_000_000, v2_script_pubkey(keys[0][3]))
    utxos[3] = TxOut(100_000_000, v2_script_pubkey(keys[2][3]))
    _, sigs43, agg43 = sign_halfagg_group(
        tx, utxos,
        [(0, keys[0][2], SIGHASH_DEFAULT), (1, keys[0][2], SIGHASH_DEFAULT)])
    _, _, _, sig64_43 = sign_fullagg_group(
        tx, utxos,
        [(2, keys[2][2], SIGHASH_DEFAULT), (3, keys[2][2], SIGHASH_DEFAULT)],
        nonce_offset=20)
    tx.witnesses[0] = [halfagg_member(sigs43[0][:32])]
    tx.witnesses[1] = [halfagg_final(agg43)]
    tx.witnesses[2] = [fullagg_member()]
    tx.witnesses[3] = [marker_element(MARKER_FULLAGG, sig=sig64_43)]
    add_case("duplicate-key-groups", "Half-aggregation and full-aggregation "
             "groups whose two members each spend outputs with the same "
             "witness program (address reuse)", tx, utxos, True)

    # 44: invalid, ANYONECANPAY signature for the same output key created
    # as if spending the v1 scriptPubKey, replayed on the witness v2
    # input. Fails because the message commits to the spent scriptPubKey.
    keys, utxos, tx = fresh_setup(2, key_offset=90)
    utxos_v1 = list(utxos)
    utxos_v1[0] = TxOut(utxos[0].amount, bytes([0x51, 0x20]) + keys[0][3])
    ht44 = SIGHASH_ALL | SIGHASH_ANYONECANPAY
    m0_v1spk = sigmsg_v1(tx, utxos_v1, 0, ht44)
    sig0_44 = schnorr_sign(m0_v1spk, keys[0][2], AUX_ZERO)
    m0_v2spk = sigmsg_v1(tx, utxos, 0, ht44)
    assert not schnorr_verify(m0_v2spk, keys[0][3], sig0_44)
    _, sig1_44 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [optout_element(sig0_44, ht44)]
    tx.witnesses[1] = [optout_element(sig1_44)]
    add_case("v1-replay", "BIP 341 key path signature created for a "
             "witness v1 output with the same output key, replayed on a "
             "witness v2 input", tx, utxos, False,
             "signature message commits to the spent scriptPubKey")

    # 45: invalid, undefined sighash value on a 1-byte full-aggregation
    # member, complementing case 28 for the member forms. The aggregate
    # covers the matching messages, so only the sighash validation fails.
    keys, utxos, tx = fresh_setup(3, key_offset=92)
    _, sig0_45 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_DEFAULT)
    _, _, _, sig64_45 = sign_fullagg_group(
        tx, utxos, [(1, keys[1][2], 0x04), (2, keys[2][2], SIGHASH_DEFAULT)],
        nonce_offset=21)
    tx.witnesses[0] = [optout_element(sig0_45)]
    tx.witnesses[1] = [fullagg_member(0x04)]
    tx.witnesses[2] = [marker_element(MARKER_FULLAGG, sig=sig64_45)]
    add_case("member-sighash-undefined", "Full-aggregation member with the "
             "undefined sighash value 0x04", tx, utxos, False,
             "undefined sighash type")

    # 46: invalid, 97-byte 0xbc element carrying the whole aggregate
    # signature on the final input, the encoding of an earlier revision
    # of this BIP. Half-agg analog of case 17.
    keys, utxos, tx = fresh_setup(2, key_offset=95)
    _, sigs46, agg46 = sign_halfagg_group(
        tx, utxos,
        [(0, keys[0][2], SIGHASH_DEFAULT), (1, keys[1][2], SIGHASH_DEFAULT)])
    tx.witnesses[0] = [halfagg_member(sigs46[0][:32])]
    tx.witnesses[1] = [marker_element(MARKER_HALFAGG, sig=agg46)]
    add_case("halfagg-final-old-format", "97-byte 0xbc element carrying the "
             "whole aggregate signature, the final input encoding of an "
             "earlier revision", tx, utxos, False,
             "marker and length match no defined structure")

    # 47: valid, half-aggregation member with SIGHASH_ALL|ANYONECANPAY,
    # covering the per-input commitment branch of SigMsg in an
    # aggregation flavored message
    keys, utxos, tx = fresh_setup(2, key_offset=97)
    ht47 = SIGHASH_ALL | SIGHASH_ANYONECANPAY
    _, sigs47, agg47 = sign_halfagg_group(
        tx, utxos, [(0, keys[0][2], ht47), (1, keys[1][2], SIGHASH_DEFAULT)]
    )
    tx.witnesses[0] = [halfagg_member(sigs47[0][:32], ht47)]
    tx.witnesses[1] = [halfagg_final(agg47)]
    add_case("halfagg-acp-member", "Half-aggregation group with a "
             "SIGHASH_ALL|SIGHASH_ANYONECANPAY member", tx, utxos, True)

    # 48: invalid, marker of the full-aggregation final from case 25
    # flipped to 0xbc by a third party, which parses as a half-aggregation
    # final of the correct size. Fails because the message commits to the
    # marker. fresh_setup(1, key_offset=44) recreates the case 25 tx.
    keys, utxos, tx = fresh_setup(1, key_offset=44)
    m0_48 = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_HALFAGG)
    assert not halfagg.VerifyAggregate(
        sig64_25, [(utxos[0].script_pubkey[2:], m0_48)])
    tx.witnesses[0] = [marker_element(MARKER_HALFAGG, sig=sig64_25)]
    add_case("marker-swapped-fullagg", "Full-aggregation final of a "
             "single-member group mutated to carry the half-aggregation "
             "marker", tx, utxos, False,
             "aggregate signature invalid, messages commit to the "
             "aggregation mode")

    # 49: valid, annex on an empty full-aggregation member element.
    # Complements cases 13 and 27 for the empty element form.
    keys, utxos, tx = fresh_setup(2, key_offset=99)
    annex49 = bytes([0x50]) + b"CISA annex test"
    _, _, _, sig64_49 = sign_fullagg_group(
        tx, utxos,
        [(0, keys[0][2], SIGHASH_DEFAULT), (1, keys[1][2], SIGHASH_DEFAULT)],
        nonce_offset=22, annexes={0: annex49})
    tx.witnesses[0] = [fullagg_member(), annex49]
    tx.witnesses[1] = [marker_element(MARKER_FULLAGG, sig=sig64_49)]
    add_case("annex-on-empty-member", "Full-aggregation member carrying an "
             "annex on an empty witness element, committed in its signature "
             "message", tx, utxos, True)

    # 50: invalid, nonce shares swapped between the two inputs by a third
    # party. The randomizers of the aggregate commit to the shares in
    # input order, so verification fails.
    keys, utxos, tx = fresh_setup(2, key_offset=101)
    _, sigs50, agg50 = sign_halfagg_group(
        tx, utxos,
        [(0, keys[0][2], SIGHASH_DEFAULT), (1, keys[1][2], SIGHASH_DEFAULT)])
    swapped = sigs50[1][:32] + sigs50[0][:32] + agg50[-32:]
    msgs50 = [(utxos[i].script_pubkey[2:],
               sigmsg_v2(tx, utxos, i, SIGHASH_DEFAULT, MARKER_HALFAGG))
              for i in range(2)]
    assert not halfagg.VerifyAggregate(swapped, msgs50)
    tx.witnesses[0] = [halfagg_member(sigs50[1][:32])]
    tx.witnesses[1] = [halfagg_final(swapped)]
    add_case("nonce-shares-swapped", "Nonce shares of the two "
             "half-aggregation inputs swapped by a third party", tx, utxos,
             False, "aggregate signature invalid, the randomizers commit "
             "to the shares in input order")

    # 51: invalid, 66-byte element ending in a valid sighash byte.
    # 66-byte elements must end in a marker, there is no 66-byte
    # opted-out form.
    keys, utxos, tx = fresh_setup(2, key_offset=103)
    _, sig0_51 = sign_optout(tx, utxos, 0, keys[0][2], SIGHASH_ALL)
    _, sig1_51 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [sig0_51 + bytes([SIGHASH_ALL, SIGHASH_ALL])]
    tx.witnesses[1] = [optout_element(sig1_51)]
    add_case("optout-too-long", "66-byte element ending in a valid sighash "
             "byte, one byte above the opted-out maximum", tx, utxos, False,
             "marker and length match no defined structure")

    # 52: invalid, 1-byte element containing only the marker value. It
    # parses as a full-aggregation member with an invalid sighash byte.
    # In an earlier revision this was a valid placeholder form.
    keys, utxos, tx = fresh_setup(2, key_offset=105)
    _, sig1_52 = sign_optout(tx, utxos, 1, keys[1][2], SIGHASH_DEFAULT)
    tx.witnesses[0] = [bytes([MARKER_HALFAGG])]
    tx.witnesses[1] = [optout_element(sig1_52)]
    add_case("member-marker-only", "1-byte element containing only the "
             "marker value 0xbc, a full-aggregation member with an invalid "
             "sighash byte", tx, utxos, False, "undefined sighash type")

    # 53: invalid, marker of the half-aggregation final from case 24
    # flipped to 0xbd by a third party, the mirror of case 48.
    # fresh_setup(1, key_offset=43) recreates the case 24 tx.
    keys, utxos, tx = fresh_setup(1, key_offset=43)
    m0_53 = sigmsg_v2(tx, utxos, 0, SIGHASH_DEFAULT, MARKER_FULLAGG)
    R53 = GE.from_bytes_xonly(aggsig24[:32])
    s53 = Scalar.from_bytes_checked(aggsig24[32:])
    assert not fullagg.Verify(
        [GE.from_bytes_xonly(utxos[0].script_pubkey[2:])], [m0_53],
        (R53, s53))
    tx.witnesses[0] = [marker_element(MARKER_FULLAGG, sig=aggsig24)]
    add_case("marker-swapped-halfagg", "Half-aggregation final of a "
             "single-member group mutated to carry the full-aggregation "
             "marker", tx, utxos, False,
             "aggregate signature invalid, messages commit to the "
             "aggregation mode")

    return {"testCases": cases}


def main():
    out_dir = Path(__file__).parent
    wallet = make_wallet_vectors()
    consensus = make_consensus_vectors()
    with open(out_dir / "wallet-test-vectors.json", "w") as f:
        json.dump(wallet, f, indent=2)
        f.write("\n")
    with open(out_dir / "consensus-test-vectors.json", "w") as f:
        json.dump(consensus, f, indent=2)
        f.write("\n")
    print(f"wrote {out_dir / 'wallet-test-vectors.json'}")
    print(f"wrote {out_dir / 'consensus-test-vectors.json'}")


if __name__ == "__main__":
    main()
