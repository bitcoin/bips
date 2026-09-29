#!/usr/bin/env python3
"""
Checks the ECDSA signatures and key commitments of test vector inputs

Whether a signature verifies is a PSBTv2 matter that BIP-375 does not restate,
so it is not one of the validator's checks. The test runner applies this check
to every vector and fails a vector whose PSBT_IN_PARTIAL_SIG does not verify
against the transaction its PSBT describes.
"""

import struct
from typing import List, Optional, Tuple

from deps.bitcoin_test.messages import (
    CTransaction,
    CTxOut,
    from_binary,
    hash160,
    hash256,
    ser_compact_size,
    ser_string,
)
from deps.bitcoin_test.psbt import (
    PSBT,
    PSBT_GLOBAL_FALLBACK_LOCKTIME,
    PSBT_GLOBAL_TX_VERSION,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_OUTPUT_INDEX,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_PREVIOUS_TXID,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_REQUIRED_HEIGHT_LOCKTIME,
    PSBT_IN_REQUIRED_TIME_LOCKTIME,
    PSBT_IN_SEQUENCE,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_WITNESS_UTXO,
    PSBT_OUT_AMOUNT,
    PSBT_OUT_SCRIPT,
)
from secp256k1lab.secp256k1 import G, GE

SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


class CannotVerify(Exception):
    """No signature hash can be computed for a signature"""


def check_partial_signatures(psbt: PSBT) -> List[str]:
    """
    Check every input's partial signatures and single-key program

    Checks:
    - A P2PKH, P2WPKH or P2SH-P2WPKH program commits to every key in the
      input's PSBT_IN_PARTIAL_SIG and PSBT_IN_BIP32_DERIVATION
    - A P2SH program commits to PSBT_IN_REDEEM_SCRIPT
    - Each signature's sighash byte equals PSBT_IN_SIGHASH_TYPE, if set
    - Each signature verifies: BIP 143 for P2WPKH and P2SH-P2WPKH, the
      legacy signature hash for P2PKH and bare scripts

    A signature with no defined signature hash, such as one on a witness v2
    input or one committing to an output without PSBT_OUT_SCRIPT, is a failure.

    Returns the list of failures, empty if there is none.
    """
    errors = []
    for i, input_map in enumerate(psbt.i):
        spent_output = _spent_output(input_map)
        if spent_output is None:
            errors.append(f"Input {i} spent output not found in PSBT_IN_WITNESS_UTXO or PSBT_IN_NON_WITNESS_UTXO")
            continue
        amount, script_pubkey = spent_output
        redeem_script = input_map.get(PSBT_IN_REDEEM_SCRIPT)
        if _is_p2sh(script_pubkey) and redeem_script is not None:
            if hash160(redeem_script) != script_pubkey[2:22]:
                errors.append(f"Input {i} P2SH program does not commit to PSBT_IN_REDEEM_SCRIPT")

        signatures = input_map.get_all_by_type(PSBT_IN_PARTIAL_SIG)
        key_hash = _key_hash(script_pubkey, redeem_script)
        if key_hash is not None:
            keys = [key for key, _ in signatures]
            keys += [key for key, _ in input_map.get_all_by_type(PSBT_IN_BIP32_DERIVATION)]
            for key in dict.fromkeys(keys):
                if hash160(key) != key_hash:
                    errors.append(f"Input {i} program does not commit to key {key.hex()}")

        for key, signature in signatures:
            if not signature:
                errors.append(f"Input {i} signature by key {key.hex()} is empty")
                continue
            hashtype = signature[-1]
            if PSBT_IN_SIGHASH_TYPE in input_map:
                expected = struct.unpack("<I", input_map[PSBT_IN_SIGHASH_TYPE])[0]
                if hashtype != expected:
                    errors.append(
                        f"Input {i} signature sighash type {hashtype} differs from PSBT_IN_SIGHASH_TYPE {expected}"
                    )
            try:
                sighash = _signature_hash(psbt, i, amount, script_pubkey, redeem_script, hashtype)
            except CannotVerify as e:
                errors.append(f"Input {i} signature cannot be verified: {e}")
                continue
            if not _ecdsa_verify(key, sighash, signature[:-1]):
                errors.append(f"Input {i} signature by key {key.hex()} does not verify")
    return errors


def _signature_hash(
    psbt: PSBT,
    index: int,
    amount: int,
    script_pubkey: bytes,
    redeem_script: Optional[bytes],
    hashtype: int,
) -> bytes:
    """Compute the signature hash an ECDSA signature on input index commits to"""
    witness_version = _witness_version(script_pubkey)
    if _is_p2wpkh(script_pubkey):
        return _segwit_v0_sighash(psbt, index, _p2pkh(script_pubkey[2:]), amount, hashtype)
    if witness_version is not None:
        if witness_version == 0:
            raise CannotVerify("P2WSH is not supported")
        raise CannotVerify(f"no ECDSA signature hash is defined for witness version {witness_version}")
    if _is_p2sh(script_pubkey):
        if redeem_script is not None and _is_p2wpkh(redeem_script):
            return _segwit_v0_sighash(psbt, index, _p2pkh(redeem_script[2:]), amount, hashtype)
        raise CannotVerify("only P2SH-P2WPKH is supported among P2SH scripts")
    if 0xAB in script_pubkey:
        raise CannotVerify("a script that may contain OP_CODESEPARATOR is not supported")
    return _legacy_sighash(psbt, index, script_pubkey, hashtype)


def _legacy_sighash(psbt: PSBT, index: int, script_code: bytes, hashtype: int) -> bytes:
    """Compute the pre-segwit signature hash"""
    base_type = hashtype & 0x1F
    outputs = list(range(len(psbt.o)))
    if base_type == SIGHASH_SINGLE:
        if index >= len(psbt.o):
            return (1).to_bytes(32, "little")
        outputs = outputs[: index + 1]
    elif base_type == SIGHASH_NONE:
        outputs = []

    tx_inputs = []
    for j, input_map in enumerate(psbt.i):
        if hashtype & SIGHASH_ANYONECANPAY and j != index:
            continue
        sequence = _sequence(input_map)
        if j != index and base_type in (SIGHASH_NONE, SIGHASH_SINGLE):
            sequence = bytes(4)
        script_sig = script_code if j == index else b""
        tx_inputs.append(_outpoint(input_map) + ser_string(script_sig) + sequence)

    tx_outputs = []
    for k in outputs:
        if base_type == SIGHASH_SINGLE and k != index:
            tx_outputs.append(struct.pack("<q", -1) + ser_string(b""))
        else:
            tx_outputs.append(_output(psbt, k))

    tx = (
        _tx_version(psbt)
        + ser_compact_size(len(tx_inputs)) + b"".join(tx_inputs)
        + ser_compact_size(len(tx_outputs)) + b"".join(tx_outputs)
        + _locktime(psbt)
    )
    return hash256(tx + struct.pack("<I", hashtype))


def _segwit_v0_sighash(
    psbt: PSBT, index: int, script_code: bytes, amount: int, hashtype: int
) -> bytes:
    """Compute the BIP 143 signature hash"""
    base_type = hashtype & 0x1F
    anyone_can_pay = hashtype & SIGHASH_ANYONECANPAY
    hash_prevouts = bytes(32)
    hash_sequence = bytes(32)
    hash_outputs = bytes(32)
    if not anyone_can_pay:
        hash_prevouts = hash256(b"".join(_outpoint(m) for m in psbt.i))
        if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
            hash_sequence = hash256(b"".join(_sequence(m) for m in psbt.i))
    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        hash_outputs = hash256(b"".join(_output(psbt, k) for k in range(len(psbt.o))))
    elif base_type == SIGHASH_SINGLE and index < len(psbt.o):
        hash_outputs = hash256(_output(psbt, index))

    input_map = psbt.i[index]
    preimage = (
        _tx_version(psbt)
        + hash_prevouts
        + hash_sequence
        + _outpoint(input_map)
        + ser_string(script_code)
        + struct.pack("<q", amount)
        + _sequence(input_map)
        + hash_outputs
        + _locktime(psbt)
        + struct.pack("<I", hashtype)
    )
    return hash256(preimage)


def _ecdsa_verify(pubkey: bytes, msg: bytes, der_signature: bytes) -> bool:
    """Verify a DER-encoded ECDSA signature of a 32-byte message"""
    try:
        r, s = _parse_der(der_signature)
        point = GE.from_bytes(pubkey)
    except (AssertionError, ValueError):
        return False
    n = GE.ORDER
    if not (0 < r < n and 0 < s < n):
        return False
    w = pow(s, -1, n)
    z = int.from_bytes(msg, "big")
    R = GE.batch_mul((z * w % n, G), (r * w % n, point))
    return not R.infinity and int(R.x) % n == r


def _parse_der(signature: bytes) -> Tuple[int, int]:
    """Parse a strict DER (BIP 66) signature without its sighash byte"""
    if len(signature) < 8 or signature[0] != 0x30 or signature[1] != len(signature) - 2:
        raise ValueError("not a DER sequence")
    values = []
    pos = 2
    for _ in range(2):
        if pos + 2 > len(signature) or signature[pos] != 0x02:
            raise ValueError("not a DER integer")
        length = signature[pos + 1]
        value = signature[pos + 2 : pos + 2 + length]
        if (
            length == 0
            or len(value) != length
            or value[0] & 0x80
            or (length > 1 and value[0] == 0 and not value[1] & 0x80)
        ):
            raise ValueError("not a DER integer")
        values.append(int.from_bytes(value, "big"))
        pos += 2 + length
    if pos != len(signature):
        raise ValueError("trailing bytes after DER sequence")
    return values[0], values[1]


# ============================================================================
# Transaction fields from PSBTv2 maps
# ============================================================================


def _spent_output(input_map) -> Optional[Tuple[int, bytes]]:
    """Return the amount and scriptPubKey of the output an input spends, None if unknown"""
    if PSBT_IN_WITNESS_UTXO in input_map:
        utxo = from_binary(CTxOut, input_map[PSBT_IN_WITNESS_UTXO])
    elif PSBT_IN_NON_WITNESS_UTXO in input_map:
        tx = from_binary(CTransaction, input_map[PSBT_IN_NON_WITNESS_UTXO])
        index = struct.unpack("<I", input_map[PSBT_IN_OUTPUT_INDEX])[0]
        if index >= len(tx.vout):
            return None
        utxo = tx.vout[index]
    else:
        return None
    return utxo.nValue, utxo.scriptPubKey


def _tx_version(psbt: PSBT) -> bytes:
    return psbt.g.get(PSBT_GLOBAL_TX_VERSION)


def _locktime(psbt: PSBT) -> bytes:
    for input_map in psbt.i:
        if PSBT_IN_REQUIRED_TIME_LOCKTIME in input_map or PSBT_IN_REQUIRED_HEIGHT_LOCKTIME in input_map:
            raise CannotVerify("required input locktimes are not supported")
    return psbt.g.get(PSBT_GLOBAL_FALLBACK_LOCKTIME, bytes(4))


def _outpoint(input_map) -> bytes:
    return input_map[PSBT_IN_PREVIOUS_TXID] + input_map[PSBT_IN_OUTPUT_INDEX]


def _sequence(input_map) -> bytes:
    return input_map.get(PSBT_IN_SEQUENCE, b"\xff\xff\xff\xff")


def _output(psbt: PSBT, index: int) -> bytes:
    output_map = psbt.o[index]
    if PSBT_OUT_SCRIPT not in output_map:
        raise CannotVerify(f"output {index} has no PSBT_OUT_SCRIPT for the signature hash to commit to")
    return output_map[PSBT_OUT_AMOUNT] + ser_string(output_map[PSBT_OUT_SCRIPT])


# ============================================================================
# scriptPubKey helpers
# ============================================================================


def _key_hash(script_pubkey: bytes, redeem_script: Optional[bytes]) -> Optional[bytes]:
    """Return the key hash a single-key program commits to, None for other scripts"""
    if _is_p2pkh(script_pubkey):
        return script_pubkey[3:23]
    if _is_p2wpkh(script_pubkey):
        return script_pubkey[2:22]
    if _is_p2sh(script_pubkey) and redeem_script is not None and _is_p2wpkh(redeem_script):
        return redeem_script[2:22]
    return None


def _witness_version(script_pubkey: bytes) -> Optional[int]:
    """Return the witness version of a witness program, None for other scripts"""
    if not (4 <= len(script_pubkey) <= 42 and script_pubkey[1] == len(script_pubkey) - 2):
        return None
    if script_pubkey[0] == 0x00:
        return 0
    if 0x51 <= script_pubkey[0] <= 0x60:
        return script_pubkey[0] - 0x50
    return None


def _p2pkh(key_hash: bytes) -> bytes:
    return b"\x76\xa9\x14" + key_hash + b"\x88\xac"


def _is_p2pkh(spk: bytes) -> bool:
    return len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[23:] == b"\x88\xac"


def _is_p2wpkh(spk: bytes) -> bool:
    return len(spk) == 22 and spk[:2] == b"\x00\x14"


def _is_p2sh(spk: bytes) -> bool:
    return len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[22] == 0x87
