#!/usr/bin/env python3
# For running the test vectors, run this script:
# ./reference.py send_and_receive_test_vectors.json

import json
from pathlib import Path
import sys
from typing import List, Tuple, Dict, cast

# import the vendored copy of secp256k1lab
sys.path.insert(0, str(Path(__file__).parent / "secp256k1lab/src"))
from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash, hash_sha256


from bech32m import convertbits, bech32_encode, decode, Encoding
from bitcoin_utils import (
        deser_txid,
        from_hex,
        hash160,
        is_p2pkh,
        is_p2sh,
        is_p2wpkh,
        is_p2tr,
        ser_uint32,
        COutPoint,
        CTxInWitness,
        VinInfo,
    )


NUMS_H = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0


def get_pubkey_from_input(vin: VinInfo) -> GE:
    if is_p2pkh(vin.prevout):
        # skip the first 3 op_codes and grab the 20 byte hash
        # from the scriptPubKey
        spk_hash = vin.prevout[3:3 + 20]
        for i in range(len(vin.scriptSig), 0, -1):
            if i - 33 >= 0:
                # starting from the back, we move over the scriptSig with a 33 byte
                # window (to match a compressed pubkey). we hash this and check if it matches
                # the 20 byte hash from the scriptPubKey. for standard scriptSigs, this will match
                # right away because the pubkey is the last item in the scriptSig.
                # if its a non-standard (malleated) scriptSig, we will still find the pubkey if its
                # a compressed pubkey.
                #
                # note: this is an incredibly inefficient implementation, for demonstration purposes only.
                pubkey_bytes = vin.scriptSig[i - 33:i]
                pubkey_hash = hash160(pubkey_bytes)
                if pubkey_hash == spk_hash:
                    try:
                        return GE.from_bytes_compressed(pubkey_bytes)
                    except ValueError:
                        pass
    if is_p2sh(vin.prevout):
        redeem_script = vin.scriptSig[1:]
        if is_p2wpkh(redeem_script):
            try:
                return GE.from_bytes_compressed(vin.txinwitness.scriptWitness.stack[-1])
            except (ValueError, AssertionError):
                pass
    if is_p2wpkh(vin.prevout):
        try:
            return GE.from_bytes_compressed(vin.txinwitness.scriptWitness.stack[-1])
        except (ValueError, AssertionError):
            pass
    if is_p2tr(vin.prevout):
        witnessStack = vin.txinwitness.scriptWitness.stack
        if (len(witnessStack) >= 1):
            if (len(witnessStack) > 1 and witnessStack[-1][0] == 0x50):
                # Last item is annex
                witnessStack.pop()

            if (len(witnessStack) > 1):
                # Script-path spend
                control_block = witnessStack[-1]
                #  control block is <control byte> <32 byte internal key> and 0 or more <32 byte hash>
                internal_key = control_block[1:33]
                if (internal_key == NUMS_H.to_bytes(32, 'big')):
                    # Skip if NUMS_H
                    return GE()

            try:
                return GE.from_bytes_xonly(vin.prevout[2:])
            except ValueError:
                pass

    return GE()


def get_input_hash(outpoints: List[COutPoint], sum_input_pubkeys: GE) -> bytes:
    lowest_outpoint = sorted(outpoints, key=lambda outpoint: outpoint.serialize())[0]
    return tagged_hash("BIP0352/Inputs", lowest_outpoint.serialize() + sum_input_pubkeys.to_bytes_compressed())



def encode_silent_payment_address(B_scan: GE, B_m: GE, hrp: str = "tsp", version: int = 0) -> str:
    data = convertbits(B_scan.to_bytes_compressed() + B_m.to_bytes_compressed(), 8, 5)
    return bech32_encode(hrp, [version] + cast(List[int], data), Encoding.BECH32M)


def generate_label(b_scan: Scalar, m: int) -> Scalar:
    return Scalar.from_bytes_checked(tagged_hash("BIP0352/Label", b_scan.to_bytes() + ser_uint32(m)))


def create_labeled_silent_payment_address(b_scan: Scalar, B_spend: GE, m: int, hrp: str = "tsp", version: int = 0) -> str:
    B_scan = b_scan * G
    B_m = B_spend + generate_label(b_scan, m) * G
    labeled_address = encode_silent_payment_address(B_scan, B_m, hrp, version)

    return labeled_address


def decode_silent_payment_address(address: str, hrp: str = "tsp") -> Tuple[GE, GE]:
    _, data = decode(hrp, address)
    if data is None:
        return GE(), GE()
    B_scan = GE.from_bytes_compressed(data[:33])
    B_spend = GE.from_bytes_compressed(data[33:])

    return B_scan, B_spend


def create_outputs(input_priv_keys: List[Tuple[Scalar, bool]], outpoints: List[COutPoint], recipients: List[str], expected: Dict[str, any] = None, hrp="tsp") -> List[str]:
    negated_keys = []
    for key, is_xonly in input_priv_keys:
        k = Scalar.from_bytes_checked(key.to_bytes())
        if is_xonly and not (k * G).has_even_y():
            k = -k
        negated_keys.append(k)

    a_sum = Scalar.sum(*negated_keys)
    if a_sum == 0:
        # Input privkeys sum is zero -> fail
        return []
    assert Scalar.from_bytes_checked(bytes.fromhex(expected.get("input_private_key_sum"))) == a_sum, "a_sum did not match expected input_private_key_sum"
    input_hash_scalar = Scalar.from_bytes_checked(get_input_hash(outpoints, a_sum * G))
    silent_payment_groups: Dict[GE, List[GE]] = {}
    for recipient in recipients:
        B_scan, B_m = decode_silent_payment_address(recipient["address"], hrp=hrp)
        # Verify decoded intermediate keys for recipient
        expected_B_scan = GE.from_bytes_compressed(bytes.fromhex(recipient["scan_pub_key"]))
        expected_B_m = GE.from_bytes_compressed(bytes.fromhex(recipient["spend_pub_key"]))
        assert expected_B_scan == B_scan, "B_scan did not match expected recipient.scan_pub_key"
        assert expected_B_m == B_m, "B_m did not match expected recipient.spend_pub_key"
        if B_scan in silent_payment_groups:
            silent_payment_groups[B_scan].append(B_m)
        else:
            silent_payment_groups[B_scan] = [B_m]

    outputs = []
    for B_scan, B_m_values in silent_payment_groups.items():
        ecdh_shared_secret = input_hash_scalar * a_sum * B_scan
        expected_shared_secrets = expected.get("shared_secrets", {})
        # Find the recipient address that corresponds to this B_scan and get its index
        for recipient_idx, recipient in enumerate(recipients):
            recipient_B_scan = GE.from_bytes_compressed(bytes.fromhex(recipient["scan_pub_key"]))
            if recipient_B_scan == B_scan:
                expected_shared_secret_hex = expected_shared_secrets[recipient_idx]
                assert ecdh_shared_secret.to_bytes_compressed().hex() == expected_shared_secret_hex, f"ecdh_shared_secret did not match expected, recipient {recipient_idx} ({recipient['address']}): expected={expected_shared_secret_hex}"
                break
        k = 0
        for B_m in B_m_values:
            t_k = Scalar.from_bytes_checked(tagged_hash("BIP0352/SharedSecret", ecdh_shared_secret.to_bytes_compressed() + ser_uint32(k)))
            P_km = B_m + t_k * G
            outputs.append(P_km.to_bytes_xonly().hex())
            k += 1

    return list(set(outputs))


def scanning(b_scan: Scalar, B_spend: GE, A_sum: GE, input_hash: bytes, outputs_to_check: List[bytes], labels: Dict[str, str] = None, expected: Dict[str, any] = None) -> List[Dict[str, str]]:
    input_hash_scalar = Scalar.from_bytes_checked(input_hash)
    computed_tweak_point = input_hash_scalar * A_sum
    assert computed_tweak_point.to_bytes_compressed().hex() == expected.get("tweak"), "tweak did not match expected"
    ecdh_shared_secret = input_hash_scalar * b_scan * A_sum
    assert ecdh_shared_secret.to_bytes_compressed().hex() == expected.get("shared_secret"), "ecdh_shared_secret did not match expected shared_secret"
    k = 0
    wallet = []
    while True:
        t_k = Scalar.from_bytes_checked(tagged_hash("BIP0352/SharedSecret", ecdh_shared_secret.to_bytes_compressed() + ser_uint32(k)))
        P_k = B_spend + t_k * G
        for output in outputs_to_check:
            output_ge = GE.from_bytes_xonly(output)
            if P_k.to_bytes_xonly() == output:
                wallet.append({"pub_key": P_k.to_bytes_xonly().hex(), "priv_key_tweak": t_k.to_bytes().hex()})
                outputs_to_check.remove(output)
                k += 1
                break
            elif labels:
                m_G_sub = output_ge - P_k
                if m_G_sub.to_bytes_compressed().hex() in labels:
                    P_km = P_k + m_G_sub
                    wallet.append({
                        "pub_key": P_km.to_bytes_xonly().hex(),
                        "priv_key_tweak": (t_k + Scalar.from_bytes_checked(
                            bytes.fromhex(labels[m_G_sub.to_bytes_compressed().hex()])
                        )).to_bytes().hex(),
                    })
                    outputs_to_check.remove(output)
                    k += 1
                    break
                else:
                    m_G_sub = -output_ge - P_k
                    if m_G_sub.to_bytes_compressed().hex() in labels:
                        P_km = P_k + m_G_sub
                        wallet.append({
                            "pub_key": P_km.to_bytes_xonly().hex(),
                            "priv_key_tweak": (t_k + Scalar.from_bytes_checked(
                                bytes.fromhex(labels[m_G_sub.to_bytes_compressed().hex()])
                            )).to_bytes().hex(),
                        })
                        outputs_to_check.remove(output)
                        k += 1
                        break
        else:
            break
    return wallet


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        print("Usage: ./reference.py send_and_receive_test_vectors.json")
        sys.exit(0)

    with open(sys.argv[1], "r") as f:
        test_data = json.loads(f.read())

    for case in test_data:
        print(case["comment"])
        # Test sending
        for sending_test in case["sending"]:
            given = sending_test["given"]
            expected = sending_test["expected"]

            vins = [
                VinInfo(
                    outpoint=COutPoint(hash=deser_txid(input["txid"]), n=input["vout"]),
                    scriptSig=bytes.fromhex(input["scriptSig"]),
                    txinwitness=CTxInWitness().deserialize(from_hex(input["txinwitness"])),
                    prevout=bytes.fromhex(input["prevout"]["scriptPubKey"]["hex"]),
                    private_key=Scalar.from_bytes_checked(bytes.fromhex(input["private_key"])),
                )
                for input in given["vin"]
            ]
            # Convert the tuples to lists so they can be easily compared to the json list of lists from the given test vectors
            input_priv_keys = []
            input_pub_keys = []
            for vin in vins:
                pubkey = get_pubkey_from_input(vin)
                if pubkey.infinity:
                    continue
                input_priv_keys.append((
                    vin.private_key,
                    is_p2tr(vin.prevout),
                ))
                input_pub_keys.append(pubkey)
            assert [pk.to_bytes_compressed().hex() for pk in input_pub_keys] == expected.get("input_pub_keys"), "input_pub_keys did not match expected"

            sending_outputs = []
            if (len(input_pub_keys) > 0):
                outpoints = [vin.outpoint for vin in vins]
                sending_outputs = create_outputs(input_priv_keys, outpoints, given["recipients"], expected=expected, hrp="sp")

                # Note: order doesn't matter for creating/finding the outputs. However, different orderings of the recipient addresses
                # will produce different generated outputs if sending to multiple silent payment addresses belonging to the
                # same sender but with different labels. Because of this, expected["outputs"] contains all possible valid output sets,
                # based on all possible permutations of recipient address orderings. Must match exactly one of the possible output sets.
                assert(any(set(sending_outputs) == set(lst) for lst in expected["outputs"])), "Sending test failed"
            else:
                assert(sending_outputs == expected["outputs"][0] == []), "Sending test failed"

        # Test receiving
        msg = hash_sha256(b"message")
        aux = hash_sha256(b"random auxiliary data")
        for receiving_test in case["receiving"]:
            given = receiving_test["given"]
            expected = receiving_test["expected"]
            outputs_to_check = [
                bytes.fromhex(p) for p in given["outputs"]
            ]
            vins = [
                VinInfo(
                    outpoint=COutPoint(hash=deser_txid(input["txid"]), n=input["vout"]),
                    scriptSig=bytes.fromhex(input["scriptSig"]),
                    txinwitness=CTxInWitness().deserialize(from_hex(input["txinwitness"])),
                    prevout=bytes.fromhex(input["prevout"]["scriptPubKey"]["hex"]),
                )
                for input in given["vin"]
            ]
            # Check that the given inputs for the receiving test match what was generated during the sending test
            receiving_addresses = []
            b_scan = Scalar.from_bytes_checked(bytes.fromhex(given["key_material"]["scan_priv_key"]))
            b_spend = Scalar.from_bytes_checked(bytes.fromhex(given["key_material"]["spend_priv_key"]))
            B_scan = b_scan * G
            B_spend = b_spend * G
            receiving_addresses.append(
                encode_silent_payment_address(B_scan, B_spend, hrp="sp")
            )
            if given["labels"]:
                for label in given["labels"]:
                    receiving_addresses.append(
                        create_labeled_silent_payment_address(
                            b_scan, B_spend, m=label, hrp="sp"
                        )
                    )

            # Check that the silent payment addresses match for the given BIP32 seed and labels dictionary
            assert (receiving_addresses == expected["addresses"]), "Receiving addresses don't match"
            input_pub_keys = []
            for vin in vins:
                pubkey = get_pubkey_from_input(vin)
                if pubkey.infinity:
                    continue
                input_pub_keys.append(pubkey)

            add_to_wallet = []
            if (len(input_pub_keys) > 0):
                A_sum = GE.sum(*input_pub_keys)
                if A_sum.infinity:
                    # Input pubkeys sum is point at infinity -> skip tx
                    assert expected["outputs"] == []
                    continue
                assert A_sum.to_bytes_compressed().hex() == expected.get("input_pub_key_sum"), "A_sum did not match expected input_pub_key_sum"
                input_hash = get_input_hash([vin.outpoint for vin in vins], A_sum)
                pre_computed_labels = {
                    (generate_label(b_scan, label) * G).to_bytes_compressed().hex(): generate_label(b_scan, label).to_bytes().hex()
                    for label in given["labels"]
                }
                add_to_wallet = scanning(
                    b_scan=b_scan,
                    B_spend=B_spend,
                    A_sum=A_sum,
                    input_hash=input_hash,
                    outputs_to_check=outputs_to_check,
                    labels=pre_computed_labels,
                    expected=expected,
                )

            # Check that the private key is correct for the found output public key
            for output in add_to_wallet:
                pub_key = GE.from_bytes_xonly(bytes.fromhex(output["pub_key"]))
                full_private_key = b_spend + Scalar.from_bytes_checked(bytes.fromhex(output["priv_key_tweak"]))
                if not (full_private_key * G).has_even_y():
                    full_private_key = -full_private_key

                sig = schnorr_sign(msg, full_private_key.to_bytes(), aux)
                assert schnorr_verify(msg, pub_key.to_bytes_xonly(), sig), f"Invalid signature for {pub_key}"
                output["signature"] = sig.hex()

            # Note: order doesn't matter for creating/finding the outputs. However, different orderings of the recipient addresses
            # will produce different generated outputs if sending to multiple silent payment addresses belonging to the
            # same sender but with different labels. Because of this, expected["outputs"] contains all possible valid output sets,
            # based on all possible permutations of recipient address orderings. Must match exactly one of the possible found output
            # sets in expected["outputs"]
            generated_set = {frozenset(d.items()) for d in add_to_wallet}
            expected_set = {frozenset(d.items()) for d in expected["outputs"]}
            assert generated_set == expected_set, "Receive test failed"


    print("All tests passed")
