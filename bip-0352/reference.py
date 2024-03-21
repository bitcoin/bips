#!/usr/bin/env python3

import hashlib
import json
from typing import List, Tuple, Dict, cast
from sys import argv
from functools import reduce

# local files
from bech32m import convertbits, bech32_encode, decode, Encoding
from secp256k1 import ECKey, ECPubKey, TaggedHash, NUMS_H
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


def get_pubkey_from_input(vin: VinInfo) -> ECPubKey:
    if is_p2pkh(vin.prevout):
        # skip the first 3 op_codes and grab the 20 byte hash
        # from the scriptPubKey
        spk_hash = vin.prevout[3:3 + 20]
        for i in range(len(vin.scriptSig), 0, -1):
            if i - 33 >= 0:
                # starting from the back, we move over the scriptSig with a 33 byte
                # window (to match a compressed pubkey). we hash this and check if it matches
                # the 20 byte has from the scriptPubKey. for standard scriptSigs, this will match
                # right away because the pubkey is the last item in the scriptSig.
                # if its a non-standard (malleated) scriptSig, we will still find the pubkey if its
                # a compressed pubkey.
                #
                # note: this is an incredibly inefficient implementation, for demonstration purposes only.
                pubkey_bytes = vin.scriptSig[i - 33:i]
                pubkey_hash = hash160(pubkey_bytes)
                if pubkey_hash == spk_hash:
                    pubkey = ECPubKey().set(pubkey_bytes)
                    if (pubkey.valid) & (pubkey.compressed):
                        return pubkey
    if is_p2sh(vin.prevout):
        redeem_script = vin.scriptSig[1:]
        if is_p2wpkh(redeem_script):
            pubkey = ECPubKey().set(vin.txinwitness.scriptWitness.stack[-1])
            if (pubkey.valid) & (pubkey.compressed):
                return pubkey
    if is_p2wpkh(vin.prevout):
        txin = vin.txinwitness
        pubkey = ECPubKey().set(txin.scriptWitness.stack[-1])
        if (pubkey.valid) & (pubkey.compressed):
            return pubkey
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
                    return ECPubKey()

            pubkey = ECPubKey().set(vin.prevout[2:])
            if (pubkey.valid) & (pubkey.compressed):
                return pubkey


    return ECPubKey()


def get_input_hash(outpoints: List[COutPoint], sum_input_pubkeys: ECPubKey) -> bytes:
    lowest_outpoint = sorted(outpoints, key=lambda outpoint: (outpoint.hash, outpoint.n))[0]
    return TaggedHash("BIP0352/Inputs", lowest_outpoint.serialize() + cast(bytes, sum_input_pubkeys.get_bytes(False)))



def encode_silent_payment_address(B_scan: ECPubKey, B_m: ECPubKey, hrp: str = "tsp", version: int = 0) -> str:
    data = convertbits(cast(bytes, B_scan.get_bytes(False)) + cast(bytes, B_m.get_bytes(False)), 8, 5)
    return bech32_encode(hrp, [version] + cast(List[int], data), Encoding.BECH32M)


def generate_label(b_scan: ECKey, m: int) -> bytes:
    return TaggedHash("BIP0352/Label", b_scan.get_bytes() + ser_uint32(m))


def create_labeled_silent_payment_address(b_scan: ECKey, B_spend: ECPubKey, m: int, hrp: str = "tsp", version: int = 0) -> str:
    G = ECKey().set(1).get_pubkey()
    B_scan = b_scan.get_pubkey()
    B_m = B_spend + generate_label(b_scan, m) * G
    labeled_address = encode_silent_payment_address(B_scan, B_m, hrp, version)

    return labeled_address


def decode_silent_payment_address(address: str, hrp: str = "tsp") -> Tuple[ECPubKey, ECPubKey]:
    _, data = decode(hrp, address)
    if data is None:
        return ECPubKey(), ECPubKey()
    B_scan = ECPubKey().set(data[:33])
    B_spend = ECPubKey().set(data[33:])

    return B_scan, B_spend


def create_outputs(input_priv_keys: List[Tuple[ECKey, bool]], input_hash: bytes, recipients: List[str], hrp="tsp") -> List[str]:
    G = ECKey().set(1).get_pubkey()
    negated_keys = []
    for key, is_xonly in input_priv_keys:
        k = ECKey().set(key.get_bytes())
        if is_xonly and k.get_pubkey().get_y() % 2 != 0:
            k.negate()
        negated_keys.append(k)

    a_sum = sum(negated_keys)
    silent_payment_groups: Dict[ECPubKey, List[ECPubKey]] = {}
    for recipient in recipients:
        B_scan, B_m = decode_silent_payment_address(recipient, hrp=hrp)
        if B_scan in silent_payment_groups:
            silent_payment_groups[B_scan].append(B_m)
        else:
            silent_payment_groups[B_scan] = [B_m]

    outputs = []
    for B_scan, B_m_values in silent_payment_groups.items():
        k = 0
        ecdh_shared_secret = input_hash * a_sum * B_scan

        # Order doesn't matter for creating/finding the outputs. However, different orderings
        # may produce different generated outputs, if sending to multiple silent payment addresses belong to the
        # same sender but different labels
        for B_m in B_m_values:
            t_k = TaggedHash("BIP0352/SharedSecret", ecdh_shared_secret.get_bytes(False) + ser_uint32(k))
            P_km = B_m + t_k * G
            outputs.append(P_km.get_bytes().hex())
            k += 1
    return outputs


def scanning(b_scan: ECKey, B_spend: ECPubKey, A_sum: ECPubKey, input_hash: bytes, outputs_to_check: List[ECPubKey], labels: Dict[str, str] = {}) -> List[Dict[str, str]]:
    G = ECKey().set(1).get_pubkey()
    ecdh_shared_secret = input_hash * b_scan * A_sum
    k = 0
    wallet = []
    while True:
        t_k = TaggedHash("BIP0352/SharedSecret", ecdh_shared_secret.get_bytes(False) + ser_uint32(k))
        P_k = B_spend + t_k * G
        for output in outputs_to_check:
            if P_k == output:
                wallet.append({"pub_key": P_k.get_bytes().hex(), "priv_key_tweak": t_k.hex()})
                outputs_to_check.remove(output)
                k += 1
                break
            elif labels:
                m_G_sub = output - P_k
                if m_G_sub.get_bytes(False).hex() in labels:
                    P_km = P_k + m_G_sub
                    wallet.append({
                        "pub_key": P_km.get_bytes().hex(),
                        "priv_key_tweak": (ECKey().set(t_k).add(
                            bytes.fromhex(labels[m_G_sub.get_bytes(False).hex()])
                        )).get_bytes().hex(),
                    })
                    outputs_to_check.remove(output)
                    k += 1
                else:
                    output.negate()
                    m_G_sub = output - P_k
                    if m_G_sub.get_bytes(False).hex() in labels:
                        P_km = P_k + m_G_sub
                        wallet.append({
                            "pub_key": P_km.get_bytes().hex(),
                            "priv_key_tweak": (ECKey().set(t_k).add(
                                bytes.fromhex(labels[m_G_sub.get_bytes(False).hex()])
                            )).get_bytes().hex(),
                        })
                        outputs_to_check.remove(output)
                        k += 1
                        break
        else:
            break
    return wallet


if __name__ == "__main__":
    with open(argv[1], "r") as f:
        test_data = json.loads(f.read())

    # G , needed for generating the labels "database"
    G = ECKey().set(1).get_pubkey()
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
                    private_key=ECKey().set(bytes.fromhex(input["private_key"])),
                )
                for input in given["vin"]
            ]
            # Conver the tuples to lists so they can be easily compared to the json list of lists from the given test vectors
            input_priv_keys = []
            input_pub_keys = []
            for vin in vins:
                pubkey = get_pubkey_from_input(vin)
                if not pubkey.valid:
                    continue
                input_priv_keys.append((
                    vin.private_key,
                    is_p2tr(vin.prevout),
                ))
                input_pub_keys.append(pubkey)

            sending_outputs = []
            if (len(input_pub_keys) > 0):
                A_sum = reduce(lambda x, y: x + y, input_pub_keys)
                input_hash = get_input_hash([vin.outpoint for vin in vins], A_sum)
                sending_outputs = create_outputs(input_priv_keys, input_hash, given["recipients"], hrp="sp")
                # Check that for a given set of inputs, we were able to generate the expected outputs for the receiver
            assert sending_outputs == expected["outputs"], "Sending test failed"

        # Test receiving
        msg = hashlib.sha256(b"message").digest()
        aux = hashlib.sha256(b"random auxiliary data").digest()
        for receiving_test in case["receiving"]:
            given = receiving_test["given"]
            expected = receiving_test["expected"]
            outputs_to_check = [
                ECPubKey().set(bytes.fromhex(p)) for p in given["outputs"]
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
            b_scan = ECKey().set(bytes.fromhex(given["key_material"]["scan_priv_key"]))
            b_spend = ECKey().set(
                bytes.fromhex(given["key_material"]["spend_priv_key"])
            )
            B_scan = b_scan.get_pubkey()
            B_spend = b_spend.get_pubkey()
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
                if not pubkey.valid:
                    continue
                input_pub_keys.append(pubkey)

            add_to_wallet = []
            if (len(input_pub_keys) > 0):
                A_sum = reduce(lambda x, y: x + y, input_pub_keys)
                input_hash = get_input_hash([vin.outpoint for vin in vins], A_sum)
                pre_computed_labels = {
                    (generate_label(b_scan, label) * G).get_bytes(False).hex(): generate_label(b_scan, label).hex()
                    for label in given["labels"]
                }
                add_to_wallet = scanning(
                    b_scan=b_scan,
                    B_spend=B_spend,
                    A_sum=A_sum,
                    input_hash=input_hash,
                    outputs_to_check=outputs_to_check,
                    labels=pre_computed_labels,
                )

            # Check that the private key is correct for the found output public key
            for output in add_to_wallet:
                pub_key = ECPubKey().set(bytes.fromhex(output["pub_key"]))
                full_private_key = b_spend.add(bytes.fromhex(output["priv_key_tweak"]))
                if full_private_key.get_pubkey().get_y() % 2 != 0:
                    full_private_key.negate()

                sig = full_private_key.sign_schnorr(msg, aux)
                assert pub_key.verify_schnorr(sig, msg), f"Invalid signature for {pub_key}"
                output["signature"] = sig.hex()

            # Check if the found output public keys match the expected output public keys
            assert add_to_wallet == expected["outputs"], "Receiving test failed"

    print("All tests passed")
