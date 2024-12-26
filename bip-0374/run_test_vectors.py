#!/usr/bin/env python3
"""Run the BIP-DLEQ test vectors."""
import csv
import os
import sys
from reference import (
    dleq_generate_proof,
    dleq_verify_proof,
)
from secp256k1 import GE


FILENAME_GENERATE_PROOF_TEST = os.path.join(sys.path[0], 'test_vectors_generate_proof.csv')
FILENAME_VERIFY_PROOF_TEST = os.path.join(sys.path[0], 'test_vectors_verify_proof.csv')


all_passed = True
print("-----------------------------------------")
print("----- Proof generation test vectors -----")
print("-----------------------------------------")
with open(FILENAME_GENERATE_PROOF_TEST, newline='') as csvfile:
    reader = csv.reader(csvfile)
    reader.__next__()
    for row in reader:
        (index, point_G_hex, seckey_a_hex, point_B_hex, aux_rand_hex, msg_hex, result_str, comment) = row
        print(seckey_a_hex)
        G = GE() if point_G_hex == 'INFINITY' else GE.from_bytes(bytes.fromhex(point_G_hex))
        a = int.from_bytes(bytes.fromhex(seckey_a_hex), 'big')
        B = GE() if point_B_hex == 'INFINITY' else GE.from_bytes(bytes.fromhex(point_B_hex))
        aux_rand = bytes.fromhex(aux_rand_hex)
        msg = bytes.fromhex(msg_hex)
        print('Test vector', ('#' + index).rjust(3, ' ') + ':' + f' ({comment})')
        expected_result = None if result_str == 'INVALID' else bytes.fromhex(result_str)
        actual_result = dleq_generate_proof(a, B, aux_rand, G=G, m=msg)
        if expected_result == actual_result:
            print(' * Passed proof generation test.')
        else:
            print(' * Failed proof generation test.')
            print('   Expected proof: ', expected_result.hex() if expected_result is not None else 'INVALID')
            print('     Actual proof: ', actual_result.hex() if actual_result is not None else 'INVALID')
            all_passed = False
    print()


print("-------------------------------------------")
print("----- Proof verification test vectors -----")
print("-------------------------------------------")
with open(FILENAME_VERIFY_PROOF_TEST, newline='') as csvfile:
    reader = csv.reader(csvfile)
    reader.__next__()
    for row in reader:
        (index, point_G_hex, point_A_hex, point_B_hex, point_C_hex, proof_hex, msg_hex, result_success, comment) = row
        G = GE() if point_G_hex == 'INFINITY' else GE.from_bytes(bytes.fromhex(point_G_hex))
        A = GE() if point_A_hex == 'INFINITY' else GE.from_bytes(bytes.fromhex(point_A_hex))
        B = GE() if point_B_hex == 'INFINITY' else GE.from_bytes(bytes.fromhex(point_B_hex))
        C = GE() if point_C_hex == 'INFINITY' else GE.from_bytes(bytes.fromhex(point_C_hex))
        proof = bytes.fromhex(proof_hex)
        msg = bytes.fromhex(msg_hex)
        print('Test vector', ('#' + index).rjust(3, ' ') + ':' + f' ({comment})')
        expected_result = result_success == 'TRUE'
        actual_result = dleq_verify_proof(A, B, C, proof, G=G, m=msg)
        if expected_result == actual_result:
            print(' * Passed proof verification test.')
        else:
            print(' * Failed proof verification test.')
            print('   Expected verification result: ', expected_result)
            print('     Actual verification result: ', actual_result)
            all_passed = False


print()
if all_passed:
    print('All test vectors passed.')
    sys.exit(0)
else:
    print('Some test vectors failed.')
    sys.exit(1)
