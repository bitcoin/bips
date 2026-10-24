"""Run the low-R grinding test vectors."""

import csv
import os
import sys

import reference

FILENAME_SIGN_TEST = os.path.join(sys.path[0], 'sign_test_vectors.csv')
FILENAME_VERIFY_TEST = os.path.join(sys.path[0], 'verify_test_vectors.csv')

def sig_from_hex(s):
    """Parse a compact signature into the integer pair (r, s)."""
    b = bytes.fromhex(s)
    assert len(b) == 64
    return (int.from_bytes(b[:32], 'big'), int.from_bytes(b[32:], 'big'))

def sig_hex(sig):
    return (reference.bytes_from_int(sig[0]) + reference.bytes_from_int(sig[1])).hex()

def pubkey_from_hex(s):
    """Parse an uncompressed SEC 1 public key into a point."""
    b = bytes.fromhex(s)
    if b == b'\x00':
        return None
    assert len(b) == 65 and b[0] == 0x04
    return (int.from_bytes(b[1:33], 'big'), int.from_bytes(b[33:], 'big'))

def result_from_str(s):
    assert s in ('TRUE', 'FALSE')
    return s == 'TRUE'

with open(FILENAME_SIGN_TEST, newline='', encoding='utf-8') as csvfile:
    print(f"Running {FILENAME_SIGN_TEST} tests...")
    reader = csv.DictReader(csvfile)
    for row in reader:
        seckey = bytes.fromhex(row['seckey'])
        msghash = bytes.fromhex(row['msghash'])
        if row['sig'] == '':
            # An empty signature means signing must fail for this secret key.
            raised = False
            try:
                reference.deterministic_sign(seckey, msghash)
            except ValueError:
                raised = True
            assert raised
            continue
        sig = reference.deterministic_sign(seckey, msghash)
        assert reference.is_low_r(sig)
        assert row['sig'] == sig_hex(sig)

with open(FILENAME_VERIFY_TEST, newline='', encoding='utf-8') as csvfile:
    print(f"Running {FILENAME_VERIFY_TEST} tests...")
    reader = csv.DictReader(csvfile)
    for row in reader:
        pubkey = pubkey_from_hex(row['pubkey'])
        msghash = bytes.fromhex(row['msghash'])
        sig = sig_from_hex(row['sig'])
        assert reference.verify(sig, pubkey, msghash) == result_from_str(row['result'])
