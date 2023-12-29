"""Compare ellswift decoding in the BIP-324 test vectors against the SwiftEC reference code.

Instructions:

* Clone the SwiftEC repository, and enter the directory:

  git clone https://github.com/Jchavezsaab/SwiftEC
  cd SwiftEC
  git checkout 5320a25035d91addde29d14164cce684b56a12ed

* Generate parameters for the secp256k1 curve:

  sage --python generate_parameters.py -p secp256k1

* Copy over this file and the CSV test vectors:

  cp PATH_TO_BIPS_REPO/bips/bip-0324/{*.csv,test_sage_decoding.py} .

* Run the tests:

  sage --python test_sage_decoding.py -p secp256k1

No output = good.
"""

import sys
import csv
from config import F
from Xencoding_0 import Xdecode


FILENAME_PACKET_TEST = 'packet_encoding_test_vectors.csv'
FILENAME_XSWIFTEC_INV_TEST = 'xswiftec_inv_test_vectors.csv'
FILENAME_ELLSWIFT_DECODE_TEST = 'ellswift_decode_test_vectors.csv'

def ellswift_decode_sage(ellswift):
    """Given a 64-byte ellswift encoded public key, get the 32-byte X coordinate."""

    u = F(int.from_bytes(ellswift[:32], 'big'))
    t = F(int.from_bytes(ellswift[32:], 'big'))

    # Reimplement the input correction step.
    if u == F(0):
        u = F(1)
    if t == F(0):
        t = F(1)
    if u**3 + t**2 + 7 == F(0):
        t = F(2) * t

    # Invoke reference code
    x, z = Xdecode(u, t)

    # Convert to bytes.
    return int(x / z).to_bytes(32, 'big')

with open(FILENAME_PACKET_TEST, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        bytes_ellswift_ours = bytes.fromhex(row['in_ellswift_ours'])
        bytes_ellswift_theirs = bytes.fromhex(row['in_ellswift_theirs'])
        assert row['mid_x_ours'] == ellswift_decode_sage(bytes_ellswift_ours).hex()
        assert row['mid_x_theirs'] == ellswift_decode_sage(bytes_ellswift_theirs).hex()

with open(FILENAME_XSWIFTEC_INV_TEST, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        udat = bytes.fromhex(row['u'])
        xdat = bytes.fromhex(row['x'])
        for case in range(8):
            tdat = bytes.fromhex(row[f"case{case}_t"])
            if tdat:
                assert ellswift_decode_sage(udat + tdat) == xdat

with open(FILENAME_ELLSWIFT_DECODE_TEST, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        ellswift = bytes.fromhex(row['ellswift'])
        assert ellswift_decode_sage(ellswift).hex() == row['x']
