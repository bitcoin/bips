"""Convert the BIP-324 test vectors to secp256k1 code."""

import csv
import reference
import os
import sys

FILENAME_XSWIFTEC_INV_TEST = os.path.join(sys.path[0], 'xswiftec_inv_test_vectors.csv')
FILENAME_ELLSWIFT_DECODE_TEST = os.path.join(sys.path[0], 'ellswift_decode_test_vectors.csv')

def format_int(v):
    """Format 0 as "0", but other integers as 0x%08x."""
    if v == 0:
        return "0"
    return f"0x{v:08x}"

def format_fe(fe):
    """Format a field element constant as SECP256K1_FE_CONST code."""
    vals = [(int(fe) >> (32 * (7 - i))) & 0xffffffff for i in range(8)]
    strs = ", ".join(format_int(v) for v in vals)
    return f"SECP256K1_FE_CONST({strs})"

def output_xswiftec_inv_cases():
    """Generate lines corresponding to the xswiftec_inv test cases."""
    with open(FILENAME_XSWIFTEC_INV_TEST, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        print("xswiftec_inv cases:")
        for row in reader:
            u = int.from_bytes(bytes.fromhex(row['u']), 'big')
            x = int.from_bytes(bytes.fromhex(row['x']), 'big')
            pat = sum(1<<c for c in range(8) if row[f"case{c}_t"])
            tstrs = []
            for c in range(8):
                tstrs.append(format_fe(int.from_bytes(bytes.fromhex(row[f"case{c}_t"]), 'big')))
            print(f"    {{0x{pat:02x}, {format_fe(u)}, {format_fe(x)}, {{{', '.join(tstrs)}}}}},")
    print()

def output_ellswift_decode_cases():
    """Generate lines corresponding to the ellswift_decode test cases."""
    with open(FILENAME_ELLSWIFT_DECODE_TEST, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        print("ellswift_decode cases:")
        for row in reader:
            enc = bytes.fromhex(row['ellswift'])
            tval = int.from_bytes(enc[32:], 'big') % reference.FE.SIZE
            x = int.from_bytes(bytes.fromhex(row['x']), 'big')
            encstr = ", ".join(f"0x{b:02x}" for b in enc)
            print(f"    {{{{{encstr}}}, {format_fe(x)}, {tval & 1}}},")
    print()

output_xswiftec_inv_cases()
output_ellswift_decode_cases()
