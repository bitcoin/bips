"""Run the BIP-324 test vectors."""

import csv
import os
import sys

import reference

FILENAME_PACKET_TEST = os.path.join(sys.path[0], 'packet_encoding_test_vectors.csv')
FILENAME_XSWIFTEC_INV_TEST = os.path.join(sys.path[0], 'xswiftec_inv_test_vectors.csv')
FILENAME_ELLSWIFT_DECODE_TEST = os.path.join(sys.path[0], 'ellswift_decode_test_vectors.csv')

with open(FILENAME_PACKET_TEST, newline='', encoding='utf-8') as csvfile:
    print(f"Running {FILENAME_PACKET_TEST} tests...")
    reader = csv.DictReader(csvfile)
    for row in reader:
        in_initiating = int(row['in_initiating'])
        bytes_priv_ours = bytes.fromhex(row['in_priv_ours'])
        int_priv_ours = int.from_bytes(bytes_priv_ours, 'big')
        assert row['mid_x_ours'] == (int_priv_ours * reference.SECP256K1_G).x.to_bytes().hex()
        bytes_ellswift_ours = bytes.fromhex(row['in_ellswift_ours'])
        assert row['mid_x_ours'] == reference.ellswift_decode(bytes_ellswift_ours).hex()
        bytes_ellswift_theirs = bytes.fromhex(row['in_ellswift_theirs'])
        assert row['mid_x_theirs'] == reference.ellswift_decode(bytes_ellswift_theirs).hex()
        x_shared = reference.ellswift_ecdh_xonly(bytes_ellswift_theirs, bytes_priv_ours)
        assert row['mid_x_shared'] == x_shared.hex()
        shared_secret = reference.v2_ecdh(bytes_priv_ours, bytes_ellswift_theirs,
            bytes_ellswift_ours, in_initiating)
        assert row['mid_shared_secret'] == shared_secret.hex()

        peer = reference.initialize_v2_transport(shared_secret, in_initiating)
        assert row['mid_initiator_l'] == peer['initiator_L'].hex()
        assert row['mid_initiator_p'] == peer['initiator_P'].hex()
        assert row['mid_responder_l'] == peer['responder_L'].hex()
        assert row['mid_responder_p'] == peer['responder_P'].hex()
        assert row['mid_send_garbage_terminator'] == peer['send_garbage_terminator'].hex()
        assert row['mid_recv_garbage_terminator'] == peer['recv_garbage_terminator'].hex()
        assert row['out_session_id'] == peer['session_id'].hex()
        for _ in range(int(row['in_idx'])):
            reference.v2_enc_packet(peer, b"")
        ciphertext = reference.v2_enc_packet(
            peer,
            bytes.fromhex(row['in_contents']) * int(row['in_multiply']),
            bytes.fromhex(row['in_aad']), int(row['in_ignore']))
        if len(row['out_ciphertext']):
            assert row['out_ciphertext'] == ciphertext.hex()
        if len(row['out_ciphertext_endswith']):
            assert ciphertext.hex().endswith(row['out_ciphertext_endswith'])

with open(FILENAME_XSWIFTEC_INV_TEST, newline='', encoding='utf-8') as csvfile:
    print(f"Running {FILENAME_XSWIFTEC_INV_TEST} tests...")
    reader = csv.DictReader(csvfile)
    for row in reader:
        u = reference.FE.from_bytes(bytes.fromhex(row['u']))
        x = reference.FE.from_bytes(bytes.fromhex(row['x']))
        for case in range(8):
            ret = reference.xswiftec_inv(x, u, case)
            if ret is None:
                assert row[f"case{case}_t"] == ""
            else:
                assert row[f"case{case}_t"] == ret.to_bytes().hex()
                assert reference.xswiftec(u, ret) == x

with open(FILENAME_ELLSWIFT_DECODE_TEST, newline='', encoding='utf-8') as csvfile:
    print(f"Running {FILENAME_ELLSWIFT_DECODE_TEST} tests...")
    reader = csv.DictReader(csvfile)
    for row in reader:
        ellswift = bytes.fromhex(row['ellswift'])
        assert reference.ellswift_decode(ellswift).hex() == row['x']
