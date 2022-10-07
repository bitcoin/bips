import csv
import os
import sys

import reference

with open(os.path.join(sys.path[0], 'packet_encoding_test_vectors.csv'), newline='') as csvfile:
    reader = csv.reader(csvfile)
    reader.__next__()
    for row in reader:
        in_idx, in_priv_ours, in_ellswift_ours, in_ellswift_theirs, in_initiating, in_content, in_multiply, in_aad, in_ignore, mid_x_ours, mid_x_shared, mid_shared_secret, mid_initiator_l, mid_initiator_p, mid_responder_l, mid_responder_p, mid_send_garbage_terminator, mid_recv_garbage_terminator, mid_session_id, out_ciphertext, out_ciphertext_endswith = row

        assert mid_x_ours == (int.from_bytes(bytes.fromhex(in_priv_ours), 'big') * reference.SECP256K1_G).x.to_bytes().hex()
        assert mid_x_shared == reference.ellswift_ecdh_xonly(bytes.fromhex(in_ellswift_theirs), bytes.fromhex(in_priv_ours)).hex()
        assert mid_shared_secret == reference.v2_ecdh(bytes.fromhex(in_priv_ours), bytes.fromhex(in_ellswift_theirs), bytes.fromhex(in_ellswift_ours), int(in_initiating)).hex()

        peer = reference.initialize_v2_transport(bytes.fromhex(mid_shared_secret), int(in_initiating))
        assert mid_initiator_l == peer['initiator_L'].hex()
        assert mid_initiator_p == peer['initiator_P'].hex()
        assert mid_responder_l == peer['responder_L'].hex()
        assert mid_responder_p == peer['responder_P'].hex()
        assert mid_send_garbage_terminator == peer['send_garbage_terminator'].hex()
        assert mid_recv_garbage_terminator == peer['recv_garbage_terminator'].hex()
        assert mid_session_id == peer['session_id'].hex()
        for _ in range(int(in_idx)):
            reference.v2_enc_packet(peer, b"")
        ciphertext = reference.v2_enc_packet(peer, bytes.fromhex(in_content) * int(in_multiply), bytes.fromhex(in_aad), int(in_ignore))
        if len(out_ciphertext):
            assert out_ciphertext == ciphertext.hex()
        if len(out_ciphertext_endswith):
            assert ciphertext.hex().endswith(out_ciphertext_endswith)

with open(os.path.join(sys.path[0], 'xswiftec_test_vectors.csv'), newline='') as csvfile:
    reader = csv.reader(csvfile)
    reader.__next__()
    for row in reader:
        u = reference.FE.from_bytes(bytes.fromhex(row[0]))
        x = reference.FE.from_bytes(bytes.fromhex(row[1]))
        for case in range(8):
            ret = reference.xswiftec_inv(x, u, case)
            if ret is None:
                assert row[2 + case] == ""
            else:
                assert row[2 + case] == ret.to_bytes().hex()
                assert reference.xswiftec(u, ret) == x

with open(os.path.join(sys.path[0], 'xelligatorswift_test_vectors.csv'), newline='') as csvfile:
    reader = csv.reader(csvfile)
    reader.__next__()
    for row in reader:
        ellswift = bytes.fromhex(row[0])
        x = bytes.fromhex(row[1])
        assert reference.ellswift_ecdh_xonly(ellswift, (1).to_bytes(32, 'big')) == x
