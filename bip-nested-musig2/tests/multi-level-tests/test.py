"""Validate the committed nested key and nonce aggregation vectors."""
import json
from pathlib import Path

from tree import parse_forest
import reference as ref


def check_aggregation_errors(vectors, nonce_mode=False):
    assert vectors['error_test_cases'], 'No aggregation error cases found'
    for case in vectors['error_test_cases']:
        nodes = dict(parse_forest(case['tree']).walk())
        for path, index in case['leaf_key_indices'].items():
            nodes[path].pk = bytes.fromhex(vectors['pubkeys'][index])
            if nonce_mode:
                nodes[path].out = bytes.fromhex(vectors['pubnonces'][case['leaf_nonce_indices'][path]])
        try:
            for path, node in reversed(list(nodes.items())):
                if node.is_leaf():
                    continue
                ordered = sorted(node.children, key=lambda child: child.pk)
                participants = [f'{path}/{child.value}' for child in ordered]
                operation = 'key_agg'
                node.keyagg_ctx = ref.key_agg([child.pk for child in ordered])
                if node.is_root and not nonce_mode:
                    operation = 'apply_tweaks'
                    node.keyagg_ctx = ref.apply_tweaks(node.keyagg_ctx,
                        [bytes.fromhex(t) for t in case['tweaks']], case['is_xonly'])
                node.pk = ref.cbytes(node.keyagg_ctx.Q)
                if nonce_mode:
                    operation = 'nonce_agg'
                    participants = [f'{path}/{child.value}' for child in node.children]
                    node.out_internal = ref.nonce_agg([child.out for child in node.children])
                    if not node.is_root:
                        operation = 'nonce_agg_ext'
                        node.out = ref.nonce_agg_ext(node.out_internal, node.keyagg_ctx.Q)
        except (ref.InvalidContributionError, ValueError) as error:
            expected = case['error']
            assert (operation, path) == (expected['operation'], expected['node']), f'{case["id"]}: wrong failure location'
            if isinstance(error, ref.InvalidContributionError):
                assert expected['type'] == 'invalid_contribution', case['id']
                assert (error.signer, error.contrib) == (expected['signer'], expected['contrib']), case['id']
                if 'participant' in expected:
                    assert participants[error.signer] == expected['participant'], case['id']
            else:
                assert expected['type'] == 'value' and str(error) == expected['message'], f'{case["id"]}: {error}'
        else:
            raise AssertionError(f'{case["id"]}: expected error was not raised')


def test_key_agg():
    vector_path = Path(__file__).parent / 'vectors' / 'key_agg_vectors.json'
    vectors = json.loads(vector_path.read_text())
    pubkeys = [ref.PlainPk(bytes.fromhex(key)) for key in vectors['pubkeys']]
    cases = vectors['valid_test_cases']
    assert cases, 'No key-aggregation cases found'
    check_aggregation_errors(vectors)

    for case in cases:
        case_id = case['id']
        nodes = dict(parse_forest(case['tree']).walk())
        leaf_paths = {path for path, node in nodes.items() if node.is_leaf()}
        aggregate_paths = set(nodes) - leaf_paths
        assert set(case['leaf_key_indices']) == leaf_paths, f'{case_id}: incorrect leaf assignments'
        assert set(case['expected']) == aggregate_paths, f'{case_id}: incorrect expected node paths'

        for path, index in case['leaf_key_indices'].items():
            assert 0 <= index < len(pubkeys), f'{case_id}: {path}: invalid public-key index'
            nodes[path].pk = pubkeys[index]

        tweaks = [bytes.fromhex(tweak) for tweak in case['tweaks']]
        # Reversing preorder ensures each child is aggregated before its parent.
        for path, node in reversed(list(nodes.items())):
            if node.is_leaf():
                continue
            child_keys = ref.key_sort([child.pk for child in node.children])
            node.keyagg_ctx = ref.key_agg(child_keys)
            if node.is_root:
                node.keyagg_ctx = ref.apply_tweaks(node.keyagg_ctx, tweaks, case['is_xonly'])
            node.pk = ref.PlainPk(ref.cbytes(node.keyagg_ctx.Q))
            expected = bytes.fromhex(case['expected'][path])
            assert node.pk == expected, (
                f'{case_id}: {path}: aggregate key mismatch\n'
                f'  expected: {expected.hex().upper()}\n'
                f'  actual:   {node.pk.hex().upper()}\n'
            )

def test_nonce_agg():
    vector_path = Path(__file__).parent / 'vectors' / 'nonce_agg_vectors.json'
    vectors = json.loads(vector_path.read_text())
    pubkeys = [ref.PlainPk(bytes.fromhex(key)) for key in vectors['pubkeys']]
    pubnonces = [bytes.fromhex(nonce) for nonce in vectors['pubnonces']]
    cases = vectors['valid_test_cases']
    assert cases, 'No nonce-aggregation cases found'
    check_aggregation_errors(vectors, nonce_mode=True)

    for case in cases:
        case_id = case['id']
        nodes = dict(parse_forest(case['tree']).walk())
        leaf_paths = {path for path, node in nodes.items() if node.is_leaf()}
        assert set(case['leaf_key_indices']) == leaf_paths, f'{case_id}: incorrect leaf key assignments'
        assert set(case['leaf_nonce_indices']) == leaf_paths, f'{case_id}: incorrect leaf nonce assignments'
        assert set(case['expected']) == set(nodes) - leaf_paths, f'{case_id}: incorrect expected node paths'

        for path in leaf_paths:
            key_index = case['leaf_key_indices'][path]
            nonce_index = case['leaf_nonce_indices'][path]
            assert 0 <= key_index < len(pubkeys), f'{case_id}: {path}: invalid public-key index'
            assert 0 <= nonce_index < len(pubnonces), f'{case_id}: {path}: invalid public-nonce index'
            nodes[path].pk = pubkeys[key_index]
            nodes[path].out = pubnonces[nonce_index]

        for path, node in reversed(list(nodes.items())):
            if node.is_leaf():
                continue
            # Reconstruct the subgroup key, retaining its full compressed parity
            # when it becomes a participant key at the parent.
            node.keyagg_ctx = ref.key_agg(ref.key_sort([child.pk for child in node.children]))
            node.pk = ref.PlainPk(ref.cbytes(node.keyagg_ctx.Q))
            node.out_internal = ref.nonce_agg([child.out for child in node.children])
            if not node.is_root:
                node.out = ref.nonce_agg_ext(node.out_internal, node.keyagg_ctx.Q)
            expected = case['expected'][path]
            assert set(expected) == {'internal_nonce', 'external_nonce'}, f'{case_id}: {path}: incorrect nonce fields'
            for field, actual in [('internal_nonce', node.out_internal), ('external_nonce', node.out)]:
                value = expected[field]
                wanted = None if value is None else bytes.fromhex(value)
                assert actual == wanted, (
                    f'{case_id}: {path}: {field} mismatch\n'
                    f'  expected: {value}\n'
                    f'  actual:   {None if actual is None else actual.hex().upper()}'
                )


def check_sign_errors(vectors):
    """Exercise Sign/PartialSigVerify directly with the balanced tree's public session."""
    for group in ('sign_error_test_cases', 'verify_fail_test_cases', 'verify_error_test_cases'):
        assert vectors[group], f'No {group} found'
        for case in vectors[group]:
            assert case['tree'] == 'G(A,B),H(C,D)', case['id']
            nodes = dict(parse_forest(case['tree']).walk())
            for path, index in case['leaf_key_indices'].items():
                nodes[path].pk = ref.PlainPk(bytes.fromhex(vectors['pubkeys'][index]))
            # Only the opposite subgroup needs aggregation here. The signing
            # function reconstructs G and the root from its cosigner key path.
            other = nodes['root/H']
            other.pk = ref.cbytes(ref.key_agg(ref.key_sort([child.pk for child in other.children])).Q)
            signer = nodes[case['signer']]
            siblings = [child.pk for child in nodes['root/G'].children if child is not signer]
            ctx = ref.SessionContext(
                [bytes.fromhex(vectors['aggnonces'][i]) for i in case['nonce_path_indices']],
                [[other.pk], siblings], [bytes.fromhex(t) for t in case['tweaks']],
                case['is_xonly'], bytes.fromhex(vectors['msgs'][case['msg_index']]))
            try:
                if group == 'sign_error_test_cases':
                    ref.sign(bytearray.fromhex(vectors['secnonces'][case['secnonce_index']]),
                             bytes.fromhex(vectors['sk']), ctx)
                else:
                    valid = ref.partial_sig_verify(
                        bytes.fromhex(vectors['psigs'][case['psig_index']]),
                        bytes.fromhex(vectors['pubnonces'][case['leaf_nonce_indices'][case['signer']]]),
                        signer.pk, ctx)
            except (ref.InvalidContributionError, ValueError) as error:
                assert group != 'verify_fail_test_cases', f'{case["id"]}: expected False, not an exception'
                expected = case['error']
                if isinstance(error, ref.InvalidContributionError):
                    assert expected['type'] == 'invalid_contribution', case['id']
                    assert (error.signer, error.contrib) == (expected['signer'], expected['contrib']), case['id']
                else:
                    assert expected['type'] == 'value' and str(error) == expected['message'], f'{case["id"]}: {error}'
            else:
                assert group == 'verify_fail_test_cases', f'{case["id"]}: expected error was not raised'
                assert valid is False and case['expected'] is False, f'{case["id"]}: invalid signature accepted'


def test_sign_verify():
    vector_path = Path(__file__).parent / 'vectors' / 'sign_verify_vectors.json'
    vectors = json.loads(vector_path.read_text())
    sk = bytes.fromhex(vectors['sk'])
    pubkeys = [ref.PlainPk(bytes.fromhex(key)) for key in vectors['pubkeys']]
    pubnonces = [bytes.fromhex(nonce) for nonce in vectors['pubnonces']]
    cases = vectors['valid_test_cases']
    assert cases, 'No signing cases found'
    check_sign_errors(vectors)
    assert ref.individual_pk(sk) == pubkeys[0], 'Dedicated signing key does not match public-key pool'

    for case in cases:
        case_id = case['id']
        nodes = dict(parse_forest(case['tree']).walk())
        leaf_paths = {path for path, node in nodes.items() if node.is_leaf()}
        assert set(case['leaf_key_indices']) == leaf_paths, f'{case_id}: incorrect key assignments'
        assert set(case['leaf_nonce_indices']) == leaf_paths, f'{case_id}: incorrect nonce assignments'
        signer_path = case['signer']
        assert signer_path in leaf_paths, f'{case_id}: signer is not a leaf'
        for path in leaf_paths:
            key_index = case['leaf_key_indices'][path]
            nonce_index = case['leaf_nonce_indices'][path]
            assert 0 <= key_index < len(pubkeys), f'{case_id}: {path}: invalid key index'
            assert 0 <= nonce_index < len(pubnonces), f'{case_id}: {path}: invalid nonce index'
            nodes[path].pk = pubkeys[key_index]
            nodes[path].out = pubnonces[nonce_index]
        signer = nodes[signer_path]
        assert signer.pk == ref.individual_pk(sk), f'{case_id}: wrong signer key'
        for path, node in reversed(list(nodes.items())):
            if node.is_leaf():
                continue
            node.keyagg_ctx = ref.key_agg(ref.key_sort([child.pk for child in node.children]))
            node.pk = ref.PlainPk(ref.cbytes(node.keyagg_ctx.Q))
            node.out_internal = ref.nonce_agg([child.out for child in node.children])
            if not node.is_root:
                node.out = ref.nonce_agg_ext(node.out_internal, node.keyagg_ctx.Q)

        msg_index = case['msg_index']
        assert 0 <= msg_index < len(vectors['msgs']), f'{case_id}: invalid message index'
        tweaks = [bytes.fromhex(tweak) for tweak in case['tweaks']]
        assert len(tweaks) == len(case['is_xonly']), f'{case_id}: mismatched tweak modes'
        contexts = {'root': ref.SessionContext([], [], tweaks, case['is_xonly'], bytes.fromhex(vectors['msgs'][msg_index]))}
        for path, node in nodes.items():
            parent_ctx = contexts[path]
            for index, child in enumerate(node.children):
                siblings = [sibling.pk for i, sibling in enumerate(node.children) if i != index]
                contexts[f'{path}/{child.value}'] = ref.SessionContext(
                    parent_ctx.nonce_path + [node.out_internal], parent_ctx.pk_tree + [siblings],
                    parent_ctx.tweaks, parent_ctx.is_xonly, parent_ctx.msg)
        ctx = contexts[signer_path]
        secnonce_index = case['secnonce_index']
        assert 0 <= secnonce_index < len(vectors['secnonces']), f'{case_id}: invalid secret-nonce index'
        # Fresh mutable state per public test case; Sign consumes this copy.
        secnonce = bytearray.fromhex(vectors['secnonces'][secnonce_index])
        assert len(secnonce) == 97 and secnonce[64:] == signer.pk, f'{case_id}: invalid secret nonce'
        k1, k2 = (int.from_bytes(secnonce[i:i+32], 'big') for i in (0, 32))
        assert 0 < k1 < ref.n and 0 < k2 < ref.n, f'{case_id}: invalid nonce scalars'
        pubnonce = ref.cbytes(ref.point_mul(ref.G, k1)) + ref.cbytes(ref.point_mul(ref.G, k2))
        assert pubnonce == signer.out, f'{case_id}: secret/public nonce mismatch'
        _, psig = ref.sign(secnonce, sk, ctx)
        expected = bytes.fromhex(case['expected'])
        assert psig == expected, (
            f'{case_id}: {signer_path}: partial signature mismatch\n'
            f'  expected: {expected.hex().upper()}\n'
            f'  actual:   {psig.hex().upper()}'
        )
        assert ref.partial_sig_verify(expected, signer.out, signer.pk, ctx), f'{case_id}: partial verification failed'


def test_sig_agg():
    vectors = json.loads((Path(__file__).parent / 'vectors' / 'sig_agg_vectors.json').read_text())
    for group in ('valid_test_cases', 'error_test_cases', 'verify_fail_test_cases'):
        assert vectors[group], f'No {group} for signature aggregation'
        for case in vectors[group]:
            nodes = dict(parse_forest(case['tree']).walk())
            leaves = {path for path, node in nodes.items() if node.is_leaf()}
            assert set(case['leaf_key_indices']) == set(case['leaf_nonce_indices']) == leaves
            assert set(case['psig_indices']) == set(nodes) - {'root'}
            for path in leaves:
                nodes[path].pk = ref.PlainPk(bytes.fromhex(vectors['pubkeys'][case['leaf_key_indices'][path]]))
                nodes[path].out = bytes.fromhex(vectors['pubnonces'][case['leaf_nonce_indices'][path]])
            for path, node in reversed(list(nodes.items())):
                if not node.is_leaf():
                    node.keyagg_ctx = ref.key_agg(ref.key_sort([child.pk for child in node.children]))
                    node.pk = ref.PlainPk(ref.cbytes(node.keyagg_ctx.Q))
                    node.out_internal = ref.nonce_agg([child.out for child in node.children])
                    if not node.is_root:
                        node.out = ref.nonce_agg_ext(node.out_internal, node.keyagg_ctx.Q)
            tweaks = [bytes.fromhex(t) for t in case['tweaks']]
            msg = bytes.fromhex(vectors['msgs'][case['msg_index']])
            contexts = {'root': ref.SessionContext([], [], tweaks, case['is_xonly'], msg)}
            for path, node in nodes.items():
                ctx = contexts[path]
                for i, child in enumerate(node.children):
                    contexts[f'{path}/{child.value}'] = ref.SessionContext(
                        ctx.nonce_path + [node.out_internal],
                        ctx.pk_tree + [[sibling.pk for j, sibling in enumerate(node.children) if i != j]],
                        tweaks, case['is_xonly'], msg)
            first_leaf = next(path for path, node in nodes.items() if node.is_leaf())
            rx = ref.xbytes(ref.get_session_values(contexts[first_leaf], nodes[first_leaf].pk)[4])
            psigs = {path: bytes.fromhex(vectors['psigs'][index]) for path, index in case['psig_indices'].items()}
            if group == 'error_test_cases':
                error = case['error']
                path = error['node']
                node = nodes[path]
                children = [f'{path}/{child.value}' for child in node.children]
                inputs = [psigs[p] for p in children]
                try:
                    if node.is_root:
                        ref.partial_sig_agg(inputs, rx, contexts[path], node.keyagg_ctx)
                    else:
                        ref.partial_sig_agg(inputs, rx)
                except ref.InvalidContributionError as actual:
                    assert error['type'] == 'invalid_contribution'
                    assert (actual.signer, actual.contrib) == (error['signer'], error['contrib']), case['id']
                    assert children[actual.signer] == error['participant'], case['id']
                else:
                    raise AssertionError(f'{case["id"]}: invalid partial signature accepted')
                continue
            if group == 'verify_fail_test_cases':
                path = case['participant']
                node = nodes[path]
                assert ref.partial_sig_verify(psigs[path], node.out, node.pk, contexts[path]) is False, case['id']
            else:
                assert set(case['expected']) == set(nodes) - leaves
                for path, psig in psigs.items():
                    node = nodes[path]
                    assert ref.partial_sig_verify(psig, node.out, node.pk, contexts[path]), f'{case["id"]}: {path}: invalid contribution'
            # Recompute subgroup sums so a corrupt leaf propagates to the root.
            for path, node in reversed(list(nodes.items())):
                if node.is_leaf():
                    node.out_ = psigs[path]
                    continue
                inputs = [child.out_ for child in node.children]
                node.out_ = ref.partial_sig_agg(inputs, rx, contexts[path], node.keyagg_ctx) if node.is_root else ref.partial_sig_agg(inputs, rx)
                if group == 'valid_test_cases':
                    actual = rx + node.out_ if node.is_root else node.out_
                    assert actual == bytes.fromhex(case['expected'][path]), f'{case["id"]}: {path}: incorrect aggregation'
                    if not node.is_root:
                        assert node.out_ == psigs[path], f'{case["id"]}: {path}: inconsistent pooled subgroup signature'
            root = nodes['root']
            key = ref.get_xonly_pk(ref.apply_tweaks(root.keyagg_ctx, tweaks, case['is_xonly']))
            valid = ref.schnorr_verify(msg, key, rx + root.out_)
            if group == 'valid_test_cases':
                assert valid is True, f'{case["id"]}: valid aggregate signature failed BIP340 verification'
            else:
                assert case['expected'] is False
                assert valid is False, f'{case["id"]}: corrupted aggregate signature unexpectedly verified'



def test_session_nonce_validation():
    from unittest.mock import patch

    pk = ref.PlainPk(ref.cbytes(ref.G))
    finite = ref.cbytes(ref.G)
    zero = bytes(33)
    valid = finite + finite

    def check_failure(nonces, level):
        ctx = ref.SessionContext(nonces, [[], [], []], [], [], bytes(32))
        try:
            ref.get_session_values(ctx, pk)
        except ref.InvalidContributionError as error:
            assert (error.signer, error.contrib) == (level, 'aggnonce')
        else:
            raise AssertionError(f'Expected invalid nonce blame at level {level}')

    # Malformed encodings and lengths must blame the actual path level.
    for level in range(3):
        for bad in (valid[:-1], valid + b'\x00', b'\x04' + valid[1:], finite + b'\x04' + finite[1:]):
            nonces = [valid, valid, valid]
            nonces[level] = bad
            check_failure(nonces, level)
    for level in (1, 2):
        for bad in (zero + finite, finite + zero):
            nonces = [valid, valid, valid]
            nonces[level] = bad
            check_failure(nonces, level)
        # Force a zero binding scalar to test a finite second point becoming infinity.
        nonces = [valid, valid, valid]
        marked = finite + ref.cbytes(ref.point_mul(ref.G, 2))
        nonces[level] = marked
        with patch.object(ref, 'agg_nonce_coeff_hash', side_effect=lambda nonce, key: 0 if nonce == marked else 1):
            check_failure(nonces, level)

    # A zero binding factor must also be rejected by the extension API itself.
    with patch.object(ref, 'agg_nonce_coeff_hash', return_value=0):
        try:
            ref.nonce_agg_ext(valid, ref.G)
        except ref.InvalidContributionError as error:
            assert (error.signer, error.contrib) == (None, 'aggnonce')
        else:
            raise AssertionError('NonceAggExt accepted an infinite transformed point')

    # Root infinity remains legal and uses the effective-nonce fallback R = G.
    ctx = ref.SessionContext([zero + zero, valid, valid], [[], [], []], [], [], bytes(32))
    assert ref.get_session_values(ctx, pk)[4] == ref.G


if __name__ == '__main__':
    test_key_agg()
    test_nonce_agg()
    test_sign_verify()
    test_sig_agg()
    test_session_nonce_validation()
