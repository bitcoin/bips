use hex;
use log::debug;
use once_cell::sync::Lazy;

use bitcoin::{Network, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::p2mr::{P2mrBuilder, P2mrSpendInfo};
use bitcoin::taproot::{LeafVersion, TapTree, ScriptLeaves, TapLeafHash, TaprootMerkleBranch, TapNodeHash};

use p2mr_ref::data_structures::{TVScriptTree, TestVector, Direction, TestVectors, UtxoReturn};
use p2mr_ref::error::P2MRError;
use p2mr_ref::{create_p2mr_utxo};

//  This file contains tests that execute against the BIP360 script-path-only test vectors.

static TEST_VECTORS: Lazy<TestVectors> = Lazy::new(|| {
    let bip360_test_vectors = include_str!("../../common/tests/data/p2mr_construction.json");
    let test_vectors: TestVectors = serde_json::from_str(bip360_test_vectors).unwrap();
    assert_eq!(test_vectors.version, 1);
    test_vectors
});

// Helper to run a P2MR error test vector
fn assert_p2mr_error<F>(id: &str, process: F, expected: P2MRError)
where
    F: FnOnce(&TestVector) -> anyhow::Result<()>,
{
    let _ = env_logger::try_init();
    let tv = TEST_VECTORS.test_vector_map.get(id).unwrap();
    let err = process(tv).unwrap_err();
    assert!(matches!(err.downcast_ref::<P2MRError>(), Some(e) if std::mem::discriminant(e) == std::mem::discriminant(&expected)));
}

// Helper to run a P2MR positive test vector by its ID.
fn run_p2mr_test(id: &str) {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error
    let test_vector = TEST_VECTORS.test_vector_map.get(id).unwrap();
    process_test_vector_p2mr(test_vector).unwrap();
}

// Error Tests
#[test]
fn test_p2tr_using_v2_witness_version_error() {
    assert_p2mr_error(
        "p2mr_misuse_v2_witness_version_with_pubkey_error",
        process_test_vector_p2tr,
        P2MRError::P2trRequiresWitnessVersion1,
    );
}

// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-2-script-path-spend-simple
#[test]
fn test_p2mr_missing_leaf_script_tree_error() {
    assert_p2mr_error(
        "p2mr_null_or_missing_script_tree_error",
        process_test_vector_p2mr,
        P2MRError::MissingScriptTreeLeaf,
    );
}

// Positive Tests
// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-2-script-path-spend-simple
#[test]
fn test_p2mr_single_leaf_script_tree() {
    run_p2mr_test("p2mr_single_leaf_script_tree");
}

/// Verifies that P2MR construction succeeds when leaves carry non-standard leaf versions (e.g. 0xfa).
/// Unknown leaf versions are accepted: the TapLeaf hash is computed using the supplied version,
/// and the resulting merkle root and control blocks are valid.
#[test]
fn test_p2mr_different_version_leaves() {
    run_p2mr_test("p2mr_different_version_leaves");
}

#[test]
fn test_p2mr_simple_lightning_contract() {
    run_p2mr_test("p2mr_simple_lightning_contract")
}

#[test]
fn test_p2mr_two_leaf_same_version() {
    run_p2mr_test("p2mr_two_leaf_same_version");
}

#[test]
fn test_p2mr_three_leaf_complex() {
    run_p2mr_test("p2mr_three_leaf_complex");
}

#[test]
fn test_p2mr_three_leaf_alternative() {
    run_p2mr_test("p2mr_three_leaf_alternative");
}

#[test]
fn test_p2mr_duplicate_leaves() {
    run_p2mr_test("p2mr_duplicate_leaves");
}

fn process_test_vector_p2tr(test_vector: &TestVector) -> anyhow::Result<()> {
    let script_pubkey_hex = test_vector.expected.script_pubkey.as_ref().unwrap();
    let script_pubkey_bytes = hex::decode(script_pubkey_hex).unwrap();
    if script_pubkey_bytes[0] != 0x51 {
        return Err(P2MRError::P2trRequiresWitnessVersion1.into());
    }
    Ok(())
}

fn process_test_vector_p2mr(test_vector: &TestVector) -> anyhow::Result<()> {

    let tv_script_tree: Option<&TVScriptTree> = test_vector.given.script_tree.as_ref();

    let mut tv_leaf_count: u8 = 0;
    let mut current_branch_id: u8 = 0;

    // TaprootBuilder expects the addition of each leaf script with its associated depth
    // It then constructs the binary tree in DFS order, sorting siblings lexicographically & combining them via BIP341's tapbranch_hash
    // Use of TaprootBuilder avoids user error in constructing branches manually and ensures Merkle tree correctness and determinism
    let mut p2mr_builder: P2mrBuilder = P2mrBuilder::new();

    // 1)  traverse test vector script tree and add leaves to P2MR builder
    if let Some(script_tree) = tv_script_tree {

        script_tree.traverse_with_right_subtree_first(0, Direction::Root, &mut |node, depth, direction| {

            if let TVScriptTree::Leaf(tv_leaf) = node {

                let tv_leaf_script_bytes = hex::decode(&tv_leaf.script).unwrap();
                let tv_leaf_script_buf = ScriptBuf::from_bytes(tv_leaf_script_bytes.clone());
                let tv_leaf_version = LeafVersion::from_consensus(tv_leaf.leaf_version).unwrap();

                let mut modified_depth = depth + 1;
                if direction == Direction::Root {
                    modified_depth = depth;
                }
                debug!("traverse_with_depth: leaf_count: {}, depth: {}, modified_depth: {}, direction: {}, tv_leaf_script: {}",
                    tv_leaf_count, depth, modified_depth, direction, tv_leaf.script);

                // NOTE: Some of the test vectors in this project specify leaves with non-standard versions (ie: 250 / 0xfa)
                p2mr_builder = p2mr_builder.clone().add_leaf_with_ver(depth, tv_leaf_script_buf.clone(), tv_leaf_version)
                    .unwrap_or_else(|e| {
                        panic!("Failed to add leaf: {:?}", e);
                    });

                tv_leaf_count += 1;
            } else if let TVScriptTree::Branch { left, right } = node {
                debug!("branch_count: {}, depth: {}, direction: {}", current_branch_id, depth, direction);
                current_branch_id += 1;
            }
        });
    } else {
        return Err(P2MRError::MissingScriptTreeLeaf.into());
    }

    let spend_info: P2mrSpendInfo = p2mr_builder.clone()
        .finalize()
        .unwrap_or_else(|e| {
            panic!("finalize failed: {:?}", e);
        });

    let derived_merkle_root: TapNodeHash = spend_info.merkle_root.unwrap();

    // 2)  verify derived merkle root against test vector
    let test_vector_merkle_root = test_vector.intermediary.merkle_root.as_ref().unwrap();
    assert_eq!(
        derived_merkle_root.to_string(),
        *test_vector_merkle_root,
        "Merkle root mismatch"
    );
    debug!("just passed merkle root validation: {}", test_vector_merkle_root);

    let expected_control_blocks = test_vector.expected.script_path_control_blocks.as_ref().unwrap();
    let tap_tree: TapTree = p2mr_builder.clone().into_inner().try_into_taptree().unwrap();
    let script_leaves: ScriptLeaves = tap_tree.script_leaves();

    // 3) Iterate through leaves of derived script tree and verify control blocks
    for derived_leaf in script_leaves {

        let version = derived_leaf.version();
        let script = derived_leaf.script();
        let merkle_branch: &TaprootMerkleBranch = derived_leaf.merkle_branch();

        let derived_leaf_hash: TapLeafHash = TapLeafHash::from_script(script, version);
        let leaf_hash = hex::encode(derived_leaf_hash.as_raw_hash().to_byte_array());

        // BIP341 control byte layout: bits 7..1 = leaf_version, bit 0 = parity.
        // `& 0xfe` (11111110) masks off bit 0, isolating the leaf version in the upper 7 bits.
        // `| 0x01` sets bit 0 to 1: P2MR has no key-spend path, so parity is always 1.
        let control_byte = (version.to_consensus() & 0xfe) | 0x01u8;
        let mut cb_buf = vec![control_byte];
        merkle_branch
            .encode(&mut cb_buf)
            .expect("encode should not fail");
        let derived_serialized_control_block = hex::encode(&cb_buf);

        assert!(
            expected_control_blocks.contains(&derived_serialized_control_block),
            "Unexpected control block: {}", derived_serialized_control_block
        );

        debug!("leaf_hash: {}, derived_serialized_control_block: {}", leaf_hash, derived_serialized_control_block);
    }

    let p2mr_utxo_return: UtxoReturn = create_p2mr_utxo(derived_merkle_root.to_string());

    assert_eq!(
        p2mr_utxo_return.script_pubkey_hex,
        *test_vector.expected.script_pubkey.as_ref().unwrap(),
        "Script pubkey mismatch"
    );
    debug!("just passed script_pubkey validation. script_pubkey = {}", p2mr_utxo_return.script_pubkey_hex);

    let bech32m_address: String = p2mr_utxo_return.bech32m_address;
    debug!("derived bech32m address for bitcoin_network: {} : {}", p2mr_utxo_return.bitcoin_network, bech32m_address);

    if p2mr_utxo_return.bitcoin_network == Network::Bitcoin {
        assert_eq!(bech32m_address, *test_vector.expected.bip350_address.as_ref().unwrap(), "Bech32m address mismatch.");
    }

    Ok(())
}
