use std::collections::HashSet;
use bitcoin::{Address, Network, ScriptBuf, Script};
use bitcoin::taproot::{LeafVersion, TapTree, ScriptLeaves, TapLeafHash, TaprootMerkleBranch};
use bitcoin::p2qrh::{P2qrhBuilder, P2qrhScriptBuf, P2qrhControlBlock, P2qrhSpendInfo };
use bitcoin::hashes::Hash;

use hex;
use log::debug;
use once_cell::sync::Lazy;

use p2qrh_ref::data_structures::{TVScriptTree, TestVector, Direction, TestVectors};
use p2qrh_ref::error::P2QRHError;

//  This file contains tests that execute against the BIP360 script-path-only test vectors.

static TEST_VECTORS: Lazy<TestVectors> = Lazy::new(|| {
    let bip360_test_vectors = include_str!("../tests/data/p2qrh_construction.json");
    let test_vectors: TestVectors = serde_json::from_str(bip360_test_vectors).unwrap();
    assert_eq!(test_vectors.version, 1);
    test_vectors
});

static P2QRH_MISSING_LEAF_SCRIPT_TREE_ERROR_TEST: &str = "p2qrh_missing_leaf_script_tree_error";
static P2QRH_SINGLE_LEAF_SCRIPT_TREE_TEST: &str = "p2qrh_single_leaf_script_tree";
static P2QRH_DIFFERENT_VERSION_LEAVES_TEST: &str = "p2qrh_different_version_leaves";
static P2QRH_TWO_LEAF_SAME_VERSION_TEST: &str = "p2qrh_two_leaf_same_version";
static P2QRH_THREE_LEAF_COMPLEX_TEST: &str = "p2qrh_three_leaf_complex";
static P2QRH_THREE_LEAF_ALTERNATIVE_TEST: &str = "p2qrh_three_leaf_alternative";

// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-2-script-path-spend-simple
#[test]
fn test_p2qrh_missing_leaf_script_tree_error() {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let test_vectors = &*TEST_VECTORS;
    let test_vector = test_vectors.test_vector_map.get(P2QRH_MISSING_LEAF_SCRIPT_TREE_ERROR_TEST).unwrap();
    let test_result: anyhow::Result<()> = process_test_vector_p2qrh(test_vector);
    assert!(matches!(test_result.unwrap_err().downcast_ref::<P2QRHError>(),
        Some(P2QRHError::MissingScriptTreeLeaf)));
}

// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-2-script-path-spend-simple
#[test]
fn test_p2qrh_single_leaf_script_tree() {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let test_vectors = &*TEST_VECTORS;
    let test_vector = test_vectors.test_vector_map.get(P2QRH_SINGLE_LEAF_SCRIPT_TREE_TEST).unwrap();
    process_test_vector_p2qrh(test_vector).unwrap();
}

#[test]
fn test_p2qrh_different_version_leaves() {

    let test_vectors = &*TEST_VECTORS;
    let test_vector = test_vectors.test_vector_map.get(P2QRH_DIFFERENT_VERSION_LEAVES_TEST).unwrap();
    process_test_vector_p2qrh(test_vector).unwrap();
}

#[test]
fn test_p2qrh_two_leaf_same_version() {

    let test_vectors = &*TEST_VECTORS;
    let test_vector = test_vectors.test_vector_map.get(P2QRH_TWO_LEAF_SAME_VERSION_TEST).unwrap();
    process_test_vector_p2qrh(test_vector).unwrap();
}

#[test]
fn test_p2qrh_three_leaf_complex() {

    let test_vectors = &*TEST_VECTORS;
    let test_vector = test_vectors.test_vector_map.get(P2QRH_THREE_LEAF_COMPLEX_TEST).unwrap();
    process_test_vector_p2qrh(test_vector).unwrap();
}

#[test]
fn test_p2qrh_three_leaf_alternative() {

    let test_vectors = &*TEST_VECTORS;
    let test_vector = test_vectors.test_vector_map.get(P2QRH_THREE_LEAF_ALTERNATIVE_TEST).unwrap();
    process_test_vector_p2qrh(test_vector).unwrap();
}

fn process_test_vector_p2qrh(test_vector: &TestVector) -> anyhow::Result<()> {

    let tv_script_tree: Option<&TVScriptTree> = test_vector.given.script_tree.as_ref();

    let mut tv_leaf_count: u8 = 0;
    let mut current_branch_id: u8 = 0;

    // TaprootBuilder expects the addition of each leaf script with its associated depth
    // It then constructs the binary tree in DFS order, sorting siblings lexicographically & combining them via BIP341's tapbranch_hash
    // Use of TaprootBuilder avoids user error in constructing branches manually and ensures Merkle tree correctness and determinism
    let mut p2qrh_builder: P2qrhBuilder = P2qrhBuilder::new();

    let mut control_block_data: Vec<(ScriptBuf, LeafVersion)> = Vec::new();

    // 1)  traverse test vector script tree and add leaves to P2QRH builder
    if let Some(script_tree) = tv_script_tree {

        script_tree.traverse_with_right_subtree_first(0, Direction::Root,&mut |node, depth, direction| {

            if let TVScriptTree::Leaf(tv_leaf) = node {
                
                let tv_leaf_script_bytes = hex::decode(&tv_leaf.script).unwrap();
    
                // NOTE:  IOT to execute script_info.control_block(..), will add these to a vector
                let tv_leaf_script_buf = ScriptBuf::from_bytes(tv_leaf_script_bytes.clone());
                let tv_leaf_version = LeafVersion::from_consensus(tv_leaf.leaf_version).unwrap();
                control_block_data.push((tv_leaf_script_buf.clone(), tv_leaf_version));
                
                let mut modified_depth = depth + 1;
                if direction == Direction::Root {
                    modified_depth = depth;
                }
                debug!("traverse_with_depth: leaf_count: {}, depth: {}, modified_depth: {}, direction: {}, tv_leaf_script: {}", 
                    tv_leaf_count, depth, modified_depth, direction, tv_leaf.script);
                
                // NOTE: Some of the the test vectors in this project specify leaves with non-standardversions (ie: 250 / 0xfa)
                p2qrh_builder = p2qrh_builder.clone().add_leaf_with_ver(depth, tv_leaf_script_buf.clone(), tv_leaf_version)
                    .unwrap_or_else(|e| {
                        panic!("Failed to add leaf: {:?}", e);
                    });
    
                tv_leaf_count += 1;
            } else if let TVScriptTree::Branch { left, right } = node {
                // No need to calculate branch hash.
                // TaprootBuilder does this for us.
                debug!("branch_count: {}, depth: {}, direction: {}", current_branch_id, depth, direction);
                current_branch_id += 1;
            }
        });
    }else {
        return Err(P2QRHError::MissingScriptTreeLeaf.into());
    }

    let spend_info: P2qrhSpendInfo = p2qrh_builder.clone()
        .finalize()
        .unwrap_or_else(|e| {
            panic!("finalize failed: {:?}", e);
        });

    let derived_merkle_root = spend_info.merkle_root.unwrap();

    // 2)  verify derived merkle root against test vector
    let test_vector_merkle_root = test_vector.intermediary.merkle_root.as_ref().unwrap();
    assert_eq!( 
        derived_merkle_root.to_string(),
        *test_vector_merkle_root, 
        "Merkle root mismatch"
    );
    debug!("just passed merkle root validation: {}", test_vector_merkle_root);

    let test_vector_leaf_hashes_vec: Vec<String> = test_vector.intermediary.leaf_hashes.clone();
    let test_vector_leaf_hash_set: HashSet<String> = test_vector_leaf_hashes_vec.iter().cloned().collect();
    let test_vector_control_blocks_vec = &test_vector.expected.script_path_control_blocks;
    let test_vector_control_blocks_set: HashSet<String> = test_vector_control_blocks_vec.as_ref().unwrap().iter().cloned().collect();
    let tap_tree: TapTree = p2qrh_builder.clone().into_inner().try_into_taptree().unwrap();
    let script_leaves: ScriptLeaves = tap_tree.script_leaves();

    // TO-DO:  Investigate why the ordering of script leaves seems to be reverse of test vectors.
    // 3) Iterate through leaves of derived script tree and verify both script leaf hashes and control blocks
    for (i, derived_leaf) in script_leaves.enumerate() {

        let version = derived_leaf.version();
        let script = derived_leaf.script();
        let merkle_branch: &TaprootMerkleBranch = derived_leaf.merkle_branch();

        let derived_leaf_hash: TapLeafHash = TapLeafHash::from_script(script, version);
        let leaf_hash = hex::encode(derived_leaf_hash.as_raw_hash().to_byte_array());
        assert!(
            test_vector_leaf_hash_set.contains(&leaf_hash),
            "Leaf hash not found in expected set for {}", leaf_hash
        );
        debug!("just passed leaf_hash validation: {}", leaf_hash);
    
        // Each leaf in the script tree has a corresponding control block.
        // Specific to P2TR, the 3 sections of the control block (control byte, public key & merkle path) are highlighted here:
        //    https://learnmeabitcoin.com/technical/upgrades/taproot/#script-path-spend-control-block
        // The control block, which includes the Merkle path, must be 33 + 32 * n bytes, where n is the number of Merkle path hashes (n ≥ 0).
        // There is no consensus limit on n, but large Merkle trees increase the witness size, impacting block weight.
        // NOTE:  Control blocks could have also been obtained from spend_info.control_block(..) using the data in control_block_data
        debug!("merkle_branch nodes: {:?}", merkle_branch);
        let derived_control_block: P2qrhControlBlock = P2qrhControlBlock{
            leaf_version: derived_leaf.version(),
            merkle_branch: merkle_branch.clone(),
        };
        let serialized_control_block = derived_control_block.serialize();
        debug!("derived_control_block: {:?}, merkle_branch size: {}, control_block size: {}, serialized size: {}", 
            derived_control_block,
            merkle_branch.len(),
            derived_control_block.size(),
            serialized_control_block.len());
        let derived_serialized_control_block = hex::encode(serialized_control_block);
        assert!(
            test_vector_control_blocks_set.contains(&derived_serialized_control_block),
            "Control block mismatch: {}, expected: {:?}", derived_serialized_control_block, test_vector_control_blocks_set
        );
        debug!("leaf_hash: {}, derived_serialized_control_block: {}", leaf_hash, derived_serialized_control_block);

    }

    /* commit (in scriptPubKey) to the merkle root of all the script path leaves. ie:
        This output key is what gets committed to in the final Taproot address (ie: scriptPubKey)
    */
    let script_buf: P2qrhScriptBuf = P2qrhScriptBuf::new_p2qrh(derived_merkle_root);
    let script: &Script = script_buf.as_script();
    let script_pubkey = script.to_hex_string();
    assert_eq!(script_pubkey, *test_vector.expected.script_pubkey.as_ref().unwrap());
    debug!("just passed script_pubkey validation. script_pubkey = {}", script_pubkey);

    // 4)  derive bech32m address and verify against test vector
    //     p2qrh adress is comprised of network HRP + WitnessProgram (version + program)
    let bech32m_address = Address::p2qrh(Some(derived_merkle_root), Network::Bitcoin);
    //let bech32m_address = Address::p2qrh(Some(derived_merkle_root), Network::Regtest);

    assert_eq!(bech32m_address.to_string(), *test_vector.expected.bip350_address.as_ref().unwrap(), "Bech32m address mismatch.");

    Ok(())
}
