use log::debug;
use once_cell::sync::Lazy;

use bitcoin::blockdata::witness::Witness;
use bitcoin::ScriptBuf;

use p2qrh_ref::data_structures::{TestVector, TestVectors};

static TEST_VECTORS: Lazy<TestVectors> = Lazy::new(|| {
    let bip360_test_vectors = include_str!("../tests/data/p2qrh_spend.json");
    let test_vectors: TestVectors = serde_json::from_str(bip360_test_vectors).unwrap();
    assert_eq!(test_vectors.version, 1);
    test_vectors
});

static P2QRH_SINGLE_LEAF_SCRIPT_TREE_NO_SIGS_TEST: &str = "p2qrh_single_leaf_script_tree_no_sigs";

/*  The rust-bitcoin crate does not provide a single high-level API that builds the full Taproot script-path witness stack for you.
    It does expose all the necessary types and primitives to build it manually and correctly.
 */

#[test]
fn test_p2qrh_single_leaf_script_tree_no_sigs() {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let test_vectors: &TestVectors = &*TEST_VECTORS;
    let test_vector: &TestVector = test_vectors.test_vector_map.get(P2QRH_SINGLE_LEAF_SCRIPT_TREE_NO_SIGS_TEST).unwrap();

    let mut witness: Witness= Witness::new();

    
    test_vector.given.script_inputs.as_ref().unwrap().iter().for_each(|tv_script_input| {
        let script_input_bytes = hex::decode(tv_script_input).unwrap();
        witness.push(script_input_bytes);
        
    });

    // Hint:  use https://learnmeabitcoin.com/technical/script/
    let tv_script_hex = test_vector.given.script_hex.as_ref().unwrap();
    let script_buf: ScriptBuf = ScriptBuf::from(hex::decode(tv_script_hex).unwrap());
    debug!("script asm: {}", script_buf.to_asm_string());
    witness.push(script_buf.to_bytes());

    let tv_control_block = test_vector.given.control_block.as_ref().unwrap();
    let control_block_bytes = hex::decode(tv_control_block).unwrap();
    witness.push(control_block_bytes);

    debug!("witness: {:?}", witness);

    // Concatenate all witness elements into a single hex string
    let mut witness_hex_string = String::new();
    for element in witness.iter() {
        witness_hex_string.push_str(&hex::encode(element));
    }
    debug!("witness hex: {}", witness_hex_string);

    let expected_witness = test_vector.expected.witness.as_ref().unwrap();
    assert_eq!(&witness_hex_string, expected_witness);
    
}



