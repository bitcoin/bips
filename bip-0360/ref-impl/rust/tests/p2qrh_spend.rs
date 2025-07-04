use log::{debug, info};
use once_cell::sync::Lazy;

use bitcoin::sighash::{EcdsaSighashType, Prevouts, TapSighash};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::ecdsa::Signature;
use bitcoin::{ Amount, TxOut, sighash::TapSighashType, transaction, ScriptBuf, WPubkeyHash,
    OutPoint,
    blockdata::witness::Witness,
    sighash::SighashCache,
    taproot::{LeafVersion, TapLeafHash},
    transaction::Transaction,
};

use p2qrh_ref::{
    data_structures::{TestVector, TestVectors},
    serialize_script,
};

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

// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-2-script-path-spend-simple
#[test]
fn test_script_path_spend_simple() {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let script_inputs_count = hex::decode("03").unwrap();
    let script_inputs_bytes: Vec<u8> = hex::decode("08").unwrap();
    let leaf_script_bytes: Vec<u8> = hex::decode("5887").unwrap();
    let control_block_bytes: Vec<u8> =
        hex::decode("c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329").unwrap();
    let test_witness_bytes: Vec<u8> = hex::decode(
        "03010802588721c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329",
    )
    .unwrap();

    let mut derived_witness: Witness = Witness::new();
    derived_witness.push(script_inputs_count);
    derived_witness.push(serialize_script(&script_inputs_bytes));
    derived_witness.push(serialize_script(&leaf_script_bytes));
    derived_witness.push(serialize_script(&control_block_bytes));

    info!("witness: {:?}", derived_witness);

    let derived_witness_vec: Vec<u8> = derived_witness.iter().flatten().cloned().collect();

    assert_eq!(derived_witness_vec, test_witness_bytes);
}


// https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
#[test]
fn test_script_path_spend_signatures() {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let input_tx_id_bytes =
        hex::decode("d1c40446c65456a9b11a9dddede31ee34b8d3df83788d98f690225d2958bfe3c").unwrap();

    let input_leaf_script_bytes: Vec<u8> =
        hex::decode("206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac").unwrap();
    let input_control_block_bytes: Vec<u8> =
        hex::decode("c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329").unwrap();
    let input_script_pubkey_bytes: Vec<u8> =
        hex::decode("5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80")
            .unwrap();
    let input_script_priv_key_bytes: Vec<u8> = hex::decode("9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189").unwrap();

    let spend_pubkey_hash_bytes: Vec<u8> = hex::decode("0de745dc58d8e62e6f47bde30cd5804a82016f9e").unwrap();

    let test_sighash_bytes: Vec<u8> = hex::decode("752453d473e511a0da2097d664d69fe5eb89d8d9d00eab924b42fc0801a980c9").unwrap();
    let test_p2wpkh_signature_bytes: Vec<u8> = hex::decode("01769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01").unwrap();
    let test_witness_bytes: Vec<u8> = hex::decode("034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329").unwrap();

    let mut txid_little_endian = input_tx_id_bytes.clone();
    txid_little_endian.reverse();

    
    // vin: Create TxIn from the input utxo
    // Details of this input tx are not known at this point
    let input_tx_in = bitcoin::TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::from_slice(&txid_little_endian).unwrap(), // bitcoin::Txid expects the bytes in little-endian format
            vout: 0,
        },
        script_sig: ScriptBuf::new(), // Empty for segwit transactions - script goes in witness
        sequence: transaction::Sequence::MAX, // Default sequence, allows immediate spending (no RBF or timelock)
        witness: bitcoin::Witness::new(), // Empty for now, will be filled with signature and pubkey after signing
    };

    let spend_wpubkey_hash = WPubkeyHash::from_byte_array(spend_pubkey_hash_bytes.try_into().unwrap());
    let spend_output: TxOut = TxOut {
        value: Amount::from_sat(15000),
        script_pubkey: ScriptBuf::new_p2wpkh(&spend_wpubkey_hash),
    };

    // The spend tx to eventually be signed and broadcast
    let mut unsigned_spend_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input_tx_in],
        output: vec![spend_output],
    };

    // Create SighashCache
    // At this point, sighash_cache does not know the values and type of input UTXO
    let mut tapscript_sighash_cache = SighashCache::new(&mut unsigned_spend_tx);

    // Create the leaf hash
    let leaf_version = LeafVersion::TapScript;
    let leaf_script = ScriptBuf::from_bytes(input_leaf_script_bytes.clone());
    let leaf_hash: TapLeafHash = TapLeafHash::from_script(&leaf_script, leaf_version);

    /*  prevouts parameter tells the sighash algorithm:
            1. The value of each input being spent (needed for fee calculation and sighash computation)
            2. The scriptPubKey of each input being spent (ie: type of output & how to validate the spend)
     */
    let prevouts = vec![TxOut {
        value: Amount::from_sat(20000),
        script_pubkey: ScriptBuf::from_bytes(input_script_pubkey_bytes.clone()),
    }];
    info!("prevouts: {:?}", prevouts);

    // Compute the sighash
    let tapscript_sighash: TapSighash = tapscript_sighash_cache.taproot_script_spend_signature_hash(
        0, // input_index
        &Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::All
    ).unwrap();

    assert_eq!(tapscript_sighash.as_byte_array().as_slice(), test_sighash_bytes.as_slice(), "sighash mismatch");
    info!("sighash: {:?}", tapscript_sighash);

    let spend_msg = Message::from(tapscript_sighash);

    // Signing: Sign the sighash using the secp256k1 library (re-exported by rust-bitcoin).
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&input_script_priv_key_bytes).unwrap();

    // Spending a p2tr UTXO thus using Schnorr signature
    // The aux_rand parameter ensures that signing the same message with the same key produces the same signature
    let p2wpkh_signature: bitcoin::secp256k1::schnorr::Signature = secp.sign_schnorr_with_aux_rand(
        &spend_msg, 
        &secret_key.keypair(&secp), 
        &[0u8; 32] // 32 zero bytes of auxiliary random data
    );
    let mut p2wpkh_sig_bytes: Vec<u8> = p2wpkh_signature.serialize().to_vec();
    p2wpkh_sig_bytes.push(EcdsaSighashType::All as u8);

    assert_eq!(p2wpkh_sig_bytes, test_p2wpkh_signature_bytes, "p2wpkh_signature mismatch");
    let p2wpkh_sig_hex = hex::encode(p2wpkh_sig_bytes.clone());
    info!("p2wpkh_signature: {:?}", p2wpkh_sig_hex);

    let mut derived_witness: Witness = Witness::new();
    derived_witness.push(hex::decode("03").unwrap());
    derived_witness.push(serialize_script(&p2wpkh_sig_bytes));
    derived_witness.push(serialize_script(&input_leaf_script_bytes));
    derived_witness.push(serialize_script(&input_control_block_bytes));

    let derived_witness_vec: Vec<u8> = derived_witness.iter().flatten().cloned().collect();

    assert_eq!(derived_witness_vec, test_witness_bytes, "derived_witness mismatch");

    let derived_witness_hex = hex::encode(derived_witness_vec);
    info!("derived_witness_hex: {:?}", derived_witness_hex);
}

#[test]
fn test_p2qrh_single_leaf_script_tree_no_sigs() {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let test_vectors: &TestVectors = &*TEST_VECTORS;
    let test_vector: &TestVector = test_vectors
        .test_vector_map
        .get(P2QRH_SINGLE_LEAF_SCRIPT_TREE_NO_SIGS_TEST)
        .unwrap();

    let mut witness: Witness = Witness::new();

    test_vector
        .given
        .script_inputs
        .as_ref()
        .unwrap()
        .iter()
        .for_each(|tv_script_input| {
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
