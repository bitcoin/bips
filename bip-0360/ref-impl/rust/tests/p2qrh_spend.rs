use log::info;
use bitcoin::blockdata::witness::Witness;

use p2qrh_ref::{ p2qrh_to_p2wpkh_tx, serialize_script };

use p2qrh_ref::data_structures::P2qrhSpendDetails;

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


// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
// Spends from a p2qrh UTXO to a p2wpk UTXO
#[test]
fn test_script_path_spend_signatures() {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let funding_tx_id_bytes: Vec<u8> =
        hex::decode("d1c40446c65456a9b11a9dddede31ee34b8d3df83788d98f690225d2958bfe3c").unwrap();

    // The input index of the funding tx
    let funding_tx_index: u32 = 0;

    let funding_utxo_amount_sats: u64 = 20000;

    // OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG
    let input_leaf_script_bytes: Vec<u8> =
        hex::decode("206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac").unwrap();

    // Modified from learnmeabitcoin example
    // Changed from c0 to c1 control byte to reflect p2qrh specification:  The parity bit of the control byte is always 1 since P2QRH does not have a key-spend path.
    let input_control_block_bytes: Vec<u8> =
        hex::decode("c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329").unwrap();

    let input_script_pubkey_bytes: Vec<u8> =
        hex::decode("5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80")
            .unwrap();
    let input_script_priv_key_bytes: Vec<u8> = hex::decode("9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189").unwrap();

    let leaf_script_pubkey_hash_bytes: Vec<u8> = hex::decode("0de745dc58d8e62e6f47bde30cd5804a82016f9e").unwrap();

    let output_amount_sats: u64 = 15000;

    let test_sighash_bytes: Vec<u8> = hex::decode("752453d473e511a0da2097d664d69fe5eb89d8d9d00eab924b42fc0801a980c9").unwrap();
    let test_signature_bytes: Vec<u8> = hex::decode("01769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01").unwrap();

    // Modified from learnmeabitcoin example
    // Changed from c0 to c1 control byte to reflect p2qrh specification:  The parity bit of the control byte is always 1 since P2QRH does not have a key-spend path.
    let test_witness_bytes: Vec<u8> = hex::decode("034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c7700615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac21c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329").unwrap();

    let result: P2qrhSpendDetails = p2qrh_to_p2wpkh_tx(funding_tx_id_bytes,
        funding_tx_index,
        funding_utxo_amount_sats,
        input_script_pubkey_bytes,
        input_control_block_bytes,
        leaf_script_pubkey_hash_bytes,
        input_leaf_script_bytes,
        input_script_priv_key_bytes,
        output_amount_sats
    );

    assert_eq!(result.tapscript_sighash.as_slice(), test_sighash_bytes.as_slice(), "sighash mismatch");
    assert_eq!(result.p2wpkh_sig_bytes, test_signature_bytes, "signature mismatch");
    assert_eq!(result.derived_witness_vec, test_witness_bytes, "derived_witness mismatch");

}

