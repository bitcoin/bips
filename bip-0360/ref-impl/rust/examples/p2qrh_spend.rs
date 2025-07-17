use p2qrh_ref::{ pay_to_p2wpkh_tx, verify_schnorr_signature_via_bytes };

use p2qrh_ref::data_structures::SpendDetails;
use std::env;
use log::{info, error};

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> SpendDetails {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    // FUNDING_TX_ID environment variable is required
    let funding_tx_id: String = env::var("FUNDING_TX_ID")
        .unwrap_or_else(|_| {
            error!("FUNDING_TX_ID environment variable is required but not set");
            std::process::exit(1);
        });
    let funding_tx_id_bytes: Vec<u8> = hex::decode(funding_tx_id.clone()).unwrap();
    
    // FUNDING_UTXO_AMOUNT_SATS environment variable is required
    let funding_utxo_amount_sats: u64 = env::var("FUNDING_UTXO_AMOUNT_SATS")
        .unwrap_or_else(|_| {
            error!("FUNDING_UTXO_AMOUNT_SATS environment variable is required but not set");
            std::process::exit(1);
        })
        .parse::<u64>()
        .unwrap_or_else(|_| {
            error!("FUNDING_UTXO_AMOUNT_SATS must be a valid u64 integer");
            std::process::exit(1);
        });

    // The input index of the funding tx
    // Allow override via FUNDING_UTXO_INDEX environment variable
    let funding_utxo_index: u32 = env::var("FUNDING_UTXO_INDEX")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    info!("Funding tx id: {}, utxo index: {}", funding_tx_id, funding_utxo_index);

    // FUNDING_SCRIPT_PUBKEY environment variable is required
    let funding_script_pubkey_bytes: Vec<u8> = env::var("FUNDING_SCRIPT_PUBKEY")
        .map(|s| hex::decode(s).unwrap())
        .unwrap_or_else(|_| {
            error!("FUNDING_SCRIPT_PUBKEY environment variable is required but not set");
            std::process::exit(1);
        });

    let control_block_bytes: Vec<u8> = env::var("CONTROL_BLOCK_HEX")
        .map(|s| hex::decode(s).unwrap())
        .unwrap_or_else(|_| {
            error!("CONTROL_BLOCK_HEX environment variable is required but not set");
            std::process::exit(1);
        });
    info!("P2QRH control block size: {}", control_block_bytes.len());

    let leaf_script_priv_key_bytes: Vec<u8> = env::var("LEAF_SCRIPT_PRIV_KEY_HEX")
        .map(|s| hex::decode(s).unwrap())
        .unwrap_or_else(|_| {
            error!("LEAF_SCRIPT_PRIV_KEY_HEX environment variable is required but not set");
            std::process::exit(1);
        });

    // ie: OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG
    let leaf_script_bytes: Vec<u8> = env::var("LEAF_SCRIPT_HEX")
        .map(|s| hex::decode(s).unwrap())
        .unwrap_or_else(|_| {
            error!("LEAF_SCRIPT_HEX environment variable is required but not set");
            std::process::exit(1);
        });

    // https://learnmeabitcoin.com/explorer/tx/797505b104b5fb840931c115ea35d445eb1f64c9279bf23aa5bb4c3d779da0c2#outputs
    let spend_output_pubkey_hash_bytes: Vec<u8> = hex::decode("0de745dc58d8e62e6f47bde30cd5804a82016f9e").unwrap();

    // OUTPUT_AMOUNT_SATS env var is optional. Default is FUNDING_UTXO_AMOUNT_SATS - 5000 sats
    let spend_output_amount_sats: u64 = env::var("OUTPUT_AMOUNT_SATS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(funding_utxo_amount_sats.saturating_sub(5000));


    let result: SpendDetails = pay_to_p2wpkh_tx(
        funding_tx_id_bytes,
        funding_utxo_index,
        funding_utxo_amount_sats,
        funding_script_pubkey_bytes,
        control_block_bytes,
        leaf_script_bytes.clone(),
        leaf_script_priv_key_bytes,
        spend_output_pubkey_hash_bytes,
        spend_output_amount_sats
    );

    // Remove first and last byte from leaf_script_bytes to get tapleaf_pubkey_bytes
    let tapleaf_pubkey_bytes: Vec<u8> = leaf_script_bytes[1..leaf_script_bytes.len()-1].to_vec();
    
    let is_valid: bool = verify_schnorr_signature_via_bytes(
        &result.sig_bytes,
        &result.sighash,
        &tapleaf_pubkey_bytes);
    info!("is_valid: {}", is_valid);

    return result;
}
