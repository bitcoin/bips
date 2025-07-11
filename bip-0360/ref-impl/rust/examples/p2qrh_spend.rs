use p2qrh_ref::{ p2qrh_to_p2wpkh_tx };

use p2qrh_ref::data_structures::P2qrhSpendDetails;
use std::env;
use log::{info, error};

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> P2qrhSpendDetails {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    // FUNDING_TX_ID environment variable is required
    let funding_tx_id: String = env::var("FUNDING_TX_ID")
        .unwrap_or_else(|_| {
            error!("FUNDING_TX_ID environment variable is required but not set");
            std::process::exit(1);
        });
    
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

    let funding_tx_id_bytes: Vec<u8> = hex::decode(funding_tx_id.clone()).unwrap();

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

    // Modified from learnmeabitcoin example
    // Changed from c0 to c1 control byte to reflect p2qrh specification:  The parity bit of the control byte is always 1 since P2QRH does not have a key-spend path.
    let p2qrh_control_block_bytes: Vec<u8> =
        hex::decode("c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329").unwrap();
    info!("P2QRH control block size: {}", p2qrh_control_block_bytes.len());

    let leaf_script_priv_key_bytes: Vec<u8> = hex::decode("9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189").unwrap();

    // OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG
    let leaf_script_bytes: Vec<u8> =
        hex::decode("206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac").unwrap();

    let leaf_script_pubkey_hash_bytes: Vec<u8> = hex::decode("0de745dc58d8e62e6f47bde30cd5804a82016f9e").unwrap();

    // OUTPUT_AMOUNT_SATS env var is optional. Default is FUNDING_UTXO_AMOUNT_SATS - 5000 sats
    let output_amount_sats: u64 = env::var("OUTPUT_AMOUNT_SATS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(funding_utxo_amount_sats.saturating_sub(5000));


    let result: P2qrhSpendDetails = p2qrh_to_p2wpkh_tx(
        funding_tx_id_bytes,
        funding_utxo_index,
        funding_utxo_amount_sats,
        funding_script_pubkey_bytes,
        p2qrh_control_block_bytes,
        leaf_script_pubkey_hash_bytes,
        leaf_script_bytes,
        leaf_script_priv_key_bytes,
        output_amount_sats
    );

    return result;
}
