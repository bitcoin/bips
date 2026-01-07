use p2tsh_ref::{ pay_to_p2wpkh_tx, verify_schnorr_signature_via_bytes, verify_slh_dsa_via_bytes, parse_leaf_script_type };

use p2tsh_ref::data_structures::{SpendDetails, LeafScriptType};
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
    info!("P2TSH control block size: {}", control_block_bytes.len());

    // LEAF_SCRIPT_TYPE environment variable is required to determine key structure
    let leaf_script_type: LeafScriptType = parse_leaf_script_type();
    info!("leaf_script_type: {:?}", leaf_script_type);

    // Parse private keys based on script type
    let leaf_script_priv_keys_bytes: Vec<Vec<u8>> = match leaf_script_type {
        LeafScriptType::SlhDsaOnly => {
            let priv_keys_hex_array = env::var("LEAF_SCRIPT_PRIV_KEYS_HEX")
                .unwrap_or_else(|_| {
                    error!("LEAF_SCRIPT_PRIV_KEYS_HEX environment variable is required for SLH_DSA_ONLY");
                    std::process::exit(1);
                });
            // Parse JSON array and extract the first (and only) hex string
            let priv_keys_hex: String = serde_json::from_str::<Vec<String>>(&priv_keys_hex_array)
                .unwrap_or_else(|_| {
                    error!("Failed to parse LEAF_SCRIPT_PRIV_KEYS_HEX as JSON array");
                    std::process::exit(1);
                })
                .into_iter()
                .next()
                .unwrap_or_else(|| {
                    error!("LEAF_SCRIPT_PRIV_KEYS_HEX array is empty");
                    std::process::exit(1);
                });
            let priv_keys_bytes = hex::decode(priv_keys_hex).unwrap();
            if priv_keys_bytes.len() != 64 {
                error!("SLH-DSA private key must be 64 bytes, got {}", priv_keys_bytes.len());
                std::process::exit(1);
            }
            vec![priv_keys_bytes]
        },
        LeafScriptType::SchnorrOnly => {
            let priv_keys_hex_array = env::var("LEAF_SCRIPT_PRIV_KEYS_HEX")
                .unwrap_or_else(|_| {
                    error!("LEAF_SCRIPT_PRIV_KEYS_HEX environment variable is required for SCHNORR_ONLY");
                    std::process::exit(1);
                });
            // Parse JSON array and extract the first (and only) hex string
            let priv_keys_hex: String = serde_json::from_str::<Vec<String>>(&priv_keys_hex_array)
                .unwrap_or_else(|_| {
                    error!("Failed to parse LEAF_SCRIPT_PRIV_KEYS_HEX as JSON array");
                    std::process::exit(1);
                })
                .into_iter()
                .next()
                .unwrap_or_else(|| {
                    error!("LEAF_SCRIPT_PRIV_KEYS_HEX array is empty");
                    std::process::exit(1);
                });
            let priv_keys_bytes = hex::decode(priv_keys_hex).unwrap();
            if priv_keys_bytes.len() != 32 {
                error!("Schnorr private key must be 32 bytes, got {}", priv_keys_bytes.len());
                std::process::exit(1);
            }
            vec![priv_keys_bytes]
        },
        LeafScriptType::SchnorrAndSlhDsa => {
            let priv_keys_hex_array = env::var("LEAF_SCRIPT_PRIV_KEYS_HEX")
                .unwrap_or_else(|_| {
                    error!("LEAF_SCRIPT_PRIV_KEYS_HEX environment variable is required for SCHNORR_AND_SLH_DSA");
                    std::process::exit(1);
                });
            // Parse JSON array and extract the hex strings
            let priv_keys_hex_vec: Vec<String> = serde_json::from_str(&priv_keys_hex_array)
                .unwrap_or_else(|_| {
                    error!("Failed to parse LEAF_SCRIPT_PRIV_KEYS_HEX as JSON array");
                    std::process::exit(1);
                });
            
            if priv_keys_hex_vec.len() != 2 {
                error!("For SCHNORR_AND_SLH_DSA, LEAF_SCRIPT_PRIV_KEYS_HEX must contain exactly 2 hex strings, got {}", priv_keys_hex_vec.len());
                std::process::exit(1);
            }
            
            let schnorr_priv_key_hex = &priv_keys_hex_vec[0];
            let slh_dsa_priv_key_hex = &priv_keys_hex_vec[1];
            
            let schnorr_priv_key_bytes = hex::decode(schnorr_priv_key_hex).unwrap();
            let slh_dsa_priv_key_bytes = hex::decode(slh_dsa_priv_key_hex).unwrap();
            
            if schnorr_priv_key_bytes.len() != 32 {
                error!("Schnorr private key must be 32 bytes, got {}", schnorr_priv_key_bytes.len());
                std::process::exit(1);
            }
            if slh_dsa_priv_key_bytes.len() != 64 {
                error!("SLH-DSA private key must be 64 bytes, got {}", slh_dsa_priv_key_bytes.len());
                std::process::exit(1);
            }
            
            vec![schnorr_priv_key_bytes, slh_dsa_priv_key_bytes]
        },
        LeafScriptType::NotApplicable => {
            panic!("LeafScriptType::NotApplicable is not applicable");
        }
    };


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
        leaf_script_priv_keys_bytes,  // Now passing Vec<Vec<u8>> instead of Vec<u8>
        spend_output_pubkey_hash_bytes,
        spend_output_amount_sats,
        leaf_script_type
    );

    // Remove first and last byte from leaf_script_bytes to get tapleaf_pubkey_bytes
    let tapleaf_pubkey_bytes: Vec<u8> = leaf_script_bytes[1..leaf_script_bytes.len()-1].to_vec();
    
    match leaf_script_type {
        LeafScriptType::SlhDsaOnly => {
            let is_valid: bool = verify_slh_dsa_via_bytes(&result.sig_bytes, &result.sighash, &tapleaf_pubkey_bytes);
            info!("is_valid: {}", is_valid);
        },
        LeafScriptType::SchnorrOnly => {
            let is_valid: bool = verify_schnorr_signature_via_bytes(
                &result.sig_bytes,
                &result.sighash,
                &tapleaf_pubkey_bytes);
            info!("is_valid: {}", is_valid);
        },
        LeafScriptType::SchnorrAndSlhDsa => {
            // For combined scripts, we need to separate the signatures
            // The sig_bytes contains: [schnorr_sig (64 bytes), slh_dsa_sig (7856 bytes)] (raw signatures without sighash)
            let schnorr_sig_len = 64; // Schnorr signature is 64 bytes
            let slh_dsa_sig_len = 7856; // SLH-DSA signature is 7856 bytes
            
            let expected_min_len = schnorr_sig_len + slh_dsa_sig_len;
            
            if result.sig_bytes.len() < expected_min_len {
                error!("Combined signature length is too short: expected at least {}, got {}", 
                    expected_min_len, result.sig_bytes.len());
                return result;
            }
            
            // Extract Schnorr signature (first 64 bytes)
            let schnorr_sig = &result.sig_bytes[..schnorr_sig_len];
            // Extract SLH-DSA signature (next 7856 bytes)
            let slh_dsa_sig = &result.sig_bytes[schnorr_sig_len..schnorr_sig_len + slh_dsa_sig_len];
            
            // For SCHNORR_AND_SLH_DSA scripts, we need to extract the individual public keys
            // The script structure is: OP_PUSHBYTES_32 <schnorr_pubkey(32)> OP_CHECKSIG OP_PUSHBYTES_32 <slh_dsa_pubkey(32)> OP_SUBSTR OP_BOOLAND OP_VERIFY
            // So we need to extract the Schnorr pubkey (first 32 bytes after OP_PUSHBYTES_32)
            let schnorr_pubkey_bytes = &leaf_script_bytes[1..33]; // Skip OP_PUSHBYTES_32 (0x20), get next 32 bytes
            let slh_dsa_pubkey_bytes = &leaf_script_bytes[35..67]; // Skip OP_CHECKSIG (0xac), OP_PUSHBYTES_32 (0x20), get next 32 bytes
            
            // Verify Schnorr signature
            let schnorr_is_valid: bool = verify_schnorr_signature_via_bytes(
                schnorr_sig,
                &result.sighash,
                schnorr_pubkey_bytes);
            info!("Schnorr signature is_valid: {}", schnorr_is_valid);
            
            // Verify SLH-DSA signature
            let slh_dsa_is_valid: bool = verify_slh_dsa_via_bytes(
                slh_dsa_sig,
                &result.sighash,
                slh_dsa_pubkey_bytes);
            info!("SLH-DSA signature is_valid: {}", slh_dsa_is_valid);
            
            let both_valid = schnorr_is_valid && slh_dsa_is_valid;
            info!("Both signatures valid: {}", both_valid);
        }
        LeafScriptType::NotApplicable => {
            panic!("LeafScriptType::NotApplicable is not applicable");
        }
    }

    return result;
}
