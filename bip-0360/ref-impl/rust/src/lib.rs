pub mod data_structures;
pub mod error;

use log::{debug, info};
use std::io::Write;
use once_cell::sync::Lazy;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Secp256k1, Parity};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, TapSighash};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::{ Amount, TxOut, WPubkeyHash, Txid,
    Address, Network, OutPoint,
    blockdata::witness::Witness,
    Script, ScriptBuf, XOnlyPublicKey, PublicKey,
    sighash::{SighashCache, TapSighashType}, 
    taproot::{LeafVersion, TapLeafHash, TapNodeHash},
    transaction::{Transaction, Sequence}
};

use bitcoin::p2qrh::P2qrhScriptBuf;

use data_structures::{SpendDetails, UtxoReturn};

/* Secp256k1 implements the Signing trait when it's initialized in signing mode.
   It's important to note that Secp256k1 has different capabilities depending on how it's constructed:
      * Secp256k1::new() creates a context capable of both signing and verification
      * Secp256k1::signing_only() creates a context that can only sign
      * Secp256k1::verification_only() creates a context that can only verify
*/
static SECP: Lazy<Secp256k1<bitcoin::secp256k1::All>> = Lazy::new(Secp256k1::new);


pub fn create_p2qrh_utxo(quantum_root_hex: String) -> UtxoReturn {

    let quantum_root_bytes= hex::decode(quantum_root_hex.clone()).unwrap();
    let quantum_root: TapNodeHash = TapNodeHash::from_byte_array(quantum_root_bytes.try_into().unwrap());
    
    /* commit (in scriptPubKey) to the merkle root of all the script path leaves. ie:
        This output key is what gets committed to in the final P2QRH address (ie: scriptPubKey)
    */
    let script_buf: P2qrhScriptBuf = P2qrhScriptBuf::new_p2qrh(quantum_root);
    let script: &Script = script_buf.as_script();
    let script_pubkey = script.to_hex_string();

    let mut bitcoin_network: Network = Network::Bitcoin;

    // Check for BITCOIN_NETWORK environment variable and override if set
    if let Ok(network_str) = std::env::var("BITCOIN_NETWORK") {
        bitcoin_network = match network_str.to_lowercase().as_str() {
            "regtest" => Network::Regtest,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            _ => {
                debug!("Invalid BITCOIN_NETWORK value '{}', using default Bitcoin network", network_str);
                Network::Bitcoin
            }
        };
    }

    
    // 4)  derive bech32m address and verify against test vector
    //     p2qrh address is comprised of network HRP + WitnessProgram (version + program)
    let bech32m_address = Address::p2qrh(Some(quantum_root), bitcoin_network);

    return UtxoReturn {
        tree_root_hex: quantum_root_hex,
        script_pubkey_hex: script_pubkey,
        bech32m_address: bech32m_address.to_string(),
        bitcoin_network,
    };

}

// Given script path p2tr or p2qrh UTXO details, spend to p2wpkh
pub fn pay_to_p2wpkh_tx(
    funding_tx_id_bytes: Vec<u8>,
    funding_utxo_index: u32,
    funding_utxo_amount_sats: u64,
    funding_script_pubkey_bytes: Vec<u8>,
    control_block_bytes: Vec<u8>,
    leaf_script_bytes: Vec<u8>,
    leaf_script_priv_key_bytes: Vec<u8>,
    spend_output_pubkey_bytes: Vec<u8>,
    spend_output_amount_sats: u64,
) -> SpendDetails {

    let mut txid_little_endian = funding_tx_id_bytes.clone();
    txid_little_endian.reverse();

    // vin: Create TxIn from the input utxo
    // Details of this input tx are not known at this point
    let input_tx_in = bitcoin::TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::from_slice(&txid_little_endian).unwrap(), // bitcoin::Txid expects the bytes in little-endian format
            vout: funding_utxo_index,
        },
        script_sig: ScriptBuf::new(), // Empty for segwit transactions - script goes in witness
        sequence: Sequence::MAX, // Default sequence, allows immediate spending (no RBF or timelock)
        witness: bitcoin::Witness::new(), // Empty for now, will be filled with signature and pubkey after signing
    };

    let spend_wpubkey_hash = WPubkeyHash::from_byte_array(spend_output_pubkey_bytes.try_into().unwrap());
    let spend_output: TxOut = TxOut {
        value: Amount::from_sat(spend_output_amount_sats),
        script_pubkey: ScriptBuf::new_p2wpkh(&spend_wpubkey_hash),
    };

    // The spend tx to eventually be signed and broadcast
    let mut unsigned_spend_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input_tx_in],
        output: vec![spend_output],
    };

    // Create the leaf hash
    let leaf_version = LeafVersion::TapScript;
    let leaf_script = ScriptBuf::from_bytes(leaf_script_bytes.clone());
    let leaf_hash: TapLeafHash = TapLeafHash::from_script(&leaf_script, leaf_version);

    /*  prevouts parameter tells the sighash algorithm:
            1. The value of each input being spent (needed for fee calculation and sighash computation)
            2. The scriptPubKey of each input being spent (ie: type of output & how to validate the spend)
     */
    let prevouts = vec![TxOut {
        value: Amount::from_sat(funding_utxo_amount_sats),
        script_pubkey: ScriptBuf::from_bytes(funding_script_pubkey_bytes.clone()),
    }];
    info!("prevouts: {:?}", prevouts);

    let spending_tx_input_index = 0;

    // Create SighashCache
    // At this point, sighash_cache does not know the values and type of input UTXO
    let mut tapscript_sighash_cache = SighashCache::new(&mut unsigned_spend_tx);

    // Compute the sighash
    let tapscript_sighash: TapSighash = tapscript_sighash_cache.taproot_script_spend_signature_hash(
        spending_tx_input_index, // input_index
        &Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::All
    ).unwrap();

    info!("sighash: {:?}", tapscript_sighash);

    let spend_msg = Message::from(tapscript_sighash);

    // Signing: Sign the sighash using the secp256k1 library (re-exported by rust-bitcoin).
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&leaf_script_priv_key_bytes).unwrap();

    // Spending a p2tr UTXO thus using Schnorr signature
    // The aux_rand parameter ensures that signing the same message with the same key produces the same signature
    let signature: bitcoin::secp256k1::schnorr::Signature = secp.sign_schnorr_with_aux_rand(
        &spend_msg,
        &secret_key.keypair(&secp),
        &[0u8; 32] // 32 zero bytes of auxiliary random data
    );
    let mut sig_bytes: Vec<u8> = signature.serialize().to_vec();
    sig_bytes.push(EcdsaSighashType::All as u8);

    let p2wpkh_sig_hex = hex::encode(sig_bytes.clone());
    info!("signature: {:?}", p2wpkh_sig_hex);

    let mut derived_witness: Witness = Witness::new();
    derived_witness.push(&sig_bytes);
    derived_witness.push(&leaf_script_bytes);
    derived_witness.push(&control_block_bytes);

    let derived_witness_vec: Vec<u8> = derived_witness.iter().flatten().cloned().collect();

    let derived_witness_hex = hex::encode(derived_witness_vec.clone());
    info!("derived_witness_hex ( <script inputs> <script> <control block> ): \n{:?}", derived_witness_hex.clone());

    // Update the witness data for the tx's first input (index 0)
    *tapscript_sighash_cache.witness_mut(spending_tx_input_index).unwrap() = derived_witness;

    // Get the signed transaction.
    let signed_tx_obj: &mut Transaction = tapscript_sighash_cache.into_transaction();

    // Reserialize without witness data and double-SHA256 to get the txid
    let signed_txid_obj: Txid = signed_tx_obj.compute_txid();
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&signed_tx_obj);
    //info!("tx_hex: {:?}", tx_hex);

    return SpendDetails {
        tx_hex,
        tapscript_sighash: tapscript_sighash.as_byte_array().to_vec(),
        p2wpkh_sig_bytes: sig_bytes,
        derived_witness_vec: derived_witness_vec,
    };
}


pub fn create_p2tr_utxo(merkle_root_hex: String, internal_pubkey_hex: String) -> UtxoReturn {

    let merkle_root_bytes= hex::decode(merkle_root_hex.clone()).unwrap();
    let merkle_root: TapNodeHash = TapNodeHash::from_byte_array(merkle_root_bytes.try_into().unwrap());

    let pub_key_string = format!("02{}", internal_pubkey_hex);
    let internal_pubkey: PublicKey = pub_key_string.parse::<PublicKey>().unwrap();
    let internal_xonly_pubkey: XOnlyPublicKey = internal_pubkey.inner.into();
    

    let script_buf: ScriptBuf = ScriptBuf::new_p2tr(&SECP, internal_xonly_pubkey, Option::Some(merkle_root));
    let script: &Script = script_buf.as_script();
    let script_pubkey = script.to_hex_string();

    let mut bitcoin_network: Network = Network::Bitcoin;

    // Check for BITCOIN_NETWORK environment variable and override if set
    if let Ok(network_str) = std::env::var("BITCOIN_NETWORK") {
        bitcoin_network = match network_str.to_lowercase().as_str() {
            "regtest" => Network::Regtest,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            _ => {
                debug!("Invalid BITCOIN_NETWORK value '{}', using default Bitcoin network", network_str);
                Network::Bitcoin
            }
        };
    }

    // 4)  derive bech32m address and verify against test vector
    //     p2qrh address is comprised of network HRP + WitnessProgram (version + program)
    let bech32m_address = Address::p2tr(
        &SECP,
        internal_xonly_pubkey,
        Option::Some(merkle_root),
        bitcoin_network
    );

    return UtxoReturn {
        tree_root_hex: merkle_root_hex,
        script_pubkey_hex: script_pubkey,
        bech32m_address: bech32m_address.to_string(),
        bitcoin_network,
    };

}


// https://learnmeabitcoin.com/technical/upgrades/taproot/#examples
pub fn tagged_hash(tag: &str, data: &[u8]) -> String {

    // Create a hash of the tag first
    let tag_hash = sha256::Hash::hash(tag.as_bytes());

    // Create preimage:  tag_hash || tag_hash || message
    // tag_hash is prefixed twice so that the prefix is 64 bytes in total
    let mut preimage = sha256::Hash::engine();
    preimage.write_all(&tag_hash.to_byte_array()).unwrap();  // First tag hash
    preimage.write_all(&tag_hash.to_byte_array()).unwrap();  // Second tag hash
    preimage.write_all(data).unwrap();       // Message data
    let hash = sha256::Hash::from_engine(preimage).to_byte_array();
    hex::encode(hash)
}

pub fn serialize_script(script: &Vec<u8>) -> Vec<u8> {
    // get length of script as number of bytes
    let length = script.len();

    // return script with compact size prepended
    let mut result = compact_size(length as u64);
    result.extend_from_slice(&script);
    result
}

/// Encodes an integer into Bitcoin's compact size format
/// Returns a Vec<u8> containing the encoded bytes
fn compact_size(n: u64) -> Vec<u8> {
    if n <= 252 {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut result = vec![0xfd];
        result.extend_from_slice(&(n as u16).to_le_bytes());
        result
    } else if n <= 0xffffffff {
        let mut result = vec![0xfe];
        result.extend_from_slice(&(n as u32).to_le_bytes());
        result
    } else {
        let mut result = vec![0xff];
        result.extend_from_slice(&n.to_le_bytes());
        result
    }
}
