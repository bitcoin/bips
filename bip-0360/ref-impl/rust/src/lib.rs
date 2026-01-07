pub mod data_structures;
pub mod error;

use log::{debug, info, error};
use std::env;
use std::io::Write;
use rand::{rng, RngCore};
use once_cell::sync::Lazy;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Secp256k1, Parity};
use bitcoin::secp256k1::{Message, SecretKey, Keypair, rand::rngs::OsRng, rand::thread_rng, rand::Rng, schnorr::Signature};
use bitcoin::{ Amount, TxOut, WPubkeyHash,
    Address, Network, OutPoint,
    blockdata::witness::Witness,
    Script, ScriptBuf, XOnlyPublicKey, PublicKey,
    sighash::{SighashCache, TapSighashType, Prevouts, TapSighash}, 
    taproot::{LeafVersion, NodeInfo, TapLeafHash, TapNodeHash, TapTree, ScriptLeaves, TaprootMerkleBranch, TaprootBuilder, TaprootSpendInfo, ControlBlock},
    transaction::{Transaction, Sequence}
};

use bitcoin::p2tsh::{P2tshScriptBuf, P2tshBuilder, P2tshSpendInfo, P2tshControlBlock, P2TSH_LEAF_VERSION};

use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, Algorithm, KeyPair, sign, verify,
};

use data_structures::{SpendDetails, UtxoReturn, TaptreeReturn, UnifiedKeypair, MultiKeypair, LeafScriptType};

/* Secp256k1 implements the Signing trait when it's initialized in signing mode.
   It's important to note that Secp256k1 has different capabilities depending on how it's constructed:
      * Secp256k1::new() creates a context capable of both signing and verification
      * Secp256k1::signing_only() creates a context that can only sign
      * Secp256k1::verification_only() creates a context that can only verify
*/
static SECP: Lazy<Secp256k1<bitcoin::secp256k1::All>> = Lazy::new(Secp256k1::new);

fn create_huffman_tree(leaf_script_type: LeafScriptType) -> (Vec<(u32, ScriptBuf)>, MultiKeypair, ScriptBuf) {

    let mut total_leaf_count: u32 = 1;
    if let Ok(env_value) = env::var("TOTAL_LEAF_COUNT") {
        if let Ok(parsed_value) = env_value.parse::<u32>() {
            total_leaf_count = parsed_value;
        }
    }
    
    let mut leaf_of_interest: u32 = 0;
    if let Ok(env_value) = env::var("LEAF_OF_INTEREST") {
        if let Ok(parsed_value) = env_value.parse::<u32>() {
            leaf_of_interest = parsed_value;
        }
    }

    if total_leaf_count < 1 {
        panic!("total_leaf_count must be greater than 0");
    }
    if leaf_of_interest >= total_leaf_count {
        panic!("leaf_of_interest must be less than total_leaf_count and greater than 0");
    }

    debug!("Creating multi-leaf taptree with total_leaf_count: {}, leaf_of_interest: {}", total_leaf_count, leaf_of_interest);
    let mut huffman_entries: Vec<(u32, ScriptBuf)> = vec![];
    let mut keypairs_of_interest: Option<MultiKeypair> = None;
    let mut script_buf_of_interest: Option<ScriptBuf> = None;
    for leaf_index in 0..total_leaf_count {
        let keypairs: MultiKeypair;
        let script_buf: ScriptBuf;
        
        match leaf_script_type {
            LeafScriptType::SchnorrOnly => {
                let schnorr_keypair = acquire_schnorr_keypair();
                keypairs = MultiKeypair::new_schnorr_only(schnorr_keypair);
                let pubkey_bytes = keypairs.schnorr_keypair().unwrap().public_key_bytes();
                // OP_PUSHBYTES_32 <32-byte xonly pubkey> OP_CHECKSIG
                let mut script_buf_bytes = vec![0x20];
                script_buf_bytes.extend_from_slice(&pubkey_bytes);
                script_buf_bytes.push(0xac); // OP_CHECKSIG
                script_buf = ScriptBuf::from_bytes(script_buf_bytes);
            },
            LeafScriptType::SlhDsaOnly => {
                let slh_dsa_keypair = acquire_slh_dsa_keypair();
                keypairs = MultiKeypair::new_slh_dsa_only(slh_dsa_keypair);
                let pubkey_bytes = keypairs.slh_dsa_keypair().unwrap().public_key_bytes();
                // OP_PUSHBYTES_32 <32-byte pubkey> OP_SUBSTR
                let mut script_buf_bytes = vec![0x20];
                script_buf_bytes.extend_from_slice(&pubkey_bytes);
                script_buf_bytes.push(0x7f); // OP_SUBSTR
                script_buf = ScriptBuf::from_bytes(script_buf_bytes);
            },
            LeafScriptType::SchnorrAndSlhDsa => {
                // For combined scripts, we need both keypairs
                let schnorr_keypair = acquire_schnorr_keypair();
                let slh_dsa_keypair = acquire_slh_dsa_keypair();
                keypairs = MultiKeypair::new_combined(schnorr_keypair, slh_dsa_keypair);
                
                let schnorr_pubkey = keypairs.schnorr_keypair().unwrap().public_key_bytes();
                let slh_dsa_pubkey = keypairs.slh_dsa_keypair().unwrap().public_key_bytes();
                
                // Debug: Print the private key used for script construction
                info!("SLH-DSA DEBUG: Script construction using private key: {}", hex::encode(keypairs.slh_dsa_keypair().unwrap().secret_key_bytes()));
                info!("SLH-DSA DEBUG: Script construction using public key: {}", hex::encode(&slh_dsa_pubkey));
                
                // Combined script: <Schnorr_PubKey> OP_CHECKSIG <SLH_DSA_PubKey> OP_SUBSTR OP_BOOLAND OP_VERIFY
                let mut script_buf_bytes = vec![0x20]; // OP_PUSHBYTES_32
                script_buf_bytes.extend_from_slice(&schnorr_pubkey);
                script_buf_bytes.push(0xac); // OP_CHECKSIG
                script_buf_bytes.push(0x20); // OP_PUSHBYTES_32
                script_buf_bytes.extend_from_slice(&slh_dsa_pubkey);
                script_buf_bytes.push(0x7f); // OP_SUBSTR
                script_buf_bytes.push(0x9a); // OP_BOOLAND
                script_buf_bytes.push(0x69); // OP_VERIFY
                script_buf = ScriptBuf::from_bytes(script_buf_bytes);
            }
            LeafScriptType::NotApplicable => {
                panic!("LeafScriptType::NotApplicable is not applicable");
            }
        }
            
            let random_weight = thread_rng().gen_range(0..total_leaf_count);
            
            let huffman_entry = (random_weight, script_buf.clone());
            huffman_entries.push(huffman_entry);
            if leaf_index == leaf_of_interest {
                keypairs_of_interest = Some(keypairs);
                script_buf_of_interest = Some(script_buf.clone());
                debug!("Selected leaf: weight: {}, script: {:?}", random_weight, script_buf);
            }
    }
    return (huffman_entries, keypairs_of_interest.unwrap(), script_buf_of_interest.unwrap());
}

/// Parses the LEAF_SCRIPT_TYPE environment variable and returns the corresponding LeafScriptType.
/// Defaults to LeafScriptType::SchnorrOnly if the environment variable is not set or has an invalid value.
pub fn parse_leaf_script_type() -> LeafScriptType {
    match env::var("LEAF_SCRIPT_TYPE")
        .unwrap_or_else(|_| "SCHNORR_ONLY".to_string())
        .as_str() {
        "SLH_DSA_ONLY" => LeafScriptType::SlhDsaOnly,
        "SCHNORR_ONLY" => LeafScriptType::SchnorrOnly,
        "SCHNORR_AND_SLH_DSA" => LeafScriptType::SchnorrAndSlhDsa,
        _ => {
            error!("Invalid LEAF_SCRIPT_TYPE. Must be one of: SLH_DSA_ONLY, SCHNORR_ONLY, SCHNORR_AND_SLH_DSA");
            LeafScriptType::SchnorrOnly
        }
    }
}

pub fn create_p2tsh_multi_leaf_taptree() -> TaptreeReturn {
    let leaf_script_type = parse_leaf_script_type();
    
    let (huffman_entries, keypairs_of_interest, script_buf_of_interest) = create_huffman_tree(leaf_script_type);
    let p2tsh_builder: P2tshBuilder = P2tshBuilder::with_huffman_tree(huffman_entries).unwrap();


    let p2tsh_spend_info: P2tshSpendInfo = p2tsh_builder.clone().finalize().unwrap();
    let merkle_root:TapNodeHash = p2tsh_spend_info.merkle_root.unwrap();

    
    let tap_tree: TapTree = p2tsh_builder.clone().into_inner().try_into_taptree().unwrap();
    let mut script_leaves: ScriptLeaves = tap_tree.script_leaves();
    let script_leaf = script_leaves
        .find(|leaf| leaf.script() == script_buf_of_interest.as_script())
        .expect("Script leaf not found");

    let merkle_root_node_info: NodeInfo = p2tsh_builder.clone().into_inner().try_into_node_info().unwrap();
    let merkle_root: TapNodeHash = merkle_root_node_info.node_hash();

    let leaf_hash: TapLeafHash = TapLeafHash::from_script(script_leaf.script(), LeafVersion::from_consensus(P2TSH_LEAF_VERSION).unwrap());

    // Convert leaf hash to big-endian for display (like Bitcoin Core)
    let mut leaf_hash_bytes = leaf_hash.as_raw_hash().to_byte_array().to_vec();
    leaf_hash_bytes.reverse();

    info!("leaf_hash: {}, merkle_root: {}, merkle_root: {}",
        hex::encode(leaf_hash_bytes),
        merkle_root,
        merkle_root);

    let leaf_script = script_leaf.script();
    let merkle_branch: &TaprootMerkleBranch = script_leaf.merkle_branch();

    info!("Leaf script: {}, merkle branch: {:?}", leaf_script, merkle_branch);

    let control_block: P2tshControlBlock = P2tshControlBlock{
        merkle_branch: merkle_branch.clone(),
    };

    // Not a requirement here but useful to demonstrate what Bitcoin Core does as the verifier when spending from a p2tsh UTXO   
    control_block.verify_script_in_merkle_root_path(leaf_script, merkle_root);

    let control_block_hex: String = hex::encode(control_block.serialize());

    return TaptreeReturn {
        leaf_script_priv_keys_hex: keypairs_of_interest.secret_key_bytes()
            .into_iter()
            .map(|bytes| hex::encode(bytes))
            .collect(),
        leaf_script_hex: leaf_script.to_hex_string(),
        tree_root_hex: hex::encode(merkle_root.to_byte_array()),
        control_block_hex: control_block_hex,
    };
}

pub fn create_p2tr_multi_leaf_taptree(p2tr_internal_pubkey_hex: String) -> TaptreeReturn {

    let (huffman_entries, keypairs_of_interest, script_buf_of_interest) = create_huffman_tree(LeafScriptType::SchnorrOnly);

    let pub_key_string = format!("02{}", p2tr_internal_pubkey_hex);
    let internal_pubkey: PublicKey = pub_key_string.parse::<PublicKey>().unwrap();
    let internal_xonly_pubkey: XOnlyPublicKey = internal_pubkey.inner.into();
    
    let p2tr_builder: TaprootBuilder = TaprootBuilder::with_huffman_tree(huffman_entries).unwrap();
    let p2tr_spend_info: TaprootSpendInfo = p2tr_builder.clone().finalize(&SECP, internal_xonly_pubkey).unwrap();
    let merkle_root: TapNodeHash = p2tr_spend_info.merkle_root().unwrap();

    // During taproot construction, the internal key is "tweaked" by adding a scalar (the tap tweak hash) to it.
    // If this tweaking operation results in a public key w/ an odd Y-coordinate, the parity bit is set to 1.
    // When spending via script path, the verifier needs to know whether the output key has an even or odd Y-coordinate to properly reconstruct & verify the internal key.
    // The internal key can be recovered from the output key using the parity bit and the merkle root.
    let output_key_parity: Parity = p2tr_spend_info.output_key_parity();
    let output_key: XOnlyPublicKey = p2tr_spend_info.output_key().into();

    info!("keypairs_of_interest: \n\tsecret_bytes: {:?} \n\tpubkeys: {:?} \n\tmerkle_root: {}",
        keypairs_of_interest.secret_key_bytes().iter().map(|bytes| hex::encode(bytes)).collect::<Vec<_>>(),  // secret_bytes returns big endian
        keypairs_of_interest.public_key_bytes().iter().map(|bytes| hex::encode(bytes)).collect::<Vec<_>>(),  // serialize returns little endian
        merkle_root);

    let tap_tree: TapTree = p2tr_builder.clone().try_into_taptree().unwrap();
    let mut script_leaves: ScriptLeaves = tap_tree.script_leaves();
    let script_leaf = script_leaves
        .find(|leaf| leaf.script() == script_buf_of_interest.as_script())
        .expect("Script leaf not found");
    let leaf_script = script_leaf.script().to_hex_string();
    let merkle_branch: &TaprootMerkleBranch = script_leaf.merkle_branch();
    debug!("Leaf script: {}, merkle branch: {:?}", leaf_script, merkle_branch);

    let control_block: ControlBlock = ControlBlock{
        leaf_version: LeafVersion::TapScript,
        output_key_parity: output_key_parity,
        internal_key: internal_xonly_pubkey,
        merkle_branch: merkle_branch.clone(),
    };
    let control_block_hex: String = hex::encode(control_block.serialize());

    // Not a requirement but useful to demonstrate what Bitcoin Core does as the verifier when spending from a p2tr UTXO
    let verify: bool = verify_taproot_commitment(control_block_hex.clone(), output_key, script_leaf.script());
    info!("verify_taproot_commitment: {}", verify);

    return TaptreeReturn {
        leaf_script_priv_keys_hex: keypairs_of_interest.secret_key_bytes()
            .into_iter()
            .map(|bytes| hex::encode(bytes))
            .collect(),
        leaf_script_hex: leaf_script,
        tree_root_hex: hex::encode(merkle_root.to_byte_array()),
        control_block_hex: control_block_hex,
    };
}

/// Parses the BITCOIN_NETWORK environment variable and returns the corresponding Network.
/// Defaults to Network::Regtest if the environment variable is not set or has an invalid value.
pub fn get_bitcoin_network() -> Network {
    let mut bitcoin_network: Network = Network::Regtest;

    // Check for BITCOIN_NETWORK environment variable and override if set
    if let Ok(network_str) = std::env::var("BITCOIN_NETWORK") {
        bitcoin_network = match network_str.to_lowercase().as_str() {
            "regtest" => Network::Regtest,
            "testnet" => Network::Testnet,
            "signet" => Network::Signet,
            _ => {
                debug!("Invalid BITCOIN_NETWORK value '{}', using default Regtest network", network_str);
                Network::Regtest
            }
        };
    }
    
    bitcoin_network
}

pub fn create_p2tsh_utxo(merkle_root_hex: String) -> UtxoReturn {

    let merkle_root_bytes= hex::decode(merkle_root_hex.clone()).unwrap();
    let merkle_root: TapNodeHash = TapNodeHash::from_byte_array(merkle_root_bytes.try_into().unwrap());
    
    /* commit (in scriptPubKey) to the merkle root of all the script path leaves. ie:
        This output key is what gets committed to in the final P2TSH address (ie: scriptPubKey)
    */
    let script_buf: P2tshScriptBuf = P2tshScriptBuf::new_p2tsh(merkle_root);
    let script: &Script = script_buf.as_script();
    let script_pubkey = script.to_hex_string();

    let bitcoin_network = get_bitcoin_network();
    
    // derive bech32m address and verify against test vector
    // p2tsh address is comprised of network HRP + WitnessProgram (version + program)
    let bech32m_address = Address::p2tsh(Some(merkle_root), bitcoin_network);

    return UtxoReturn {
        script_pubkey_hex: script_pubkey,
        bech32m_address: bech32m_address.to_string(),
        bitcoin_network,
    };

}

// Given script path p2tr or p2tsh UTXO details, spend to p2wpkh
pub fn pay_to_p2wpkh_tx(
    funding_tx_id_bytes: Vec<u8>,
    funding_utxo_index: u32,
    funding_utxo_amount_sats: u64,
    funding_script_pubkey_bytes: Vec<u8>,
    control_block_bytes: Vec<u8>,
    leaf_script_bytes: Vec<u8>,
    leaf_script_priv_keys_bytes: Vec<Vec<u8>>, // Changed to support multiple private keys
    spend_output_pubkey_hash_bytes: Vec<u8>,
    spend_output_amount_sats: u64,
    leaf_script_type: LeafScriptType
) -> SpendDetails {

    let mut txid_little_endian = funding_tx_id_bytes.clone();  // initially in big endian format
    txid_little_endian.reverse();  // convert to little endian format

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

    let spend_wpubkey_hash = WPubkeyHash::from_byte_array(spend_output_pubkey_hash_bytes.try_into().unwrap());
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
    let leaf_script = ScriptBuf::from_bytes(leaf_script_bytes.clone());
    let leaf_hash: TapLeafHash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);

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

    let mut derived_witness: Witness = Witness::new();
    let mut sig_bytes = Vec::new();
    match leaf_script_type {
        LeafScriptType::SlhDsaOnly => {
            if leaf_script_priv_keys_bytes.len() != 1 {
                panic!("SlhDsaOnly requires exactly one private key");
            }
            let secret_key: bitcoinpqc::SecretKey = bitcoinpqc::SecretKey::try_from_slice(
                Algorithm::SLH_DSA_128S, &leaf_script_priv_keys_bytes[0]).unwrap();
            let signature = sign(&secret_key, spend_msg.as_ref()).expect("Failed to sign with SLH-DSA-128S");
            debug!("SlhDsaOnly signature.bytes: {:?}", signature.bytes.len());
            let mut sig_bytes_with_sighash = signature.bytes.clone();
            sig_bytes_with_sighash.push(TapSighashType::All as u8);
            derived_witness.push(&sig_bytes_with_sighash);
            sig_bytes = signature.bytes;
        },
        LeafScriptType::SchnorrOnly => {
            if leaf_script_priv_keys_bytes.len() != 1 {
                panic!("SchnorrOnly requires exactly one private key");
            }
            // assumes bytes are in big endian format
            let secret_key = SecretKey::from_slice(&leaf_script_priv_keys_bytes[0]).unwrap();
        
            // Spending a p2tr UTXO thus using Schnorr signature
            // The aux_rand parameter ensures that signing the same message with the same key produces the same signature
            // Otherwise (without providing aux_rand), the secp256k1 library internally generates a random nonce for each signature 
            let signature: bitcoin::secp256k1::schnorr::Signature = SECP.sign_schnorr_with_aux_rand(
                &spend_msg,
                &secret_key.keypair(&SECP),
                &[0u8; 32] // 32 zero bytes of auxiliary random data
            );
            sig_bytes = signature.serialize().to_vec();
            let mut sig_bytes_with_sighash = sig_bytes.clone();
            sig_bytes_with_sighash.push(TapSighashType::All as u8);
            derived_witness.push(&sig_bytes_with_sighash);
            debug!("SchnorrOnly signature bytes: {:?}", sig_bytes.len());
        },
        LeafScriptType::SchnorrAndSlhDsa => {
            if leaf_script_priv_keys_bytes.len() != 2 {
                panic!("SchnorrAndSlhDsa requires exactly two private keys (Schnorr first, then SLH-DSA)");
            }
            
            // Generate Schnorr signature (first key)
            let schnorr_secret_key = SecretKey::from_slice(&leaf_script_priv_keys_bytes[0]).unwrap();
            let schnorr_signature: bitcoin::secp256k1::schnorr::Signature = SECP.sign_schnorr_with_aux_rand(
                &spend_msg,
                &schnorr_secret_key.keypair(&SECP),
                &[0u8; 32] // 32 zero bytes of auxiliary random data
            );
            // Build combined signature for return value (without sighash bytes)
            let mut combined_sig_bytes = schnorr_signature.serialize().to_vec();
            debug!("SchnorrAndSlhDsa schnorr_sig_bytes: {:?}", combined_sig_bytes.len());
            
            // Generate SLH-DSA signature (second key)
            let slh_dsa_secret_key: bitcoinpqc::SecretKey = bitcoinpqc::SecretKey::try_from_slice(
                Algorithm::SLH_DSA_128S, &leaf_script_priv_keys_bytes[1]).unwrap();
            
            // Debug: Print the private key being used for signature creation
            info!("SLH-DSA DEBUG: Using private key for signature creation: {}", hex::encode(&leaf_script_priv_keys_bytes[1]));
            
            let slh_dsa_signature = sign(&slh_dsa_secret_key, spend_msg.as_ref()).expect("Failed to sign with SLH-DSA-128S");
            debug!("SchnorrAndSlhDsa slh_dsa_signature.bytes: {:?}", slh_dsa_signature.bytes.len());
            
            // Add SLH-DSA signature to combined signature for return value
            combined_sig_bytes.extend_from_slice(&slh_dsa_signature.bytes);
            sig_bytes = combined_sig_bytes;
            
            // Build witness with sighash bytes
            let mut witness_sig_bytes = schnorr_signature.serialize().to_vec();
            witness_sig_bytes.push(TapSighashType::All as u8);
            witness_sig_bytes.extend_from_slice(&slh_dsa_signature.bytes);
            witness_sig_bytes.push(TapSighashType::All as u8);
            derived_witness.push(&witness_sig_bytes);
        }
        LeafScriptType::NotApplicable => {
            panic!("LeafScriptType::NotApplicable is not applicable");
        }
    }
    // Note: sighash byte is now appended to signatures, not as separate witness element
    derived_witness.push(&leaf_script_bytes);
    derived_witness.push(&control_block_bytes);

    let derived_witness_vec: Vec<u8> = derived_witness.iter().flatten().cloned().collect();

    // Update the witness data for the tx's first input (index 0)
    *tapscript_sighash_cache.witness_mut(spending_tx_input_index).unwrap() = derived_witness;

    // Get the signed transaction.
    let signed_tx_obj: &mut Transaction = tapscript_sighash_cache.into_transaction();

    let tx_hex = bitcoin::consensus::encode::serialize_hex(&signed_tx_obj);

    return SpendDetails {
        tx_hex,
        sighash: tapscript_sighash.as_byte_array().to_vec(),
        sig_bytes: sig_bytes,
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

    let bitcoin_network = get_bitcoin_network();

    // 4)  derive bech32m address and verify against test vector
    //     p2tsh address is comprised of network HRP + WitnessProgram (version + program)
    let bech32m_address = Address::p2tr(
        &SECP,
        internal_xonly_pubkey,
        Option::Some(merkle_root),
        bitcoin_network
    );

    return UtxoReturn {
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

pub fn acquire_schnorr_keypair() -> UnifiedKeypair {

        /*  OsRng typically draws from the OS's entropy pool (hardware random num generators, system events, etc), ie:
            *   1.  $ cat /proc/sys/kernel/random/entropy_avail
            *   2.  $ sudo dmesg | grep -i "random\|rng\|entropy"

            The Linux kernel's RNG (/dev/random and /dev/urandom) typically combines multiple entropy sources: ie:
            *   Hardware RNG (if available)
            *   CPU RNG instructions (RDRAND/RDSEED)
            *   Hardware events (disk I/O, network packets, keyboard/mouse input)
            *   Timer jitter
            *   Interrupt timing
        */
        let keypair = Keypair::new(&SECP, &mut OsRng);
    
        let privkey: SecretKey = keypair.secret_key();
        let pubkey: (XOnlyPublicKey, Parity) = XOnlyPublicKey::from_keypair(&keypair);
    UnifiedKeypair::new_schnorr(privkey, pubkey.0)
}

pub fn verify_schnorr_signature_via_bytes(signature: &[u8], message: &[u8], pubkey_bytes: &[u8]) -> bool {

    // schnorr is 64 bytes so remove possible trailing Sighash Type byte if present
    let mut sig_bytes = signature.to_vec();
    if sig_bytes.len() == 65 {
        sig_bytes.pop(); // Remove the last byte
    }
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
    let message = Message::from_digest_slice(message).unwrap();
    let pubkey = XOnlyPublicKey::from_slice(pubkey_bytes).unwrap();
    verify_schnorr_signature(signature, message, pubkey)
}

pub fn verify_slh_dsa_via_bytes(signature: &[u8], message: &[u8], pubkey_bytes: &[u8]) -> bool {
    
    // Remove possible trailing Sighash Type byte if present (SLH-DSA-128S is 7856 bytes, so 7857 would indicate SIGHASH byte)
    let mut sig_bytes = signature.to_vec();
    if sig_bytes.len() == 7857 {
        sig_bytes.pop(); // Remove the last byte
    }
    
    info!("verify_slh_dsa_via_bytes: signature length: {:?}, message: {:?}, pubkey_bytes: {:?}", 
        sig_bytes.len(), 
        hex::encode(message), 
        hex::encode(pubkey_bytes));

    let signature = bitcoinpqc::Signature::try_from_slice(Algorithm::SLH_DSA_128S, &sig_bytes).unwrap();
    let public_key: bitcoinpqc::PublicKey = bitcoinpqc::PublicKey::try_from_slice(Algorithm::SLH_DSA_128S, pubkey_bytes).unwrap();
    verify(&public_key, message, &signature).is_ok()
}

pub fn verify_schnorr_signature(mut signature: Signature, message: Message, pubkey: XOnlyPublicKey) -> bool {

    // schnorr is 64 bytes so remove possible trailing Sighash Type byte if present
    if signature.serialize().to_vec().len() == 65 {
        let mut sig_bytes = signature.serialize().to_vec();
        sig_bytes.pop(); // Remove the last byte
        signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
    }
    let is_valid: bool = SECP.verify_schnorr(&signature, &message, &pubkey).is_ok();
    if !is_valid {
        error!("verify schnorr failed:\n\tsignature: {:?}\n\tmessage: {:?}\n\tpubkey: {:?}", 
          signature, 
          message, 
          hex::encode(pubkey.serialize()));
    }
    is_valid
}

/*  1. Re-constructs merkle_root from merkle_path (found in control_block) and provided script.
    2. Determines the parity of the output key via the control byte (found in the control block).
        - the parity bit indicates whether the output key has an even or odd Y-coordinate
    3. Computes the tap tweak hash using the internal key and reconstructed merkle root.
        - tap_tweak_hash = tagged_hash("TapTweak", internal_key || merkle_root)
    4. Verifies that the provided output key can be derived from the internal key using the tweak.
        - tap_tweak_hash = tagged_hash("TapTweak", internal_key || merkle_root)
    5. This proves the script is committed to in the taptree described by the output key.
 */
pub fn verify_taproot_commitment(control_block_hex: String, output_key: XOnlyPublicKey, script: &Script) -> bool {

    let control_block_bytes = hex::decode(control_block_hex).unwrap();
    let control_block: ControlBlock = ControlBlock::decode(&control_block_bytes).unwrap();

    return control_block.verify_taproot_commitment(&SECP, output_key, script);
}

fn acquire_slh_dsa_keypair() -> UnifiedKeypair {
    /*
        In SPHINCS+ (underlying algorithm of SLH-DSA), the random data is used to:
            * Initialize hash function parameters within the key generation
            * Seed the Merkle tree construction that forms the public key
            * Generate the secret key components that enable signing
    */
    let random_data = get_random_bytes(128);
    let keypair: KeyPair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
            .expect("Failed to generate SLH-DSA-128S keypair");
    UnifiedKeypair::new_slh_dsa(keypair)
}

fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rng().fill_bytes(&mut bytes);
    bytes
}
