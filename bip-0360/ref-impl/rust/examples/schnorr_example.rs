use std::env;
use log::info;
use once_cell::sync::Lazy;
use bitcoin::key::{Secp256k1};
use bitcoin::hashes::{sha256::Hash, Hash as HashTrait};
use bitcoin::secp256k1::{Message};

use p2qrh_ref::{ acquire_schnorr_keypair, verify_schnorr_signature };

/* Secp256k1 implements the Signing trait when it's initialized in signing mode.
   It's important to note that Secp256k1 has different capabilities depending on how it's constructed:
      * Secp256k1::new() creates a context capable of both signing and verification
      * Secp256k1::signing_only() creates a context that can only sign
      * Secp256k1::verification_only() creates a context that can only verify
*/
static SECP: Lazy<Secp256k1<bitcoin::secp256k1::All>> = Lazy::new(Secp256k1::new);

fn main() {
    let _ = env_logger::try_init();
    let keypair = acquire_schnorr_keypair();
    let message_bytes = b"hello";
    
    // Hash the message first to get a 32-byte digest
    let message_hash = Hash::hash(message_bytes);
    let message = Message::from_digest_slice(&message_hash.to_byte_array()).unwrap();
    let pubkey = keypair.1;

    let signature: bitcoin::secp256k1::schnorr::Signature = SECP.sign_schnorr(&message, &keypair.0.keypair(&SECP));

    let signature_aux_rand: bitcoin::secp256k1::schnorr::Signature = SECP.sign_schnorr_with_aux_rand(
        &message,
        &keypair.0.keypair(&SECP),
        &[0u8; 32] // 32 zero bytes of auxiliary random data
    );

    let schnorr_valid = verify_schnorr_signature(signature, message, pubkey);
    info!("schnorr_valid: {}", schnorr_valid);

    let schnorr_valid_aux_rand = verify_schnorr_signature(signature_aux_rand, message, pubkey);
    info!("schnorr_valid_aux_rand: {}", schnorr_valid_aux_rand);
}