use log::info;
use once_cell::sync::Lazy;
use bitcoin::key::{Secp256k1};
use bitcoin::hashes::{sha256::Hash, Hash as HashTrait};
use bitcoin::secp256k1::{Message};

use p2mr_ref::{ acquire_schnorr_keypair, verify_schnorr_signature };

/* Secp256k1 implements the Signing trait when it's initialized in signing mode.
   It's important to note that Secp256k1 has different capabilities depending on how it's constructed:
      * Secp256k1::new() creates a context capable of both signing and verification
      * Secp256k1::signing_only() creates a context that can only sign
      * Secp256k1::verification_only() creates a context that can only verify
*/
static SECP: Lazy<Secp256k1<bitcoin::secp256k1::All>> = Lazy::new(Secp256k1::new);

fn main() {
    let _ = env_logger::try_init();

    // acquire a schnorr keypair (leveraging OS provided random number generator)
    let keypair = acquire_schnorr_keypair();
    let (secret_key, public_key) = keypair.as_schnorr().unwrap();
    let message_bytes = b"hello";
    
    // secp256k1 operates on a 256-bit (32-byte) field, so inputs must be exactly this size
    // subsequently, Schnorr signatures on secp256k1 require exactly a 32-byte input (the curve's scalar field size)
    let message_hash: Hash = Hash::hash(message_bytes);

    let message: Message = Message::from_digest_slice(&message_hash.to_byte_array()).unwrap();
    
    
    /* The secp256k1 library internally generates a random scalar value (aka: nonce or k-value) for each signature
    * Every signature is unique - even if you sign the same message with the same private key multiple times
    * The randomness is handled automatically by the secp256k1 implementation
    * You get different signatures each time for the same inputs
    * The nonce is only needed during signing, not during verification
    
    Schnorr signatures require randomness for security reasons:
    * Prevents private key recovery - If the same nonce is used twice, an attacker could potentially derive your private key
    * Ensures signature uniqueness - Each signature should be cryptographically distinct
    * Protects against replay attacks - Different signatures for the same data
    */
    let signature: bitcoin::secp256k1::schnorr::Signature = SECP.sign_schnorr(&message, &secret_key.keypair(&SECP));
    info!("Signature created successfully, size: {}", signature.serialize().len());
    
    //let pubkey = public_key;


    /*
      * The nonce provides security during signing (prevents private key recovery)
      * The nonce is mathematically eliminated during verification
      * The verifier only needs public information (signature, message, public key)
     */
    let schnorr_valid = verify_schnorr_signature(signature, message, *public_key);
    info!("schnorr_valid: {}", schnorr_valid);


    let aux_rand = [0u8; 32]; // 32 zero bytes; fine for testing
    let signature_aux_rand: bitcoin::secp256k1::schnorr::Signature = SECP.sign_schnorr_with_aux_rand(
        &message,
        &secret_key.keypair(&SECP),
        &aux_rand
    );
    info!("aux_rand signature created successfully, size: {}", signature_aux_rand.serialize().len());

    let schnorr_valid_aux_rand = verify_schnorr_signature(signature_aux_rand, message, *public_key);
    info!("schnorr_valid_aux_rand: {}", schnorr_valid_aux_rand);
}
