use std::env;
use log::info;
use once_cell::sync::Lazy;
use bitcoin::hashes::{sha256::Hash, Hash as HashTrait};
use rand::{rng, RngCore};

use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify, Algorithm, KeyPair,
};

fn main() {
    let _ = env_logger::try_init();

    /*
      In SPHINCS+ (underlying algorithm of SLH-DSA), the random data is used to:
        * Initialize hash function parameters within the key generation
        * Seed the Merkle tree construction that forms the public key
        * Generate the secret key components that enable signing
     */
    let random_data = get_random_bytes(128);
    println!("Generated random data of size {}", random_data.len());

    let keypair: KeyPair = generate_keypair(Algorithm::SLH_DSA_128S, &random_data)
        .expect("Failed to generate SLH-DSA-128S keypair");

    let message_bytes = b"SLH-DSA-128S Test Message";

    println!("Message to sign: {message_bytes:?}");

    /*  No need to hash the message
        1. Variable Input Size: SPHINCS+ can handle messages of arbitrary length directly
        2. Internal Hashing: The SPHINCS+ algorithm internally handles message processing and hashing as part of its design
        3. Hash-Based Design: SPHINCS+ is built on hash functions and Merkle trees, so it's designed to work with variable-length inputs
        4. No Curve Constraints: Unlike elliptic curve schemes, SPHINCS+ doesn't have fixed field size requirements

        SLH-DSA doesn't use nonces like Schnorr does.
        With SLH-DSA, randomness is built into the key generation process only ( and not the signing process; ie: SECP256K1)
        Thus, no need for aux_rand data fed to the signature function.
        The signing algorithm is deterministic and doesn't require random input during signing.
     */

    let signature = sign(&keypair.secret_key, message_bytes).expect("Failed to sign with SLH-DSA-128S");

    println!(
        "Signature created successfully, size: {}",
        signature.bytes.len()
    );
    println!(
        "Signature prefix: {:02x?}",
        &signature.bytes[..8.min(signature.bytes.len())]
    );

    // Verify the signature
    println!("Verifying signature...");
    let result = verify(&keypair.public_key, message_bytes, &signature);
    println!("Verification result: {result:?}");

    assert!(result.is_ok(), "SLH-DSA-128S signature verification failed");

    // Try to verify with a modified message - should fail
    let modified_message = b"SLH-DSA-128S Modified Message";
    println!("Modified message: {modified_message:?}");

    let result = verify(&keypair.public_key, modified_message, &signature);
    println!("Verification with modified message result: {result:?}");

    assert!(
        result.is_err(),
        "SLH-DSA-128S verification should fail with modified message"
    );
}

fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rng().fill_bytes(&mut bytes);
    bytes
}
