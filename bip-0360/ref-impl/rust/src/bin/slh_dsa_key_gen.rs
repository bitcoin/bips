use std::env;
use log::info;
use rand::{rng, RngCore};

use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, Algorithm, KeyPair,
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

    info!("public key size / value = {}, {}", public_key_size(Algorithm::SLH_DSA_128S), hex::encode(&keypair.public_key.bytes));
    info!("private key size / value = {}, {}", secret_key_size(Algorithm::SLH_DSA_128S), hex::encode(&keypair.secret_key.bytes));

}

fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    rng().fill_bytes(&mut bytes);
    bytes
}
