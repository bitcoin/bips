use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use miniscript::Miniscript;
use bitcoin::secp256k1::{Secp256k1, PublicKey, XOnlyPublicKey};
use bitcoin::address::Address;
use bitcoin::Network;
use log::{debug, info, error};
use once_cell::sync::Lazy;
use anyhow::{anyhow, Result};

use p2qrh_ref::data_structures::{TestVector, TestVectors};

static TEST_VECTORS: Lazy<TestVectors> = Lazy::new(|| {
    let bip360_test_vectors = include_str!("../tests/data/bip-0360/test_vectors.json");
    let test_vectors: TestVectors = serde_json::from_str(bip360_test_vectors).unwrap();
    assert_eq!(test_vectors.version, 1);
    test_vectors
});

#[test]
fn test_descriptor_p2qrh() -> anyhow::Result<()> {
    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let test_vectors = &*TEST_VECTORS;

    let secp = Secp256k1::new();
    
    let xonly_pubkey = XOnlyPublicKey::from_slice(&hex::decode("03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115").unwrap())?;

    // P2TR
    let p2tr = Descriptor::new_tr(xonly_pubkey, None)?;
    let p2tr_addr = Address::from_script(&p2tr.script_pubkey(), Network::Bitcoin)?;
    println!("P2TR: {} (Address: {})", p2tr, p2tr_addr);

    Ok(())
}