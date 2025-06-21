pub mod data_structures;
pub mod error;

use std::io::Write;
use std::collections::HashMap;
use bitcoin::hashes::{sha256, Hash};


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