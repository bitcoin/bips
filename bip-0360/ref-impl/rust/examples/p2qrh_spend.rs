use p2qrh_ref::{ p2qrh_to_p2wpkh_tx };

use p2qrh_ref::data_structures::P2qrhSpendDetails;

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> P2qrhSpendDetails {

    let input_tx_id_bytes: Vec<u8> =
        hex::decode("d1c40446c65456a9b11a9dddede31ee34b8d3df83788d98f690225d2958bfe3c").unwrap();

    // The input index of the funding tx
    let input_tx_index: u32 = 0;

    // OP_PUSHBYTES_32 6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG
    let input_leaf_script_bytes: Vec<u8> =
        hex::decode("206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac").unwrap();

    // Modified from learnmeabitcoin example
    // Changed from c0 to c1 control byte to reflect p2qrh specification:  The parity bit of the control byte is always 1 since P2QRH does not have a key-spend path.
    let input_control_block_bytes: Vec<u8> =
        hex::decode("c1924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329").unwrap();

    let input_script_pubkey_bytes: Vec<u8> =
        hex::decode("5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80")
            .unwrap();
    let input_script_priv_key_bytes: Vec<u8> = hex::decode("9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189").unwrap();

    let spend_pubkey_hash_bytes: Vec<u8> = hex::decode("0de745dc58d8e62e6f47bde30cd5804a82016f9e").unwrap();

    let result: P2qrhSpendDetails = p2qrh_to_p2wpkh_tx(input_tx_id_bytes,
        input_tx_index,
        input_script_pubkey_bytes,
        input_control_block_bytes,
        spend_pubkey_hash_bytes,
        input_leaf_script_bytes,
        input_script_priv_key_bytes
    );

    return result;
}
