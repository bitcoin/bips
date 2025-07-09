use bitcoin::taproot::TapNodeHash;
use p2qrh_ref::create_p2qrh_utxo;
use p2qrh_ref::data_structures::P2qrhUtxoReturn;
use bitcoin::hashes::Hash;
use hex;

fn main() -> P2qrhUtxoReturn {
    let p2qrh_utxo_return: P2qrhUtxoReturn = p2qrh_script_path_utxo_construction();
    p2qrh_utxo_return
}

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn p2qrh_script_path_utxo_construction() -> P2qrhUtxoReturn {

    let merkle_root_bytes= hex::decode("858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16").unwrap();
    let merkle_root: TapNodeHash = TapNodeHash::from_byte_array(merkle_root_bytes.try_into().unwrap());

    let p2qrh_utxo_return: P2qrhUtxoReturn = create_p2qrh_utxo(merkle_root);

    return p2qrh_utxo_return;
}

