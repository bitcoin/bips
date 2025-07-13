use p2qrh_ref::{create_p2qrh_utxo, tagged_hash};
use p2qrh_ref::data_structures::UtxoReturn;

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> UtxoReturn {
    
    let merkle_root_hex = hex::decode("858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16").unwrap();
    let quantum_root_hex = tagged_hash("QuantumRoot", &merkle_root_hex);
    let p2qrh_utxo_return: UtxoReturn = create_p2qrh_utxo(quantum_root_hex);
    p2qrh_utxo_return
}
