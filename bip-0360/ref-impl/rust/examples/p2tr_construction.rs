
use p2qrh_ref::create_p2tr_utxo;
use p2qrh_ref::data_structures::UtxoReturn;

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> UtxoReturn {
    
    let merkle_root_hex = "858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16".to_string();
    let internal_pubkey_hex = "924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329".to_string();
    
    let p2tr_utxo_return: UtxoReturn = create_p2tr_utxo(merkle_root_hex, internal_pubkey_hex);
    p2tr_utxo_return
}
