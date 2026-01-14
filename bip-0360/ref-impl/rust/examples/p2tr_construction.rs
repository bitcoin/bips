use p2tsh_ref::{create_p2tr_utxo, create_p2tr_multi_leaf_taptree};
use p2tsh_ref::data_structures::{UtxoReturn, TaptreeReturn, ConstructionReturn};

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> ConstructionReturn {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error
    
    let internal_pubkey_hex = "924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329".to_string();
    
    let taptree_return: TaptreeReturn = create_p2tr_multi_leaf_taptree(internal_pubkey_hex.clone());
    let utxo_return: UtxoReturn = create_p2tr_utxo(taptree_return.clone().tree_root_hex, internal_pubkey_hex);
    return ConstructionReturn {
        taptree_return: taptree_return,
        utxo_return: utxo_return,
    };
}
