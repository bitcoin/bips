use p2qrh_ref::{create_p2qrh_utxo, create_p2qrh_multi_leaf_taptree};
use p2qrh_ref::data_structures::{UtxoReturn, TaptreeReturn, ConstructionReturn};

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> ConstructionReturn {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let taptree_return: TaptreeReturn = create_p2qrh_multi_leaf_taptree();
    let p2qrh_utxo_return: UtxoReturn = create_p2qrh_utxo(taptree_return.clone().tree_root_hex);

    return ConstructionReturn {
        taptree_return: taptree_return,
        utxo_return: p2qrh_utxo_return,
    };
}
