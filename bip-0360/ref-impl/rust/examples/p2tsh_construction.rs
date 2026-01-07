use p2tsh_ref::{create_p2tsh_utxo, create_p2tsh_multi_leaf_taptree, parse_leaf_script_type};
use p2tsh_ref::data_structures::{UtxoReturn, TaptreeReturn, ConstructionReturn, LeafScriptType};
use std::env;
use log::{info, error};

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> ConstructionReturn {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let leaf_script_type = parse_leaf_script_type();
    info!("leaf_script_type: {:?}", leaf_script_type);

    let taptree_return: TaptreeReturn = create_p2tsh_multi_leaf_taptree();
    let p2tsh_utxo_return: UtxoReturn = create_p2tsh_utxo(taptree_return.clone().tree_root_hex);

    return ConstructionReturn {
        taptree_return: taptree_return,
        utxo_return: p2tsh_utxo_return,
    };
}
