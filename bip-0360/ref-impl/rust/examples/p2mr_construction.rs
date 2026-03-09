use p2mr_ref::{create_p2mr_utxo, create_p2mr_multi_leaf_taptree, tap_tree_lock_type};
use p2mr_ref::data_structures::{UtxoReturn, TaptreeReturn, ConstructionReturn, LeafScriptType};
use std::env;
use log::{info, error};

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> ConstructionReturn {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let tap_tree_lock_type = tap_tree_lock_type();
    info!("tap_tree_lock_type: {:?}", tap_tree_lock_type);

    let taptree_return: TaptreeReturn = create_p2mr_multi_leaf_taptree();
    let p2mr_utxo_return: UtxoReturn = create_p2mr_utxo(taptree_return.clone().tree_root_hex);

    // Alert user about SPENDING_LEAF_TYPE requirement when using MIXED mode
    if tap_tree_lock_type == LeafScriptType::Mixed {
        info!("NOTE: TAP_TREE_LOCK_TYPE=MIXED requires setting SPENDING_LEAF_TYPE when spending (based on leaf_script_type in output above) as follows:");
        info!("      export SPENDING_LEAF_TYPE={}", taptree_return.leaf_script_type);
    }

    return ConstructionReturn {
        taptree_return: taptree_return,
        utxo_return: p2mr_utxo_return,
    };
}
