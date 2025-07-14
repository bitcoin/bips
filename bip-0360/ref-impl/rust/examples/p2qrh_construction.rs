use p2qrh_ref::{create_p2qrh_utxo, create_multi_leaf_taptree};
use p2qrh_ref::data_structures::{UtxoReturn, TaptreeReturn, ConstructionReturn};
use std::env;

// Inspired by:  https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
fn main() -> ConstructionReturn {

    let _ = env_logger::try_init(); // Use try_init to avoid reinitialization error

    let mut total_leaf_count: u32 = 1;
    if let Ok(env_value) = env::var("TOTAL_LEAF_COUNT") {
        if let Ok(parsed_value) = env_value.parse::<u32>() {
            total_leaf_count = parsed_value;
        }
    }
    
    let mut leaf_of_interest: u32 = 0;
    if let Ok(env_value) = env::var("LEAF_OF_INTEREST") {
        if let Ok(parsed_value) = env_value.parse::<u32>() {
            leaf_of_interest = parsed_value;
        }
    }

    let taptree_return: TaptreeReturn = create_multi_leaf_taptree(total_leaf_count, leaf_of_interest);
    let p2qrh_utxo_return: UtxoReturn = create_p2qrh_utxo(taptree_return.clone().tree_root_hex);

    return ConstructionReturn {
        taptree_return: taptree_return,
        utxo_return: p2qrh_utxo_return,
    };
}
