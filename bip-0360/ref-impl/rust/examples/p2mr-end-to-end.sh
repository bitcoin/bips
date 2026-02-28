
export BITCOIN_SOURCE_DIR=$HOME/bitcoin
export W_NAME=anduro
export USE_PQC=false
export TOTAL_LEAF_COUNT=5
export LEAF_TO_SPEND_FROM=4

b-cli -named createwallet \
    wallet_name=$W_NAME \
    descriptors=true \
    load_on_startup=true

export BITCOIN_ADDRESS_INFO=$( cargo run --example p2mr_construction ) \
    && echo $BITCOIN_ADDRESS_INFO | jq -r .

export QUANTUM_ROOT=$( echo $BITCOIN_ADDRESS_INFO | jq -r '.taptree_return.tree_root_hex' ) \
    && export LEAF_SCRIPT_PRIV_KEY_HEX=$( echo $BITCOIN_ADDRESS_INFO | jq -r '.taptree_return.leaf_script_priv_key_hex' ) \
    && export LEAF_SCRIPT_HEX=$( echo $BITCOIN_ADDRESS_INFO | jq -r '.taptree_return.leaf_script_hex' ) \
    && export CONTROL_BLOCK_HEX=$( echo $BITCOIN_ADDRESS_INFO | jq -r '.taptree_return.control_block_hex' ) \
    && export FUNDING_SCRIPT_PUBKEY=$( echo $BITCOIN_ADDRESS_INFO | jq -r '.utxo_return.script_pubkey_hex' ) \
    && export P2MR_ADDR=$( echo $BITCOIN_ADDRESS_INFO | jq -r '.utxo_return.bech32m_address' )

b-cli decodescript $LEAF_SCRIPT_HEX | jq -r '.asm'

export COINBASE_REWARD_TX_ID=$( b-cli -named generatetoaddress 1 $P2MR_ADDR 5 | jq -r '.[]' ) \
    && echo $COINBASE_REWARD_TX_ID

export P2MR_DESC=$( b-cli getdescriptorinfo "addr($P2MR_ADDR)" | jq -r '.descriptor' ) \
    && echo $P2MR_DESC \
    && b-cli scantxoutset start '[{"desc": "'''$P2MR_DESC'''"}]'
