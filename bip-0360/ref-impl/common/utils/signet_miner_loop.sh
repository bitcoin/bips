#!/bin/bash

# Invokes mining simulator a configurable number of times

if [ -z "${P2MR_ADDR}" ]; then
    echo "Error: Environment variable P2MR_ADDR needs to be set"
    exit 1
fi


BITCOIN_SOURCE_DIR=${BITCOIN_SOURCE_DIR:-$HOME/bitcoin}

# path to bitcoin.conf for signet
BITCOIN_CONF_FILE_PATH=${BITCOIN_CONF_FILE_PATH:-$HOME/anduro-360/configs/bitcoin.conf.signet}

# Set default LOOP_COUNT to 110 if not set
LOOP_COUNT=${LOOP_COUNT:-110}

# Validate LOOP_COUNT is a positive integer
if ! [[ "$LOOP_COUNT" =~ ^[0-9]+$ ]] || [ "$LOOP_COUNT" -le 0 ]; then
    echo "Error: LOOP_COUNT must be a positive integer"
    exit 1
fi

# Determine name of pool by querying mempool.space backend
# curl -X GET "http://localhost:8999/api/v1/mining/pool/marapool" | jq -r .pool.regexes
export POOL_ID=${POOL_ID:-"MARA Pool"}

echo -en "\nLoop_COUNT = $LOOP_COUNT\nBITCOIN_CONF_FILE_PATH=$BITCOIN_CONF_FILE_PATH\nBITCOIN_SOURCE_DIR=$BITCOIN_SOURCE_DIR\nPOOL_ID=$POOL_ID\n\n";


for ((i=1; i<=LOOP_COUNT; i++))
do
    echo "Iteration $i of $LOOP_COUNT"
    $BITCOIN_SOURCE_DIR/contrib/signet/miner --cli "bitcoin-cli -conf=$BITCOIN_CONF_FILE_PATH" generate \
        --address $P2MR_ADDR \
        --grind-cmd "$BITCOIN_SOURCE_DIR/build/bin/bitcoin-util grind" \
        --poolid "$POOL_ID" \
        --min-nbits --set-block-time $(date +%s)
done
