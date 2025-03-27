#!/bin/bash

# Resources:
# https://github.com/PowVT/satoshi-suite
# https://github.com/SovaNetwork/running-sova
# https://github.com/foundry-rs

# This script tests double-spend functionality for a dev sova-reth node using bitcoin regtest
#
# It:
# 1. Creates two Bitcoin transactions spending the same UTXO:
#    - First with 0.001 BTC fee
#    - Second with 0.01 BTC fee (broadcasted to Bitcoin network)
# 2. Submits the first transaction to uBTC contract for deposit
# 3. Broadcasts the second transaction to Bitcoin network in same bitcoin block
# 4. Mines confirmation blocks to ensure the double spend Bitcoin transaction is confirmed
# 5. Check the balanceOf user and total supply slots in the sova uBTC smart contract
# 6. User user creates another Bitcoin transaction for a deposit of the same amount and sends to the node
# 7. Check the balanceOf user and total supply slots again
# 8. Confirm bitcoin transaction by mining bitcoin blocks
# 9. Tests withdrawal functionality after the double-spend attack

# Exit on error
set -e

# Configuration
WALLET_1="user"
WALLET_2="miner"
UBTC_BITCOIN_RECEIVE_ADDRESS="bcrt1q8pw3u88q56mfdqhxyeu0a7fesddq8jwsxxqng8" # needs to be updated when eth_address changes since the ETH_ADDRESS is deployer
DOUBLE_SPEND_RECEIVE_ADDRESS="bcrt1q6xxa0arlrk6jdz02alxc6smdv5g953v7zkswaw" # random address for double spend
ETH_RPC_URL="http://localhost:8545"
ETH_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
ETH_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CHAIN_ID="120893"

# Bitcoin RPC Configuration - using the working parameters
# Port automatically assigned by satoshi-suite
BTC_RPC_URL="http:localhost"
BTC_RPC_USER="user"
BTC_RPC_PASS="password"
BTC_NETWORK="regtest"

# UTXO Indexer Configuration
# Default values if not provided in environment
INDEXER_HOST="localhost"
INDEXER_PORT="5557"
INDEXER_URL="http://${INDEXER_HOST}:${INDEXER_PORT}"

# Function to convert BTC to smallest unit (satoshis)
btc_to_sats() {
    echo "$1 * 100000000" | bc | cut -d'.' -f1
}

# Function to extract transaction hex
get_tx_hex() {
    local output=$1
    local hex=$(echo "$output" | grep "Signed transaction:" | sed 's/.*Signed transaction: //')
    echo "$hex"
}

echo "Creating Bitcoin wallets..."
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" new-wallet --wallet-name "$WALLET_1"
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" new-wallet --wallet-name "$WALLET_2"

echo "Mining initial blocks..."
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" mine-blocks --wallet-name "$WALLET_1" --blocks 1
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" mine-blocks --wallet-name "$WALLET_2" --blocks 100

echo "Creating Bitcoin transactions..."
# First transaction with 0.001 fee
TX1_OUTPUT=$(satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" sign-tx --wallet-name "$WALLET_1" --recipient "$UBTC_BITCOIN_RECEIVE_ADDRESS" --amount 49.999 --fee-amount 0.001)
TX1_HEX=$(get_tx_hex "$TX1_OUTPUT")

# Second transaction with 0.01 fee
TX2_OUTPUT=$(satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" sign-tx --wallet-name "$WALLET_1" --recipient "$DOUBLE_SPEND_RECEIVE_ADDRESS" --amount 49.99 --fee-amount 0.01)
TX2_HEX=$(get_tx_hex "$TX2_OUTPUT")

# For debugging
echo "TX1 Hex: $TX1_HEX"
echo "TX2 Hex: $TX2_HEX"

echo "Deploying uBTC contract..."
cd ~/contracts
DEPLOY_OUTPUT=$(forge create --rpc-url "$ETH_RPC_URL" --broadcast \
    --private-key "$ETH_PRIVATE_KEY" \
    src/uBTC.sol:uBTC)
CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "Deployed to:" | cut -d' ' -f3)
echo "Contract deployed to: $CONTRACT_ADDRESS"

cd ~

# Convert 49.999 BTC to satoshis
AMOUNT_SATS=$(btc_to_sats 49.999)

echo "Submitting first transaction to Ethereum contract (0.001 fee)..."
cast send \
    --rpc-url "$ETH_RPC_URL" \
    --private-key "$ETH_PRIVATE_KEY" \
    --gas-limit 250000 \
    --chain-id "$CHAIN_ID" \
    "$CONTRACT_ADDRESS" \
    "depositBTC(uint256,bytes)" \
    "$AMOUNT_SATS" \
    "0x$TX1_HEX"

echo "Broadcasting competing Bitcoin transaction (0.01 fee)..."
TX_BROADCAST_OUTPUT=$(satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" broadcast-tx --tx-hex "$TX2_HEX")
TX_ID=$(echo "$TX_BROADCAST_OUTPUT" | grep "Broadcasted transaction:" | cut -d' ' -f3)

echo "Mining confirmation blocks for double-spend transaction..."
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" mine-blocks --wallet-name "$WALLET_2" --blocks 19
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" mine-blocks --wallet-name "$WALLET_1" --blocks 1
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" mine-blocks --wallet-name "$WALLET_2" --blocks 100

echo "Checking contract state..."
BALANCE=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
    "balanceOf(address)" \
    "$ETH_ADDRESS" | cast to-dec)
TOTAL_SUPPLY=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
    "totalSupply()" | cast to-dec)

echo "Balance: $BALANCE"
echo "Total Supply: $TOTAL_SUPPLY"

echo "Creating new Bitcoin transaction for second VALID deposit..."
TX3_OUTPUT=$(satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" sign-tx --wallet-name "$WALLET_1" --recipient "$UBTC_BITCOIN_RECEIVE_ADDRESS" --amount 49.999 --fee-amount 0.001)
TX3_HEX=$(get_tx_hex "$TX3_OUTPUT")

echo "Submitting second deposit to Ethereum contract..."
cast send \
    --rpc-url "$ETH_RPC_URL" \
    --private-key "$ETH_PRIVATE_KEY" \
    --gas-limit 250000 \
    --chain-id "$CHAIN_ID" \
    "$CONTRACT_ADDRESS" \
    "depositBTC(uint256,bytes)" \
    "$AMOUNT_SATS" \
    "0x$TX3_HEX"

echo "Checking contract state..."
BALANCE=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
    "balanceOf(address)" \
    "$ETH_ADDRESS" | cast to-dec)
TOTAL_SUPPLY=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
    "totalSupply()" | cast to-dec)

echo "Balance: $BALANCE"
echo "Total Supply: $TOTAL_SUPPLY"

echo "Mining confirmation blocks for second deposit..."
satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" mine-blocks --wallet-name "$WALLET_2" --blocks 7

# Get current Bitcoin block height
BTC_BLOCK_HEIGHT=$(satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" get-block-height | grep "Current block height:" | cut -d' ' -f8)

# set withdrawal amount to 10.00 BTC
WITHDRAWAL_AMOUNT=$(btc_to_sats 10.00)

echo "Waiting for UTXO indexer to catch up..."
while true; do
    RESPONSE=$(curl -s "${INDEXER_URL}/latest-block")
    LATEST_BLOCK=$(echo $RESPONSE | jq -r '.latest_block')
    echo "Current BTC block height: $BTC_BLOCK_HEIGHT"
    echo "Latest indexed block: $LATEST_BLOCK"
    
    if [ "$LATEST_BLOCK" -ge "$BTC_BLOCK_HEIGHT" ]; then
        UTXOS=$(curl -s "${INDEXER_URL}/spendable-utxos/block/$BTC_BLOCK_HEIGHT/address/$UBTC_BITCOIN_RECEIVE_ADDRESS")
        
        # Check if we got an error response
        if ! echo "$UTXOS" | jq -e '.error' > /dev/null; then
            TOTAL_AMOUNT=$(echo "$UTXOS" | jq -r '.total_amount')
            echo "Found UTXOs worth $TOTAL_AMOUNT satoshis"
            if [ "$TOTAL_AMOUNT" -gt "$WITHDRAWAL_AMOUNT" ]; then
                echo "Sufficient UTXOs found for withdrawal of $WITHDRAWAL_AMOUNT satoshis"
                break
            fi
        else
            echo "Waiting for UTXOs to be indexed..."
        fi
    fi
    sleep 2
done

echo "Initiating withdrawal..."

# Generate new Bitcoin address for withdrawal
NEW_ADDRESS=$(satoshi-suite --rpc-url "$BTC_RPC_URL" --network "$BTC_NETWORK" --rpc-username "$BTC_RPC_USER" --rpc-password "$BTC_RPC_PASS" get-new-address --wallet-name "$WALLET_1" | grep "New address:" | cut -d' ' -f7)

cast send \
    --rpc-url "$ETH_RPC_URL" \
    --private-key "$ETH_PRIVATE_KEY" \
    --gas-limit 300000 \
    --chain-id "$CHAIN_ID" \
    "$CONTRACT_ADDRESS" \
    "withdraw(uint64,uint32,string)" \
    "$WITHDRAWAL_AMOUNT" \
    "$BTC_BLOCK_HEIGHT" \
    "$NEW_ADDRESS"

echo "Checking contract state..."
BALANCE=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
    "balanceOf(address)" \
    "$ETH_ADDRESS" | cast to-dec)
TOTAL_SUPPLY=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
    "totalSupply()" | cast to-dec)

echo "Balance: $BALANCE"
echo "Total Supply: $TOTAL_SUPPLY"

echo "Done!"