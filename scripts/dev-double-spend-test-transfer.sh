#!/bin/bash

# Resources:
# https://github.com/PowVT/satoshi-suite
# https://github.com/SovaNetwork/running-sova
# https://github.com/foundry-rs

# This script tests double-spend functionality for a dev sova-reth node using bitcoin regtest
#
# It:
# 1. Creates onr Bitcoin transaction, with 0.001 BTC fee
# 2. Submits the BTC transaction to uBTC contract for deposit
# 3. Test transfer of uBTC to another user. This should fail and enforce the locks places on the slots.
# 4. Check the balanceOf user and total supply slots in the sova uBTC smart contract

# Exit on error
set -e

# Configuration
WALLET_1="user"
WALLET_2="miner"
UBTC_BITCOIN_RECEIVE_ADDRESS="bcrt1q8pw3u88q56mfdqhxyeu0a7fesddq8jwsxxqng8"
DOUBLE_SPEND_RECEIVE_ADDRESS="bcrt1q6xxa0arlrk6jdz02alxc6smdv5g953v7zkswaw" # random address for double spend
ETH_RPC_URL="http://localhost:8545"
ETH_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CHAIN_ID="120893"

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
satoshi-suite new-wallet --wallet-name "$WALLET_1"
satoshi-suite new-wallet --wallet-name "$WALLET_2"

echo "Mining initial blocks..."
satoshi-suite mine-blocks --wallet-name "$WALLET_1" --blocks 1
satoshi-suite mine-blocks --wallet-name "$WALLET_2" --blocks 100

echo "Creating Bitcoin transactions..."
# Transaction with 0.001 fee
TX1_OUTPUT=$(satoshi-suite sign-tx --wallet-name "$WALLET_1" --recipient "$UBTC_BITCOIN_RECEIVE_ADDRESS" --amount 49.999 --fee-amount 0.001)
TX1_HEX=$(get_tx_hex "$TX1_OUTPUT")

# For debugging
echo "TX1 Hex: $TX1_HEX"

echo "Deploying uBTC contract..."
cd ~/contracts
DEPLOY_OUTPUT=$(forge create --rpc-url http://localhost:8545 --broadcast \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
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

echo "Checking contract state..."
    BALANCE=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
        "balanceOf(address)" \
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

    TOTAL_SUPPLY=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
        "totalSupply()")

    echo "Balance: $BALANCE"
    echo "Total Supply: $TOTAL_SUPPLY"

echo "Submitting erc20 transfer() call (should fail)..."

# This should fail
cast send \
    --rpc-url "$ETH_RPC_URL" \
    --private-key "$ETH_PRIVATE_KEY" \
    --gas-limit 100000 \
    --chain-id "$CHAIN_ID" \
    "$CONTRACT_ADDRESS" \
    "transfer(address,uint256)" \
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" \
    "100"

echo "Checking contract state..."
    BALANCE=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
        "balanceOf(address)" \
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

    TOTAL_SUPPLY=$(cast call --rpc-url "$ETH_RPC_URL" "$CONTRACT_ADDRESS" \
        "totalSupply()")

    echo "Balance: $BALANCE"
    echo "Total Supply: $TOTAL_SUPPLY"

echo "mining blocks to conifirm btc tx..."
satoshi-suite mine-blocks --wallet-name "$WALLET_2" --blocks 7

echo "Submitting erc20 transfer() call (should succeed)..."

cast send \
    --rpc-url "$ETH_RPC_URL" \
    --private-key "$ETH_PRIVATE_KEY" \
    --gas-limit 100000 \
    --chain-id "$CHAIN_ID" \
    "$CONTRACT_ADDRESS" \
    "transfer(address,uint256)" \
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" \
    "100"

echo "Done!"