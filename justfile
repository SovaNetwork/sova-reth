# build rust binary
alias b := build

build:
    cargo build --release

# list all CLI flags
help:
    ./target/release/corsa-reth -h

# run dev chain on bitcoin regtest network
run-chain-dev-regtest:
    ./target/release/corsa-reth node \
    --chain genesis.json \
    --btc-network "regtest" \
    --network-url "http://127.0.0.1" \
    --btc-rpc-username "user" \
    --btc-rpc-password "password" \
    --network-signing-url "http://127.0.0.1:5555" \
    --network-utxo-url "http://127.0.0.1:5557" \
    --btc-tx-queue-url "http://127.0.0.1:5558" \
    --http \
    --http.addr "127.0.0.1" \
    --http.port 8545 \
    --ws \
    --ws.addr "127.0.0.1" \
    --ws.port 8546 \
    --http.api all \
    --authrpc.addr "127.0.0.1" \
    --authrpc.port 8551 \
    --datadir ./data \
    --dev

# run prod chain on bitcoin regtest network
run-chain-prod-regtest:
    ./target/release/corsa-reth node \
    --chain genesis.json \
    --btc-network "regtest" \
    --network-url "http://127.0.0.1" \
    --btc-rpc-username "user" \
    --btc-rpc-password "password" \
    --network-signing-url "http://127.0.0.1:5555" \
    --network-utxo-url "http://127.0.0.1:5557" \
    --btc-tx-queue-url "http://127.0.0.1:5558" \
    --addr "0.0.0.0" \
    --port 30303 \
    --discovery.addr "0.0.0.0" \
    --discovery.port 30303 \
    --http \
    --http.addr "127.0.0.1" \
    --http.port 8545 \
    --ws \
    --ws.addr "127.0.0.1" \
    --ws.port 8546 \
    --http.api all \
    --authrpc.addr "127.0.0.1" \
    --authrpc.port 8551 \
    --datadir ./data \
    --log.stdout.filter info