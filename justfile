# build rust binary
alias b := build

build:
    cargo build --release

# list all CLI flags
help:
    ./target/release/corsa-reth -h

node-help:
    ./target/release/corsa-reth node -h

# run corsa chain
run-chain btc_network="regtest" network_url="http://127.0.0.1" btc_rpc_username="user" btc_rpc_password="password" network_signing_url="http://127.0.0.1:5555" network_utxo_url="http://127.0.0.1:5557" btc_tx_queue_url="http://127.0.0.1:5558":
    cargo run --release -- --btc-network {{btc_network}} --network-url {{network_url}} --btc-rpc-username {{btc_rpc_username}} --btc-rpc-password {{btc_rpc_password}} --network-signing-url {{network_signing_url}} --network-utxo-url {{network_utxo_url}} --btc-tx-queue-url {{btc_tx_queue_url}}

# run corsa chain on bitcoin regtest network
run-chain-regtest:
    ./target/release/corsa-reth node \
    --chain crates/chainspec/src/genesis/dev.json \
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
    --log.stdout.filter info \
    --dev