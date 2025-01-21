# build rust binary
alias b := build

build:
    cargo build --release

# formatting check
fmt:
    cargo fmt --all --check

# run linter
clippy:
    cargo clippy -- -D warnings

# clean data directory
clean-data:
    rm -rf ./data

# compile and run sova in dev mode using bitcoin regtest and accompanying services
run-sova-regtest clean="false":
    if [ "{{clean}}" = "clean" ]; then just clean-data; fi
    just b && ./target/release/sova-reth node \
    --chain dev \
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
    --log.stdout.filter info \
    --dev

# compile and run sova in mainnet mode using bitcoin regtest and accompanying services
run-sova-mainnet-regtest clean="false":
    if [ "{{clean}}" = "clean" ]; then just clean-data; fi
    just b && ./target/release/sova-reth node \
    --chain sova \
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