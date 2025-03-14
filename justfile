# Global variables
BIN_DIR := "dist/bin"
CARGO_TARGET_DIR := "target"
DOCKER_IMAGE_NAME := "ghcr.io/sovaNetwork/sova-reth"
PROFILE := "release"

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
    --sentinel-url "http://[::1]:50051" \
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
    --sentinel-url "http://[::1]:50051" \
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

# Ensure the binary directory exists
ensure-bin-dir:
    mkdir -p dist/bin/amd64 dist/bin/arm64

# Build for x86_64 with protobuf
build-x86_64:
    sudo apt-get update && sudo apt-get install -y protobuf-compiler
    cargo build --release --target x86_64-unknown-linux-gnu
    cp target/x86_64-unknown-linux-gnu/release/sova-reth dist/bin/amd64/

# Build for aarch64 with protobuf
build-aarch64:
    sudo apt-get update && sudo apt-get install -y protobuf-compiler
    cross build --release --target aarch64-unknown-linux-gnu
    cp target/aarch64-unknown-linux-gnu/release/sova-reth dist/bin/arm64/

# Docker cross-platform build and push
docker-build-push VERSION="latest":
    just ensure-bin-dir
    just build-x86_64
    just build-aarch64
    
    # Build and push Docker image
    docker buildx build --file ./Dockerfile.cross . \
        --platform linux/amd64,linux/arm64 \
        --tag ghcr.io/sovaNetwork/sova-reth:{{VERSION}} \
        --provenance=false \
        --push