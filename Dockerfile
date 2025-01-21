# Use Rust 1.83.0
FROM rust:1.83.0-bullseye as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libclang-dev \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/src/sova-reth

# Copy Cargo.toml and Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY . .

# Build the project
RUN cargo build --release --locked --bin sova-reth

# Start a new stage for a smaller final image
FROM debian:bullseye-slim

# Install runtime dependencies and debugging tools
RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    curl \
    netcat \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/local/bin

# Copy the binary from the builder stage
COPY --from=builder /usr/src/sova-reth/target/release/sova-reth .

# Expose port 8545 for JSON-RPC
EXPOSE 8545

# Set the entrypoint
ENTRYPOINT ["/bin/sh", "-c"]

# Set the default command
CMD ["sova-reth node \
    --btc-network $BTC_NETWORK \
    --network-url $BTC_RPC_URL \
    --btc-rpc-username $BTC_RPC_USER \
    --btc-rpc-password $BTC_RPC_PASSWORD \
    --network-signing-url $NETWORK_SIGNING_URL \
    --network-utxo-url $NETWORK_UTXO_URL \
    --btc-tx-queue-url $BTC_TX_QUEUE_URL \
    --chain $CHAIN \
    --datadir /var/lib/sova \
    --http \
    --http.addr 0.0.0.0 \
    --http.port 8545 \
    --ws \
    --ws.addr 0.0.0.0 \
    --ws.port 8546 \
    --http.api all \
    --authrpc.addr 0.0.0.0 \
    --authrpc.port 8551 \
    --log.stdout.filter $TRACE_LEVEL"]