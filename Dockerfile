FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

LABEL org.opencontainers.image.source=https://github.com/sovanetwork/sova-reth
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    libclang-dev \
    pkg-config \
    protobuf-compiler

# Builds a cargo-chef plan
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Build profile, release by default
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE=$BUILD_PROFILE

# Extra Cargo flags
ARG RUSTFLAGS=""
ENV RUSTFLAGS="$RUSTFLAGS"

# Extra Cargo features
ARG FEATURES=""
ENV FEATURES=$FEATURES

# Builds dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --features "$FEATURES" --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --profile $BUILD_PROFILE --features "$FEATURES" --locked --bin sova-reth

# ARG is not resolved in COPY so we have to hack around it by copying the
# binary to a temporary location
RUN cp /app/target/$BUILD_PROFILE/sova-reth /app/sova-reth

# Use debian:bullseye-slim as the runtime image (like the original)
FROM debian:bullseye-slim
WORKDIR /app

# Install runtime dependencies and debugging tools (matching the original)
RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    curl \
    netcat \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy sova-reth over from the build stage
COPY --from=builder /app/sova-reth /usr/local/bin

# Copy licenses
COPY LICENSE-* ./

# Expose ports
EXPOSE 30303 30303/udp 9001 8545 8546

# Set the entrypoint to use shell (key change)
ENTRYPOINT ["/bin/sh", "-c"]

# Set the default command with environment variables
CMD ["sova-reth node \
    --btc-network $BTC_NETWORK \
    --network-url $BTC_RPC_URL \
    --btc-rpc-username $BTC_RPC_USER \
    --btc-rpc-password $BTC_RPC_PASSWORD \
    --network-signing-url $NETWORK_SIGNING_URL \
    --network-utxo-url $NETWORK_UTXO_URL \
    --sentinel-url $SENTINEL_URL \
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
    --log.stdout.filter $TRACE_LEVEL \
    --dev"]