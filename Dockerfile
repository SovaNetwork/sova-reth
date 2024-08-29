# Use Rust 1.80.0
FROM rust:1.80.0-bullseye as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libclang-dev \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /usr/src/corsa-reth

# Copy Cargo.toml and Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY src ./src

# Copy any other necessary files (like build.rs if you have one)
# COPY build.rs ./

# Build dependencies - this is separate from building the project to cache dependencies
RUN cargo fetch --locked

# Build the project
RUN cargo build --release --locked

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
COPY --from=builder /usr/src/corsa-reth/target/release/corsa-reth .

# Expose port 8545 for JSON-RPC
EXPOSE 8545

# Set the startup command
ENTRYPOINT ["corsa-reth"]

# Use CMD to provide default arguments to ENTRYPOINT
CMD ["--btc-network", "regtest", "--network-url", "http://127.0.0.1", "--btc-rpc-username", "user", "--btc-rpc-password", "password"]