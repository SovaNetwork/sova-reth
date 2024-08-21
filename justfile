###################################
# Build and boostrapping commands #
###################################

# build rust binary
build:
    cargo build --release

# run corsa chain
run-chain:
    ./target/release/corsa-reth