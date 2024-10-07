# build rust binary
alias b := build

build:
    cargo build --release

# list all CLI flags
help:
    ./target/release/corsa-reth -h

# run corsa chain
run-chain btc_network="regtest" network_url="http://127.0.0.1" btc_rpc_username="user" btc_rpc_password="password" enclave_url="http://127.0.0.1:5555":
    cargo run --release -- --btc-network {{btc_network}} --network-url {{network_url}} --btc-rpc-username {{btc_rpc_username}} --btc-rpc-password {{btc_rpc_password}} --enclave-url {{enclave_url}}

# run corsa chain on bitcoin regtest network
run-chain-regtest:
    cargo run --release -- --btc-network "regtest" --network-url "http://127.0.0.1" --btc-rpc-username "user" --btc-rpc-password "password" --enclave-url "http://127.0.0.1:5555"