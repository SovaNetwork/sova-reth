# build rust binary
alias b := build

build:
    cargo build --release

# list all CLI flags
help:
    ./target/release/corsa-reth -h

# run corsa chain
run-chain btc_network="regtest" network_url="http://127.0.0.1" btc_rpc_username="user" btc_rpc_password="password":
    ./target/release/corsa-reth --btc-network {{btc_network}} --network-url {{network_url}} --btc-rpc-username {{btc_rpc_username}} --btc-rpc-password {{btc_rpc_password}}

# run corsa chain on bitcoin regtest network
run-chain-regtest:
    ./target/release/corsa-reth --btc-network "regtest" --network-url "http://127.0.0.1" --btc-rpc-username "user" --btc-rpc-password "password"