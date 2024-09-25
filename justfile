# where to store blockchain data
corsa_datadir := "./data/corsa-reth/120893"

# build rust binary
build:
    cargo build --release
alias b := build

# list all CLI flags
help:
    ./target/release/corsa-reth -h

# run corsa chain and specify bitcoin network params
run-chain btc_network="regtest" network_url="http://127.0.0.1" btc_rpc_username="user" btc_rpc_password="password":
    ./target/release/corsa-reth node --chain genesis.json --datadir {{ corsa_datadir }} --bitcoin.network {{btc_network}} --bitcoin.url {{network_url}} --bitcoin.rpc-username {{btc_rpc_username}} --bitcoin.rpc-password {{btc_rpc_password}}

# run corsa chain with a local bitcoin regtest network
run-chain-dev:
    ./target/release/corsa-reth node --chain genesis.json --datadir {{ corsa_datadir }} --http --bitcoin.network "regtest" --bitcoin.url "http://127.0.0.1" --bitcoin.rpc-username "user" --bitcoin.rpc-password "password"