# where to store blockchain data
corsa_datadir := "./data/corsa-reth/120893"

# build rust binary
build:
    cargo build --release
alias b := build

# list all corsa-reth flags
help:
    ./target/release/corsa-reth -h

# list all corsa-reth node flags
node-help:
    ./target/release/corsa-reth node -h

# create jwt
create-jwt:
    openssl rand -hex 32 > jwt.hex

# run corsa chain and specify bitcoin network params
run-chain sequencer_http="http://127.0.0.1:9545" btc_network="regtest" network_url="http://127.0.0.1" btc_rpc_username="user" btc_rpc_password="password":
    ./target/release/corsa-reth node \
    --chain genesis.json \
    --datadir {{ corsa_datadir }} \
    --rollup.sequencer-http {{sequencer_http}} \
    --bitcoin.network {{btc_network}} \
    --bitcoin.url {{network_url}} \
    --bitcoin.rpc-username {{btc_rpc_username}} \
    --bitcoin.rpc-password {{btc_rpc_password}} \
    --authrpc.jwtsecret "jwt.hex" \
    --http.addr "127.0.0.1" \
    --authrpc.port 8551 \
    --disable-discovery \
    --http

# run corsa chain with a local bitcoin regtest network
run-chain-dev:
    ./target/release/corsa-reth node \
    --chain genesis.json \
    --datadir {{ corsa_datadir }} \
    --rollup.sequencer-http "http://127.0.0.1:9545" \
    --bitcoin.network "regtest" \
    --bitcoin.url "http://127.0.0.1" \
    --bitcoin.rpc-username "user" \
    --bitcoin.rpc-password "password" \
    --authrpc.jwtsecret "jwt.hex" \
    --http.addr "127.0.0.1" \
    --authrpc.port 8551 \
    --disable-discovery \
    --http