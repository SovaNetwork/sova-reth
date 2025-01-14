# build rust binary
alias b := build

build:
    cargo build --release

# list all CLI flags
help:
    ./target/release/sova-reth -h

# run sova chain
run-chain btc_network="regtest" network_url="http://127.0.0.1" btc_rpc_username="user" btc_rpc_password="password" network_signing_url="http://127.0.0.1:5555" network_utxo_url="http://127.0.0.1:5557" btc_tx_queue_url="http://127.0.0.1:5558":
    cargo run --release -- --btc-network {{btc_network}} --network-url {{network_url}} --btc-rpc-username {{btc_rpc_username}} --btc-rpc-password {{btc_rpc_password}} --network-signing-url {{network_signing_url}} --network-utxo-url {{network_utxo_url}} --btc-tx-queue-url {{btc_tx_queue_url}}

# run sova chain on bitcoin regtest network
run-chain-regtest:
    cargo run --release -- --btc-network "regtest" --network-url "http://127.0.0.1" --btc-rpc-username "user" --btc-rpc-password "password" --network-signing-url "http://127.0.0.1:5555" --network-utxo-url "http://127.0.0.1:5557" --btc-tx-queue-url "http://127.0.0.1:5558"