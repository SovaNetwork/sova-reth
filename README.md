# Corsa Reth: An extension of reth with Bitcoin precompiles

This configuration of reth's execution client adds new Bitcoin-focused precompiles to the existing list of precompiles in the Cancun hardfork.

The new precompile is found at address 0x999 and accepts a bytes payload of data and a 4 bytes method identifier. The method identifier specifies the bitcoin rpc call that should be called with the payload data.

| Precompile Name | Address | Method Identifier (bytes) | Gas Cost | Gas Limit | Description |
|-----------------|-----|---------------------------|----------|-----------|-------------|
| sendrawtransaction | 0x999 | 0x00000001 | 6,000 + 3 * input.len() | 450,000 | Broadcast a raw Bitcoin transaction. |
| decoderawtransaction | 0x999 | 0x00000002 | 2,000 + 3 * input.len() | 150,000 | Decode a raw Bitcoin transaction. |
| verifysignature | 0x999 | 0x00000003 | 4,000 + 3 * input.len() | 300,000 | Verifies the unlocking scripts in a signed transaction are able to spend the specified inputs. |
| convertaddress | 0x999 |  0x00000004 | 3,000 | N/A | Converts a Corsa address to the corresponding BTC address using the network master key. |
| createandsignrawtransaction | 0x999 |  0x00000005 | 25,000 | N/A | Using the Corsa network keys, create and sign a BTC transaction for a specific amount. The caller of this precompile specifies the recipient BTC address and amount to send in sats. |

## Testing

For testing the corsa-reth node, a docker compose file is provided. These provides you with the corsa-reth service as well as a regtest bitcoin service. The corsa-reth service exposes port :8545 for making rpc calls to the node and the bitcoin service exposes port :18443 for making rpc calls to the regtest service.

Corsa-reth provides a `just` command runner to easily start the node using `just run-chain`. To view the possible flags that can be passed with this command use `just -l` and `just help` to view all commands and flags.

Alternatively, the bitcoin node and the corsa-reth node can run as standalone processes.  

One way to interact with the precompile is to use [cast](https://book.getfoundry.sh/reference/cast/transaction-commands).

Examples for the specific bitcoin rpc call. Each example shows which data prefix to use to each specific bitcoin rpc call.

### sendrawtransaction
> Note: `--data` is prefixed with 0x00000000. After the prefix is the raw signed btc transaction.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x0000000102000000000101b161898f2ef6bd36e1cee4b9d68c5a1937a5001306e81a0fc30e99b44e8f835a00000000000000000001c0aff629010000001600148267b14c9fc90545c5828cbb9d26e12a9ecb8c160247304402205709263844829d625759b202ecf8d85fc6a2c07f958555d5b32c98e9c8b33c8a02200a6132106329e8dcc9c54bc7444075a90f505909bffb63b65f93257cbe23c9040121025912be1b355b604d151f36348c91976c4cda0c3c9c7fcb4469cdf0213fa216e900000000 \
--rpc-url http://localhost:8545
```

### decoderawsignature
> Note: `--data` is prefixed with 0x00000002. After the prefix is the raw signed btc transaction to decode.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x0000000202000000000101b161898f2ef6bd36e1cee4b9d68c5a1937a5001306e81a0fc30e99b44e8f835a00000000000000000001c0aff629010000001600148267b14c9fc90545c5828cbb9d26e12a9ecb8c160247304402205709263844829d625759b202ecf8d85fc6a2c07f958555d5b32c98e9c8b33c8a02200a6132106329e8dcc9c54bc7444075a90f505909bffb63b65f93257cbe23c9040121025912be1b355b604d151f36348c91976c4cda0c3c9c7fcb4469cdf0213fa216e900000000 \
--rpc-url http://localhost:8545
```

### verifysignature
> Note: `--data` is prefixed with 0x00000003. After the prefix is the raw signed btc transaction to verify.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x0000000302000000000101b161898f2ef6bd36e1cee4b9d68c5a1937a5001306e81a0fc30e99b44e8f835a00000000000000000001c0aff629010000001600148267b14c9fc90545c5828cbb9d26e12a9ecb8c160247304402205709263844829d625759b202ecf8d85fc6a2c07f958555d5b32c98e9c8b33c8a02200a6132106329e8dcc9c54bc7444075a90f505909bffb63b65f93257cbe23c9040121025912be1b355b604d151f36348c91976c4cda0c3c9c7fcb4469cdf0213fa216e900000000 \
--rpc-url http://localhost:8545
```

### convertaddress
> Note: `--data` is prefixed with 0x00000004. After the prefix is the corsa address to be converted.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x000000042CB44b8970d0e62296015c1fA12E72671448Fd86 \
--rpc-url http://localhost:8545
```

### createandsignrawtransaction
> Note: `--data` is prefixed with 0x00000005. After the prefix is the corsa address of signer, the bitcoin address of the receiver, and the amount to send.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x00000005 \
--rpc-url http://localhost:8545
```

## TODO
- [ ] Reconfigure the main.rs file to work in a multinode environment with a consensus client.
- [ ] The current `main.rs` file sets the NodeBuilder handle config to 'dev mode'. This means that blocks are automatically mined when a transaction is sent to the node. This should be removed when the chain is used in a multi node env.
- [ ] Does the reth-node need a Bitcoin client attached?