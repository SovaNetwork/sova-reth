# sova-reth

**Native Bitcoin interations, using Reth**

![](./assets/sova-reth-prod.png)

[Developer Docs](./docs) | [Run Full Stack](https://github.com/SovaNetwork/running-corsa)

Sova uses a modified version of reth. Reth is an EVM based execution client. Sova adds new Bitcoin precompiles to reth.

## Precompiles

The new precompile is found at address 0x999 and accepts a bytes payload of data and a 4 bytes method identifier. The method identifier specifies the bitcoin rpc call that should be called with the payload data.

| Precompile Name | Address | Method Identifier (bytes) | Gas Cost | Gas Limit | Description |
|-----------------|-----|---------------------------|----------|-----------|-------------|
| sendrawtransaction | 0x999 | 0x00000001 | 6,000 + 3 * input.len() | 450,000 | Broadcast a raw Bitcoin transaction. |
| decoderawtransaction | 0x999 | 0x00000002 | 2,000 + 3 * input.len() | 150,000 | Decode a raw Bitcoin transaction. |
| verifysignature | 0x999 | 0x00000003 | 4,000 + 3 * input.len() | 300,000 | Verifies the unlocking scripts in a signed transaction are able to spend the specified inputs. |
| convertaddress | 0x999 |  0x00000004 | 3,000 | N/A | Converts a Sova address to the corresponding BTC address using the network master key. |
| createandsignrawtransaction | 0x999 |  0x00000005 | 25,000 | N/A | Using the Sova network keys, create and sign a BTC transaction for a specific amount. The caller of this precompile specifies the recipient BTC address and amount to send in sats. |

## Testing

For testing a sova-reth node, it is recommended to run the service along side the [running-corsa](https://github.com/SovaNetwork/running-corsa). That way you have all the auxilerary services running in docker and you can restart the node in this repo as needed without having to restart or run all the other network components separately. The sova-reth service exposes port :8545 for making rpc calls to the node.

Sova-reth provides a `just` command runner to easily start the node using `just run-chain`. To view the possible flags that can be passed with this command use `just -l` and `just help` to view all commands and flags.

One way to interact with the precompile is to use [cast](https://book.getfoundry.sh/reference/cast/transaction-commands).

Examples for the specific bitcoin rpc call. Each example shows which data prefix to use to each specific bitcoin rpc call.

### sendrawtransaction
> Note: `--data` is prefixed with 0x00000001. After the prefix is the raw signed btc transaction.
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
> Note: `--data` is prefixed with 0x00000004. After the prefix is the sova address to be converted.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x000000042CB44b8970d0e62296015c1fA12E72671448Fd86 \
--rpc-url http://localhost:8545
```

### createandsignrawtransaction
> Note: `--data` is prefixed with 0x00000005. After the prefix is the sova address of signer, the bitcoin address of the receiver, and the amount to send.
```sh
cast call 0x0000000000000000000000000000000000000999 \
--data 0x00000005 \
--rpc-url http://localhost:8545
```