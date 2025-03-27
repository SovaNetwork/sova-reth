<h1 align="left">
    sova-reth
</h1>

[![GitHub Release][gh-release]][gh-release]
[![MIT License][mit-badge]][mit-url]
[![Apache-2.0 License][apache-badge]][apache-url]
[![CI Status][actions-badge]][actions-url]

<h3 align="left">
    Native Bitcoin interations, using Reth
</h3>

<p align="left">
  <a href="#overview">Overview</a> •
  <a href="./docs/README.md">Documentation</a> •
  <a href="https://github.com/SovaNetwork/running-sova">Run Dev Node</a> •
  <a href="https://docs.sova.io/documentation/network-info#sova-testnet">Use on Testnet</a>
</p>

<h1 align="center">
    <img src="./assets/sova-reth-prod.png" alt="sova-reth" width="100%" align="center">
</h1>

## Overview

A Sova node is an extension of the EVM execution client [Reth](https://github.com/paradigmxyz/reth). This extension of reth enables a new subset of Bitcoin precompiles. The precompiles are used to directly interface with a Bitcoin node during EVM transaction execution.

## Building and Running

A Makefile is used as a command runner to execute run and build commands.

```bash
# view all make commands
make help

# build the sova-reth binary
make build

# run in devnet mode using Bitcoin regtest
make run-sova-regtest
```

## Testing

For testing sova-reth in a devnet environment, it is recommended to use [running-sova](https://github.com/SovaNetwork/running-sova). This will orchestrate the deployment of all the auxiliary services need for local develeopment.

## Precompiles

The new precompile is found at address 0x999 and accepts a bytes payload of data and a 4 bytes method identifier. The method identifier specifies the bitcoin rpc call that should be called with the payload data.

| Precompile Name | Address | Method Identifier (bytes) | Gas Cost | Gas Limit | Description |
|-----------------|-----|---------------------------|----------|-----------|-------------|
| sendrawtransaction | 0x999 | 0x00000001 | 21,000 | N/A | Broadcast a raw Bitcoin transaction. |
| decoderawtransaction | 0x999 | 0x00000002 | 4,000 + 3 * input.len() | 150,000 | Decode a raw Bitcoin transaction. |
| verifysignature | 0x999 | 0x00000003 | 6,000 + 3 * input.len() | 100,000 | Verifies the unlocking scripts in a signed transaction are able to spend the specified inputs. |
| convertaddress | 0x999 |  0x00000004 | 3,000 | N/A | Converts a Sova address to the corresponding BTC address using the network master key. |
| createandsignrawtransaction | 0x999 |  0x00000005 | 25,000 | N/A | Using the Sova network keys, create and sign a BTC transaction for a specific amount. The caller of this precompile specifies the recipient BTC address and amount to send in sats. |

The next section provides examples for interacting with each precompile and the data that needs to be provided.

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

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in these crates by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[apache-badge]: https://img.shields.io/badge/license-Apache--2.0-blue.svg
[mit-url]: LICENSE-MIT
[apache-url]: LICENSE-APACHE
[actions-badge]: https://github.com/ithacaxyz/odyssey/workflows/unit/badge.svg
[actions-url]: https://github.com/SovaNetwork/sova-reth/actions?query=workflow%3ACI+branch%3Amain
[gh-release]: https://img.shields.io/github/v/release/SovaNetwork/sova-reth