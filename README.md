<h1 align="left">
    sova-reth
</h1>

[![GitHub Release][gh-release]][gh-release]
[![Docs docs][docs-badge]][docs-url]
[![MIT License][mit-badge]][mit-url]
[![Apache-2.0 License][apache-badge]][apache-url]
[![CI Status][actions-badge]][actions-url]

<h3 align="left">
    Bitcoin's Programmable Execution Environment
</h3>

<p align="left">
  <a href="#overview">Overview</a> •
  <a href="./docs/README.md">Documentation</a> •
  <a href="#running-a-validator">Running a Validator</a> •
  <a href="https://docs.sova.io/documentation/network-info#sova-testnet">Sova Testnet</a>
</p>

<h1 align="center">
    <img src="./assets/sova-reth-prod-etch.png" alt="sova-reth" width="100%" align="center">
</h1>

## Overview

A Sova node is an extension of the EVM execution client [Reth](https://github.com/paradigmxyz/reth). This extension of reth enables a new subset of Bitcoin precompiles. The precompiles are used to directly interface with a Bitcoin node during EVM transaction execution.

## Building and Running

A Makefile is used as a command runner to execute repository commands.

```bash
# view all make commands
make help

# build the sova-reth binary
make build

# run in devnet mode using Bitcoin regtest
make run-sova-regtest
```

## Running a Validator

### For Operators (WIP)

Operators are free to join the testnet and sync their own historical chain data from genesis. For more information on how to join the Testnet as an operator view our [Operator Guide](https://docs.sova.io/node-operators/running-sova) in the docs.

### Devnet

For testing sova-reth in a devnet environment, it is recommended to use [running-sova](https://github.com/SovaNetwork/running-sova). This will orchestrate the deployment of all the auxiliary services need for local development.

## Precompiles

The Bitcoin precompiles are found at address 0x999, 0x998, 0x997, 0x996.

 Precompile Name | Address | Description |
|---|---|---|
| **Broadcast Transaction** | `0x999` | Broadcasts Bitcoin transactions |
| **Decode Transaction** | `0x998` | Decodes raw Bitcoin transactions |
| **Convert Address** | `0x997` | EVM to Bitcoin address conversion |
| **Vault Spend** | `0x996` | Network vault spending |

For more information on how to use the precompiles see related [docs](https://docs.sova.io/developers/bitcoin-precompiles).

## Sentinel

The sentinel is a custom add-on component to every sove-reth node. It is used by the Sova EVM to enforce Bitcoin finality. Transactions on Sova that have associated Bitcoin transactions are considered final after 6 Bitcoin block confirmations. If a transaction that was flagged by the chain is not confirmed on Bitcoin, the Sova state associated with the flagged Bitcoins tx will be reverted after 21 blocks.

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
[docs-badge]: https://img.shields.io/badge/Docs-854a15?style=flat&labelColor=1C2C2E&color=BEC5C9&logo=mdBook&logoColor=BEC5C9
[docs-url]: https://docs.sova.io/