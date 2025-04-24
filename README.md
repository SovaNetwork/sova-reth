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
    <img src="./assets/sova-reth-prod.png" alt="sova-reth" width="100%" align="center">
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

Operators can join the Testnet by staking Testnet Sova and syncing the historical chain data. For more information on how to join the Testnet as an operator view our [Operator Guide]() in the docs. This guide will run you through starting a VM, installing the EigenLayer CLI, registering as an operator, and running the Sova validator.

### Devnet

For testing sova-reth in a devnet environment, it is recommended to use [running-sova](https://github.com/SovaNetwork/running-sova). This will orchestrate the deployment of all the auxiliary services need for local development.

## Precompiles

The Bitcoin precompiles are found at address 0x999 and accept a bytes payload along with a 4 bytes method identifier. The method identifier specifies the bitcoin rpc call that should be called with the payload data.

For more information on how to use the precompiles see this [section](https://docs.sova.io/developers/bitcoin-precompiles) in the docs.

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