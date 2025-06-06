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

# run in devnet mode using Bitcoin regtest, use fresh data directory
make run-sova-regtest clean=clean
```

## Running a Node

### Devnet/ Testnet

For testing sova-reth in a devnet environment, it is recommended to use [running-sova](https://github.com/SovaNetwork/running-sova). This will orchestrate the deployment of all the auxiliary services need for local development.

## Precompiles

The Bitcoin precompiles are found at address 0x999 and accept a bytes payload along with a 4 bytes method identifier. The method identifier specifies the bitcoin rpc call that should be called with the payload data.

For more information on how to use the precompiles see the [docs](https://docs.sova.io/developers/bitcoin-precompiles).

## Bitcoin Finality

The Sova EVM engine is preloaded with an engine 'inspector'. REVM inspector [docs](https://docs.rs/revm-inspector/6.0.0/revm_inspector/trait.Inspector.html). For Sova's use case, the job of the engine inspector is to check the finality of Bitcoin transactions which are associated with specific smart contract slot changes. The inspector uses an speciaized database to track all of the slots that are associated with Bitcoin transactions waiting to be confirmed. We call this database the [sentinel](https://github.com/SovaNetwork/sova-sentinel). Accompanying these services is a full Bitcoin node which the sentinel does read operations from to determine if certain slots can be finalized or not. If a slot is finalized, EVM engine execution proceeds without revert, otherwise if the tx cannot be confirmed on Bitcoin before the configured timeout period, the slot is reverted to the previous value on Sova reflecting the Bitcoin state.

The inspector uses a revert slot storage cache to easily apply slot reverts during block execution and block building. We call this the simulation run and happen prior to the actual block execution run where db state is updated and finalized. In the simulation run all block txs are run through the Sova EVM and the inspector stores slot reverts in its cache. Them after all txs are executed, the revert cache is applied the the nodes db. That happens prior to 'actual' block execution so that Sova state always follows Bitcoin state.

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