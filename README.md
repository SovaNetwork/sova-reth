<div align="left">

  # sova-reth

  [![GitHub Release][gh-release]][gh-release]
  [![Docs docs][docs-badge]][docs-url]
  [![MIT License][mit-badge]][mit-url]
  [![Apache-2.0 License][apache-badge]][apache-url]
  [![CI Status][actions-badge]][actions-url]

  **The Bitcoin-powered EVM with native BTC interoperability**

  A sova-reth is a custom EVM node built upon the [Reth SDK](https://reth.rs/sdk). It extends the EVM to enable a new set of Bitcoin precompiles. The precompiles are used to send and receive Bitcoin on the Sova Network during EVM transaction execution.
</div>

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

## Validators

Validators are free to join the testnet and sync their own historical chain data from genesis. For more information on how to join the Testnet as an operator view our [Guide](https://docs.sova.io/node-operators/network-operation-manual).


## Precompiles

 Precompile Name | Address | Description |
|---|---|---|
| **Broadcast Transaction** | `0x0000000000000000000000000000000000000999` | Broadcasts Bitcoin transactions |
| **Decode Transaction** | `0x0000000000000000000000000000000000000998` | Decodes raw Bitcoin transactions |
| **Convert Address** | `0x0000000000000000000000000000000000000997` | EVM to Bitcoin address conversion |

For more information on how to use the precompiles see related [docs](https://docs.sova.io/technology/bitcoin-precompiles).

## Sentinel

The [sova-sentinel](https://github.com/SovaNetwork/sova-sentinel) is a necessary component to every sove-reth node. It is used in custom EVM hooks to enforce Bitcoin finality. Transactions on Sova that are associated with a Bitcoin transaction have their state confirmed by the sova-sentinel. If a transaction that was flagged by the chain is not confirmed on Bitcoin, the Sova state associated with the flagged Bitcoin tx will be reverted.

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