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

`sova-reth-v2` is a custom execution client for the [Sova Network](https://sova.io) built on top of [Reth](https://github.com/paradigmxyz/reth) (an Ethereum execution layer). It extends Reth with:

* **Bitcoin-aware EVM precompiles** for interacting with a Bitcoin full node.
* **Slot-lock enforcement** for Bitcoin finality inside Ethereum transaction execution.
* **Custom execution pipeline** for transaction introspection and state reversion.
* **Integration with the Sentinel service** to coordinate Bitcoin transaction status with L2 state changes.

This design lets Sova smart contracts directly consume Bitcoin transactions as part of their EVM execution flow while maintaining **trust-minimized finality** guarantees.

## Why This Architecture Exists...

Ethereum execution engines do not natively understand Bitcoin transactions or Bitcoin finality rules. This creates a core problem for a Bitcoin-backed L2 like Sova:

**Unsafe state changes before Bitcoin finality**
Without special handling, an L2 could modify state in response to an unconfirmed Bitcoin transaction. If that Bitcoin transaction later fails or is replaced, the L2 state would become invalid.

`sova-reth` solves this by introducing a **custom NodeBuilder configuration** that integrates Bitcoin-aware logic at the right points in the block build and execution lifecycle.

## High-Level Architecture

### 1. **NodeBuilder Composition**

We define a `SovaNode` type that plugs into Reth’s `NodeBuilder`:

* **Pool** → `OpPoolBuilder` (Optimism-style transaction pool)
* **Payload** → `SovaPayloadBuilder` (adds post-build slot lock updates)
* **Network** → `OpNetworkBuilder` (p2p stack)
* **Executor** → `SovaExecutorBuilder` (custom EVM execution)
* **Consensus** → `OpConsensusBuilder` (L2 sequencing/validation)

This gives full control over how transactions are executed and how blocks are assembled.

---

### 2. **Sova EVM Config**

`SovaEvmConfig` extends `OpEvmConfig` to:

* Register **Bitcoin precompiles**:

  | Name                  | Address | Purpose                             |
  | --------------------- | ------- | ----------------------------------- |
  | Broadcast Transaction | `0x999` | Send raw BTC TX to Bitcoin Core     |
  | Decode Transaction    | `0x998` | Parse raw BTC TX data               |
  | Convert Address       | `0x997` | Derive BTC address from EVM address |
  | Vault Spend           | `0x996` | Spend from network vault            |

* Embed a shared `SovaInspector` for tracking storage writes and associating them with Bitcoin TXs.

---

### 3. **Two-Phase Executor**

We wrap the block executor with our own **two-phase execution**:

1. **Simulation Phase**
   Run all transactions in an ephemeral state to:

   * Detect any slots that should be reverted (`Reverted` status from Sentinel).
   * Build a `slot_revert_cache` for state restoration.

2. **Apply Reverts**
   Modify the real state to restore previous values for reverted slots.

3. **Real Execution Phase**
   Execute the block normally but:

   * On each Bitcoin broadcast precompile, call Sentinel’s `batch_get_locked_status`.
   * If any slot is `Locked`, revert the transaction mid-execution.

---

### 4. **Post-Build Locking**

At the end of block building and block validation `sova-reth` calls the sentinel service to update the database with any new slot lock information based on the state changes in the processed block.

```
sentinel.batch_lock_slots(slots, eth_block_num, btc_block_num, txid)
```

This marks slots as locked until the associated Bitcoin transaction reaches finality.

---

### 5. **Sentinel Integration**

The **Sentinel** is an external gRPC service each node talks to:

* Tracks Bitcoin mempool + chain state.
* Decides whether a slot should be `Unlocked`, `Locked`, or `Reverted`.
* Coordinates finality rules (e.g., 6-block confirmation for final, revert after 21 blocks).

Without Sentinel, an L2 node can’t safely reconcile its EVM state with Bitcoin’s consensus reality.

---

## Problems This Solves

* **State safety**: Prevents invalid EVM state when dependent Bitcoin TXs fail.
* **Cross-chain atomicity**: Ensures an EVM state change tied to BTC only finalizes if BTC does.
* **Upgrade path**: Uses Reth’s official NodeBuilder hooks to integrate safely.
* **Operator trust**: Each node enforces slot-lock rules locally; no reliance on a single sequencer to behave.

## Development & Running

### Build

```bash
make build
```

### Devnet (Bitcoin regtest)

```bash
# 'clean' is used to remove any old chain state
make run-sova-regtest clean=clean
```

This uses [running-sova](https://github.com/SovaNetwork/running-sova) to orchestrate all needed services.

### Validator Mode

See the [Operator Guide](https://docs.sova.io/node-operators/running-sova).

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