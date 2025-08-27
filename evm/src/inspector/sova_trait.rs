use std::fmt::Debug;

use alloy_primitives::{Address, B256, U256};

/// Inspector trait focused on essential hooks for Sova's use cases
pub trait Inspector: Send + Debug {
    /// Called at the start of a new block
    fn on_block_start(&mut self) {}

    /// Called at the end of a block
    fn on_block_end(&mut self) {}

    /// Called at the start of a transaction
    fn on_tx_start(&mut self, _tx_hash: B256) {}

    /// Called at the end of a transaction
    fn on_tx_end(&mut self, _tx_hash: B256) {}

    /// Called when storage is written (SSTORE operations)
    /// Used for revert-cache and lock detection
    fn on_sstore(&mut self, _addr: Address, _slot: U256, _prev: U256, _new: U256) {}

    /// Called when a broadcast precompile operation completes
    /// Used to finalize broadcast grouping and lock data
    fn on_broadcast_end(&mut self, _txid: [u8; 32], _btc_block: u64) {}

    /// 2-pass execution integration: called after pass#1 to let the inspector
    /// expose the list of storage reverts to apply before pass#2.
    fn take_slot_reverts(&mut self) -> Vec<(Address, SlotRevert)> {
        Vec::new()
    }

    /// Enable downcasting for specific inspector implementations
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// A compact DTO for storage reverts captured during pass #1.
#[derive(Clone, Debug)]
pub struct SlotRevert {
    pub slot: U256,
    pub previous_value: U256,
}

/// No-op implementation of Inspector trait
#[derive(Debug)]
pub struct NoOpInspector;

impl Inspector for NoOpInspector {
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
