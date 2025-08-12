use alloy_primitives::{Address, Bytes, StorageKey, StorageValue, B256, U256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents the context of a block being executed
#[derive(Debug, Clone)]
pub struct BlockContext {
    pub number: u64,
    pub btc_block_height: u64,
    pub btc_block_hash: B256,
}

/// Represents the context of a transaction being executed
#[derive(Debug, Clone)]
pub struct TransactionContext {
    pub operation_id: Uuid,
    pub caller: Address,
    pub target: Address,
    pub checkpoint: Option<u64>, // Journal checkpoint for reverting
}

/// Storage access during transaction execution
#[derive(Debug, Clone)]
pub struct StorageAccess {
    pub address: Address,
    pub slot: StorageKey,
    pub previous_value: StorageValue,
    pub new_value: StorageValue,
}

/// Represents a storage change recorded during SSTORE operations
#[derive(Debug, Clone)]
pub struct SlotChange {
    /// The storage slot key
    pub key: U256,
    /// The new value stored
    pub value: U256,
    /// The previous value if it existed
    pub had_value: Option<U256>,
}

/// Represents all available Bitcoin precompile methods
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum BitcoinPrecompileMethod {
    /// Broadcasts a Bitcoin transaction
    BroadcastTransaction,
    /// Decodes a raw Bitcoin transaction
    DecodeTransaction,
    /// Converts EVM address to Bitcoin address
    ConvertAddress,
    /// Creates, signs, and broadcasts a Bitcoin transaction from a specified signer
    VaultSpend,
}

/// Precompile call information
#[derive(Debug, Clone)]
pub struct PrecompileCall {
    pub method: BitcoinPrecompileMethod,
    pub caller: Address,
    pub target: Address,
    pub input: Bytes,
    pub gas_limit: u64,
}

/// Slot lock request for checking locks
#[derive(Debug, Clone)]
pub struct SlotLockRequest {
    pub transaction_context: TransactionContext,
    pub block_context: BlockContext,
    pub precompile_call: Option<PrecompileCall>,
    pub storage_accesses: Vec<StorageAccess>,
}

/// Decision made about a slot lock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlotLockDecision {
    Allow,
    Revert { reason: String },
    RevertWithSlotData { slots: Vec<SlotRevert> },
}

/// Slot lock response
#[derive(Debug, Clone)]
pub struct SlotLockResponse {
    pub decision: SlotLockDecision,
    pub broadcast_result: Option<crate::cache::BroadcastResult>,
}

/// Slot revert information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotRevert {
    pub address: Address,
    pub slot: U256,
    pub revert_to: U256,
    pub current_value: U256,
}
