use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, U256};
use reth_tasks::TaskExecutor;
use reth_tracing::tracing::{debug, error, info, warn};
// Removed ProviderError import since inspector implementation was removed
// Removed inspector-related imports since we're removing inspector implementation
use serde_json::json;
use uuid::Uuid;

use crate::inspector::{error::SlotProviderError, provider::StorageSlotProvider};
use sova_sentinel_proto::proto::get_slot_status_response::Status;

/// Represents a storage change recorded during SSTORE operations
#[derive(Debug, Clone)]
pub struct StorageChange {
    /// The storage slot key
    pub key: U256,
    /// The new value stored
    pub value: U256,
    /// The previous value if it existed
    pub had_value: Option<U256>,
}

/// Represents accessed storage for a contract
pub type AccessedStorage = HashMap<Address, HashMap<U256, StorageChange>>;

/// Result of a Bitcoin broadcast transaction
#[derive(Debug, Clone)]
pub struct BroadcastResult {
    /// Transaction ID from Bitcoin broadcast
    pub txid: Option<Vec<u8>>,
    /// Bitcoin block height when broadcast occurred
    pub block: Option<u64>,
}

/// Manages slot locking enforcement for Bitcoin precompile operations
/// This extracts the core business logic from the inspector pattern
#[derive(Debug)]
pub struct SlotLockManager {
    /// Storage slot provider for communicating with sentinel
    storage_slot_provider: Arc<StorageSlotProvider>,
    /// Cached accessed storage for the current block
    accessed_storage: AccessedStorage,
    /// Results from Bitcoin broadcast transactions
    broadcast_results: Vec<BroadcastResult>,
    /// Current operation ID for tracking
    operation_id: Option<Uuid>,
}

impl SlotLockManager {
    pub fn new(
        sentinel_url: String,
        task_executor: TaskExecutor,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let storage_slot_provider = Arc::new(StorageSlotProvider::new(sentinel_url, task_executor)?);

        Ok(Self {
            storage_slot_provider,
            accessed_storage: HashMap::new(),
            broadcast_results: Vec::new(),
            operation_id: None,
        })
    }

    /// Clear all cached data for a new block
    pub fn clear_for_new_block(&mut self) {
        self.accessed_storage.clear();
        self.broadcast_results.clear();
        self.operation_id = None;
    }

    /// Record storage access for slot lock enforcement
    pub fn record_storage_access(&mut self, address: Address, slot: U256, change: StorageChange) {
        self.accessed_storage
            .entry(address)
            .or_default()
            .insert(slot, change);
    }

    /// Check if any accessed storage slots are locked
    /// This is the CORE BUSINESS LOGIC that must be preserved
    pub fn validate_no_locked_slots(&mut self, block_number: u64) -> Result<(), String> {
        // Generate operation ID if needed
        if self.operation_id.is_none() {
            self.operation_id = Some(Uuid::new_v4());
        }

        // Only check if we have accessed storage
        if self.accessed_storage.is_empty() {
            return Ok(());
        }

        self.log_slot_decision(
            "batch",
            &[],
            "checking",
            "batch_lock_check_started", 
            block_number,
            Some(json!({
                "slots_count": self.accessed_storage.len(),
                "operation_id": self.operation_id
            })),
        );

        // Check each accessed storage slot
        for (contract_address, slots) in &self.accessed_storage {
            for slot_key in slots.keys() {
                // Convert slot key to bytes for sentinel
                let slot_bytes = slot_key.to_be_bytes_vec();

                match self.storage_slot_provider.get_slot_status(
                    contract_address.to_string(),
                    slot_bytes.clone(),
                    block_number,
                ) {
                    Ok(response) => {
                        let status = match Status::try_from(response.status) {
                            Ok(status) => status,
                            Err(_) => {
                                self.log_slot_decision(
                                    &contract_address.to_string(),
                                    &slot_bytes,
                                    "invalid",
                                    "validation_failed",
                                    block_number,
                                    Some(json!({ "invalid_status_value": response.status })),
                                );
                                return Err(format!("Invalid status value {} from sentinel", response.status));
                            }
                        };

                        match status {
                            Status::Unknown => {
                                self.log_slot_decision(
                                    &contract_address.to_string(),
                                    &slot_bytes,
                                    "unknown",
                                    "validation_failed",
                                    block_number,
                                    Some(json!({ "reason": "sentinel_connectivity_issue" })),
                                );
                                return Err("Sentinel returned unknown status".to_string());
                            }
                            Status::Locked => {
                                self.log_slot_decision(
                                    &contract_address.to_string(),
                                    &slot_bytes,
                                    "locked",
                                    "validation_failed",
                                    block_number,
                                    Some(json!({ "reason": "slot_locked" })),
                                );
                                return Err(format!(
                                    "Storage slot is locked: {}:{}",
                                    contract_address,
                                    hex::encode(&slot_bytes)
                                ));
                            }
                            Status::Unlocked => {
                                self.log_slot_decision(
                                    &contract_address.to_string(),
                                    &slot_bytes,
                                    "unlocked",
                                    "validation_passed",
                                    block_number,
                                    None,
                                );
                            }
                            Status::Reverted => {
                                self.log_slot_decision(
                                    &contract_address.to_string(),
                                    &slot_bytes,
                                    "reverted",
                                    "slot_reverted_to_previous_value",
                                    block_number,
                                    Some(json!({
                                        "revert_value": hex::encode(&response.revert_value),
                                        "current_value": hex::encode(&response.current_value)
                                    })),
                                );
                                // Handle revert status by updating the storage value
                                // This would require state modification capability
                            }
                        }
                    }
                    Err(err) => {
                        self.log_slot_decision(
                            "batch",
                            &[],
                            "error",
                            "validation_failed",
                            block_number,
                            Some(json!({
                                "error_type": format!("{:?}", std::mem::discriminant(&err)),
                                "error_message": err.to_string()
                            })),
                        );
                        
                        match &err {
                            SlotProviderError::BitcoinNodeUnavailable(msg) => {
                                warn!("Bitcoin node unavailable: {}", msg);
                                return Err("Bitcoin node unavailable - cannot verify slot locks".to_string());
                            }
                            SlotProviderError::ServiceUnavailable(msg) => {
                                warn!("Sentinel service unavailable: {}", msg);
                                return Err("Sentinel service unavailable - cannot verify slot locks".to_string());
                            }
                            SlotProviderError::Timeout(msg) => {
                                warn!("Timeout communicating with sentinel: {}", msg);
                                return Err("Timeout verifying slot locks - transaction reverted for safety".to_string());
                            }
                            _ => {
                                warn!("Failed to get lock status from sentinel: {}", err);
                                return Err("Failed to verify slot locks - transaction reverted for safety".to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Add a broadcast result for later slot locking
    pub fn add_broadcast_result(&mut self, result: BroadcastResult) {
        self.broadcast_results.push(result);
    }

    /// Update sentinel locks after block execution (called from payload builder)
    /// This is the main method for enforcing slot locks after block execution
    pub fn update_sentinel_locks(&mut self, locked_block_number: u64) -> Result<(), String> {
        // Lock all slots for successful Bitcoin broadcast transactions
        self.lock_broadcast_slots(locked_block_number)
            .map_err(|err| format!("Failed to lock broadcast slots: {err}"))
    }

    /// Lock all slots for successful Bitcoin broadcast transactions
    /// This is called after successful block execution
    pub fn lock_broadcast_slots(&mut self, locked_block_number: u64) -> Result<(), SlotProviderError> {
        for result in &self.broadcast_results {
            if let (Some(btc_txid), Some(btc_block)) = (result.txid.as_ref(), result.block) {
                // Convert accessed storage to the format expected by batch_lock_slots
                match self.storage_slot_provider.batch_lock_slots(
                    self.accessed_storage.clone(),
                    locked_block_number,
                    btc_block,
                    btc_txid.clone(),
                ) {
                    Ok(()) => {
                        debug!("Successfully locked slots for Bitcoin transaction: {}", hex::encode(btc_txid));
                    }
                    Err(err) => {
                        warn!("Failed to lock storage slots: {}", err);
                        return Err(err);
                    }
                }
            } else {
                warn!(
                    "Incomplete broadcast result: txid={:?}, block={:?}",
                    result.txid.as_ref().map(hex::encode),
                    result.block
                );
            }
        }

        // Clear data after successful locking
        self.clear_for_new_block();
        Ok(())
    }

    fn log_slot_decision(
        &self,
        slot_address: &str,
        slot_index: &[u8],
        status: &str,
        decision: &str,
        block_number: u64,
        additional_context: Option<serde_json::Value>,
    ) {
        let log_entry = json!({
            "operation_id": self.operation_id,
            "event_type": "slot_decision",
            "contract_address": slot_address,
            "slot_index": hex::encode(slot_index),
            "slot_status": status,
            "decision": decision,
            "block_number": block_number,
            "context": additional_context
        });

        // Choose log level based on status and decision
        match (status, decision) {
            // Critical errors that prevent operation
            ("error", _) | (_, "validation_failed") => {
                error!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Invalid data or status
            ("invalid", _) | ("unknown", _) => {
                error!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Transaction blocking events
            ("locked", _) => {
                warn!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // State reversions
            ("reverted", _) | (_, "slot_reverted_to_previous_value") => {
                debug!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Routine successful operations
            ("unlocked", "validation_passed") | ("checking", "batch_lock_check_started") => {
                debug!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Default to info for any other combinations
            _ => {
                info!(target: "sova_slot_tracker", "{}", log_entry);
            }
        }
    }
}

// Inspector implementation removed - slot locking will be implemented through a cleaner approach
// All slot lock validation logic remains in validate_no_locked_slots() and related methods