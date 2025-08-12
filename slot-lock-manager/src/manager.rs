use crate::{
    cache::{BroadcastResult, StorageCache},
    client::SentinelClient,
    error::SlotLockError,
    types::*,
};
use alloy_primitives::{address, Address, U256};
use parking_lot::RwLock;
use serde_json::json;
use sova_sentinel_proto::proto::get_slot_status_response::Status;
use std::{str::FromStr, sync::Arc};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// Constants from sova-chainspec
pub const L1_BLOCK_CONTRACT_ADDRESS: Address =
    address!("0x2100000000000000000000000000000000000015");
pub const L1_BLOCK_CURRENT_BLOCK_HEIGHT_SLOT: U256 = U256::ZERO;
pub const SOVA_BTC_CONTRACT_ADDRESS: Address =
    address!("0x2100000000000000000000000000000000000020");

// Bitcoin precompile addresses
pub const BROADCAST_TRANSACTION_ADDRESS: Address =
    address!("0000000000000000000000000000000000000999");
pub const DECODE_TRANSACTION_ADDRESS: Address =
    address!("0000000000000000000000000000000000000998");
pub const CONVERT_ADDRESS_ADDRESS: Address = address!("0000000000000000000000000000000000000997");
pub const VAULT_SPEND_ADDRESS: Address = address!("0000000000000000000000000000000000000996");

pub const BITCOIN_PRECOMPILE_ADDRESSES: [Address; 4] = [
    BROADCAST_TRANSACTION_ADDRESS,
    DECODE_TRANSACTION_ADDRESS,
    CONVERT_ADDRESS_ADDRESS,
    VAULT_SPEND_ADDRESS,
];

/// Configuration for the SlotLockManager
#[derive(Debug)]
pub struct SlotLockManagerConfig {
    pub bitcoin_precompile_addresses: [Address; 4],
    pub excluded_addresses: Vec<Address>,
    pub sentinel_url: String,
}

impl Default for SlotLockManagerConfig {
    fn default() -> Self {
        Self {
            bitcoin_precompile_addresses: BITCOIN_PRECOMPILE_ADDRESSES,
            excluded_addresses: vec![],
            sentinel_url: "http://localhost:50051".to_string(),
        }
    }
}

impl SlotLockManagerConfig {
    pub fn builder() -> SlotLockManagerConfigBuilder {
        SlotLockManagerConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct SlotLockManagerConfigBuilder {
    bitcoin_precompile_addresses: Option<[Address; 4]>,
    excluded_addresses: Vec<Address>,
    sentinel_url: Option<String>,
}

impl SlotLockManagerConfigBuilder {
    pub fn bitcoin_precompile_addresses(mut self, addresses: [Address; 4]) -> Self {
        self.bitcoin_precompile_addresses = Some(addresses);
        self
    }

    pub fn excluded_address(mut self, address: Address) -> Self {
        self.excluded_addresses.push(address);
        self
    }

    pub fn excluded_addresses(mut self, addresses: Vec<Address>) -> Self {
        self.excluded_addresses.extend(addresses);
        self
    }

    pub fn sentinel_url(mut self, url: impl Into<String>) -> Self {
        self.sentinel_url = Some(url.into());
        self
    }

    pub fn build(self) -> SlotLockManagerConfig {
        SlotLockManagerConfig {
            bitcoin_precompile_addresses: self
                .bitcoin_precompile_addresses
                .unwrap_or(BITCOIN_PRECOMPILE_ADDRESSES),
            excluded_addresses: self.excluded_addresses,
            sentinel_url: self
                .sentinel_url
                .unwrap_or_else(|| "http://localhost:50051".to_string()),
        }
    }
}

/// Standalone slot lock manager for Bitcoin L2 rollup finality
#[derive(Debug)]
pub struct SlotLockManager {
    cache: Arc<RwLock<StorageCache>>,
    sentinel_client: Arc<dyn SentinelClient>,
    slot_revert_cache: Arc<RwLock<Vec<SlotRevert>>>,
    config: SlotLockManagerConfig,
}

impl SlotLockManager {
    pub fn new(config: SlotLockManagerConfig, sentinel_client: Arc<dyn SentinelClient>) -> Self {
        let cache = Arc::new(RwLock::new(StorageCache::new(
            config.bitcoin_precompile_addresses,
            config.excluded_addresses.clone(),
        )));

        Self {
            cache,
            sentinel_client,
            slot_revert_cache: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    /// Check if a precompile call should be allowed
    pub async fn check_precompile_call(
        &self,
        request: SlotLockRequest,
    ) -> Result<SlotLockResponse, SlotLockError> {
        // Check for unauthorized caller
        if let Some(ref call) = request.precompile_call {
            match call.method {
                BitcoinPrecompileMethod::BroadcastTransaction => {
                    self.handle_broadcast_transaction(request).await
                }
                _ => Ok(SlotLockResponse {
                    decision: SlotLockDecision::Allow,
                    broadcast_result: None,
                }),
            }
        } else {
            // Not a precompile call, check if it's to SovaBTC contract
            if request.transaction_context.target == SOVA_BTC_CONTRACT_ADDRESS {
                self.check_storage_locks(request).await
            } else {
                Ok(SlotLockResponse {
                    decision: SlotLockDecision::Allow,
                    broadcast_result: None,
                })
            }
        }
    }

    /// Handle broadcast transaction precompile
    async fn handle_broadcast_transaction(
        &self,
        request: SlotLockRequest,
    ) -> Result<SlotLockResponse, SlotLockError> {
        // Process storage changes
        self.process_storage_changes(&request.storage_accesses);

        // Check locks
        let decision = self.check_locks(&request).await?;

        if matches!(decision, SlotLockDecision::Allow) {
            // Cache broadcast data
            let broadcast_result = BroadcastResult {
                txid: None, // Will be set by the actual precompile execution
                block: Some(request.block_context.btc_block_height),
            };

            Ok(SlotLockResponse {
                decision,
                broadcast_result: Some(broadcast_result),
            })
        } else {
            Ok(SlotLockResponse {
                decision,
                broadcast_result: None,
            })
        }
    }

    /// Check storage locks for SovaBTC contract calls
    async fn check_storage_locks(
        &self,
        request: SlotLockRequest,
    ) -> Result<SlotLockResponse, SlotLockError> {
        self.process_storage_changes(&request.storage_accesses);
        let decision = self.check_locks(&request).await?;

        Ok(SlotLockResponse {
            decision,
            broadcast_result: None,
        })
    }

    /// Process storage changes and update cache
    fn process_storage_changes(&self, accesses: &[StorageAccess]) {
        let mut cache = self.cache.write();
        cache.broadcast_accessed_storage.clear();

        for access in accesses {
            let change = SlotChange {
                key: U256::from_be_bytes(access.slot.0),
                value: access.new_value.into(),
                had_value: Some(access.previous_value.into()),
            };

            cache.insert_broadcast_accessed_storage(access.address, access.slot, change);
        }
    }

    /// Check if any accessed slots are locked
    async fn check_locks(
        &self,
        request: &SlotLockRequest,
    ) -> Result<SlotLockDecision, SlotLockError> {
        let cache = self.cache.read();
        let accessed_storage = &cache.broadcast_accessed_storage;

        if accessed_storage.0.is_empty() {
            return Ok(SlotLockDecision::Allow);
        }

        let response = self
            .sentinel_client
            .batch_get_locked_status(
                accessed_storage,
                request.block_context.number,
                request.block_context.btc_block_height,
            )
            .await?;

        let mut revert_slots = Vec::new();

        for slot_response in response.slots {
            let status = Status::try_from(slot_response.status)
                .map_err(|_| SlotLockError::InvalidResponse("Invalid status".to_string()))?;

            match status {
                Status::Unknown => {
                    return Ok(SlotLockDecision::Revert {
                        reason: "Sentinel returned unknown status".to_string(),
                    });
                }
                Status::Locked => {
                    self.log_slot_decision(
                        &slot_response.contract_address,
                        &slot_response.slot_index,
                        "locked",
                        "transaction_reverted",
                        request.block_context.number,
                    );

                    return Ok(SlotLockDecision::Revert {
                        reason: format!(
                            "Storage slot is locked: {}:{}",
                            slot_response.contract_address,
                            hex::encode(&slot_response.slot_index)
                        ),
                    });
                }
                Status::Unlocked => {
                    self.log_slot_decision(
                        &slot_response.contract_address,
                        &slot_response.slot_index,
                        "unlocked",
                        "transaction_continues",
                        request.block_context.number,
                    );
                }
                Status::Reverted => {
                    let revert = self.parse_revert_data(slot_response);
                    self.log_slot_decision(
                        &revert.address.to_string(),
                        &revert.slot.to_be_bytes_vec(),
                        "reverted",
                        "slot_reverted_to_previous_value",
                        request.block_context.number,
                    );
                    revert_slots.push(revert);
                }
            }
        }

        if !revert_slots.is_empty() {
            // Store reverts for later application
            let mut revert_cache = self.slot_revert_cache.write();
            revert_cache.extend(revert_slots.clone());

            Ok(SlotLockDecision::RevertWithSlotData {
                slots: revert_slots,
            })
        } else {
            Ok(SlotLockDecision::Allow)
        }
    }

    /// Parse revert data from sentinel response
    fn parse_revert_data(
        &self,
        response: sova_sentinel_proto::proto::GetSlotStatusResponse,
    ) -> SlotRevert {
        let address =
            Address::from_str(&response.contract_address).unwrap_or_else(|_| Address::ZERO);

        let mut key_bytes = [0u8; 32];
        key_bytes[32 - response.slot_index.len()..].copy_from_slice(&response.slot_index);
        let slot = U256::from_be_bytes(key_bytes);

        let mut current_bytes = [0u8; 32];
        current_bytes[32 - response.current_value.len()..].copy_from_slice(&response.current_value);
        let current_value = U256::from_be_bytes(current_bytes);

        let mut revert_bytes = [0u8; 32];
        revert_bytes[32 - response.revert_value.len()..].copy_from_slice(&response.revert_value);
        let revert_to = U256::from_be_bytes(revert_bytes);

        SlotRevert {
            address,
            slot,
            revert_to,
            current_value,
        }
    }

    /// Update sentinel locks for the next block
    pub async fn update_sentinel_locks(
        &self,
        locked_block_number: u64,
    ) -> Result<(), SlotLockError> {
        let cache = self.cache.read();

        for (broadcast_result, accessed_storage) in cache.lock_data.iter() {
            if let (Some(btc_txid), Some(btc_block)) =
                (broadcast_result.txid.as_ref(), broadcast_result.block)
            {
                self.sentinel_client
                    .batch_lock_slots(
                        accessed_storage.clone(),
                        locked_block_number,
                        btc_block,
                        btc_txid.clone(),
                    )
                    .await?;
            } else {
                warn!(
                    "Incomplete broadcast result: txid={:?}, block={:?}",
                    broadcast_result.txid.as_ref().map(hex::encode),
                    broadcast_result.block
                );
            }
        }

        // Clear cache after updating locks
        drop(cache);
        self.cache.write().clear_cache();
        self.slot_revert_cache.write().clear();

        Ok(())
    }

    /// Get pending slot reverts
    pub fn get_pending_reverts(&self) -> Vec<SlotRevert> {
        self.slot_revert_cache.read().clone()
    }

    /// Clear pending reverts
    pub fn clear_pending_reverts(&self) {
        self.slot_revert_cache.write().clear();
    }

    /// Called AFTER a broadcast precompile successfully executes
    /// with the actual Bitcoin txid that was broadcast.
    ///
    /// This completes the two-phase broadcast flow:
    /// 1. check_precompile_call() - validates and caches storage accesses
    /// 2. finalize_broadcast() - commits with actual txid for future locking
    pub fn finalize_broadcast(&self, txid: Vec<u8>, btc_block: u64) {
        let mut cache = self.cache.write();

        // The broadcast_accessed_storage has the slots that were accessed
        // before the broadcast call. Now we commit them with the actual txid.
        let broadcast_result = BroadcastResult {
            txid: Some(txid),
            block: Some(btc_block),
        };

        cache.commit_broadcast(broadcast_result);
    }

    /// Clear all storage data for a new block
    pub fn clear_cache(&self) {
        self.cache.write().clear_cache();
        self.slot_revert_cache.write().clear();
    }

    /// Log slot decision for debugging
    fn log_slot_decision(
        &self,
        contract_address: &str,
        slot_index: &[u8],
        status: &str,
        decision: &str,
        block_number: u64,
    ) {
        let log_entry = json!({
            "operation_id": Uuid::new_v4(),
            "event_type": "slot_decision",
            "contract_address": contract_address,
            "slot_index": hex::encode(slot_index),
            "slot_status": status,
            "decision": decision,
            "block_number": block_number,
        });

        match (status, decision) {
            // Critical errors that prevent operation
            ("error", _) | (_, "failed_to_get_btc_height") => {
                error!(target: "slot_lock_manager", "{}", log_entry);
            }
            // Invalid data or status
            ("invalid", _) | ("unknown", _) => {
                error!(target: "slot_lock_manager", "{}", log_entry);
            }
            // Transaction blocking events
            ("locked", _) | (_, "transaction_reverted") => {
                warn!(target: "slot_lock_manager", "{}", log_entry);
            }
            // State reversions
            ("reverted", _) | (_, "slot_reverted_to_previous_value") => {
                debug!(target: "slot_lock_manager", "{}", log_entry);
            }
            // Routine successful operations
            ("unlocked", "transaction_continues") | ("checking", "batch_lock_check_started") => {
                debug!(target: "slot_lock_manager", "{}", log_entry);
            }
            // Default to info for any other combinations
            _ => {
                info!(target: "slot_lock_manager", "{}", log_entry);
            }
        }
    }
}
