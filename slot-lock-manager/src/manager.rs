use crate::{
    cache::{BroadcastResult, StorageCache},
    client::{SentinelClient, SentinelClientImpl},
    error::SlotLockError,
    types::*,
};
use alloy_primitives::{Address, U256};
use parking_lot::RwLock;
use serde_json::json;
use sova_chainspec::{
    BITCOIN_PRECOMPILE_ADDRESSES, L1_BLOCK_CONTRACT_ADDRESS, SOVA_BTC_CONTRACT_ADDRESS,
};
use sova_sentinel_proto::proto::get_slot_status_response::Status;
use std::{str::FromStr, sync::Arc};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Configuration for the SlotLockManager
#[derive(Debug, Default)]
pub struct SlotLockManagerConfig {
    pub bitcoin_precompile_addresses: [Address; 4],
    pub excluded_addresses: Vec<Address>,
    pub sentinel_url: String,
}

impl SlotLockManagerConfig {
    pub fn new(
        bitcoin_precompile_addresses: Option<[Address; 4]>,
        excluded_addresses: Vec<Address>,
        sentinel_url: Option<String>,
    ) -> Self {
        Self {
            bitcoin_precompile_addresses: bitcoin_precompile_addresses
                .unwrap_or(BITCOIN_PRECOMPILE_ADDRESSES),
            excluded_addresses,
            sentinel_url: sentinel_url.unwrap_or_else(|| "http://localhost:50051".to_string()),
        }
    }
}

/// Standalone slot lock manager for Bitcoin L2 rollup finality
#[derive(Debug)]
pub struct SlotLockManager {
    cache: Arc<RwLock<StorageCache>>,
    sentinel_client: Arc<dyn SentinelClient>,
    slot_revert_cache: Arc<RwLock<Vec<SlotRevert>>>,
    #[allow(dead_code)]
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

    pub fn build_default() -> eyre::Result<Arc<Self>> {
        let sentinel_url =
            std::env::var("SENTINEL_URL").unwrap_or_else(|_| "http://localhost:50051".to_string());
        let cfg = SlotLockManagerConfig::new(
            None,
            vec![L1_BLOCK_CONTRACT_ADDRESS],
            Some(sentinel_url.clone()),
        );
        let sentinel = Arc::new(SentinelClientImpl::new(sentinel_url));
        Ok(Arc::new(Self::new(cfg, sentinel)))
    }

    /// ---- HELPERS ----

    fn parse_revert_data(
        &self,
        response: sova_sentinel_proto::proto::GetSlotStatusResponse,
    ) -> SlotRevert {
        let address = Address::from_str(&response.contract_address).unwrap_or(Address::ZERO);

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

    pub fn clone_pending_reverts(&self) -> Vec<SlotRevert> {
        self.slot_revert_cache.read().clone()
    }

    /// ---- LOCK CHECKING ----

    fn extract_storage_accesses_from_evm_state(
        &self,
        evm_state: &revm::state::EvmState,
    ) -> Vec<StorageAccess> {
        let mut storage_accesses = Vec::new();

        // Iterate through all accounts in the EVM state
        for (address, account) in evm_state.iter() {
            debug!(target: "slot_lock_manager",
                "EVM account: {:?}, storage slots: {}, status: {:?}",
                address,
                account.storage.len(),
                account.status
            );

            // Extract storage changes from the account
            for (slot_key, storage_slot) in &account.storage {
                debug!(target: "slot_lock_manager",
                    "Storage slot: key={:?}, original={:?}, present={:?}",
                    slot_key,
                    storage_slot.original_value,
                    storage_slot.present_value
                );

                let storage_access = StorageAccess {
                    address: *address,
                    slot: alloy_primitives::StorageKey::from(*slot_key),
                    previous_value: alloy_primitives::StorageValue::from(
                        storage_slot.original_value,
                    ),
                    new_value: alloy_primitives::StorageValue::from(storage_slot.present_value),
                };
                storage_accesses.push(storage_access);
            }
        }

        storage_accesses
    }

    fn check_storage_access_locks(
        &self,
        request: SlotLockRequest,
    ) -> Result<SlotLockResponse, SlotLockError> {
        // Process storage changes - save to broadcast_accessed_storage
        self.update_broadcast_accessed_storage(&request.storage_accesses);

        // Get accessed storage
        let cache = self.cache.read();
        let accessed_storage = cache.broadcast_accessed_storage.clone();

        // return early if no bitcoin tx triggered
        if accessed_storage.0.is_empty() {
            return Ok(SlotLockResponse {
                decision: SlotLockDecision::AllowTx,
                broadcast_result: None,
            });
        }

        // Use blocking call to sentinel client
        let response = std::thread::spawn({
            let sentinel_client = self.sentinel_client.clone();
            let accessed_storage = accessed_storage.clone();
            let block_number = request.block_context.number;
            let btc_block_height = request.block_context.btc_block_height;

            move || {
                // Create a new runtime for this blocking call
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move {
                    sentinel_client
                        .batch_get_locked_status(&accessed_storage, block_number, btc_block_height)
                        .await
                })
            }
        })
        .join()
        .map_err(|_| SlotLockError::InvalidResponse("Thread panicked".to_string()))??;

        // Process the response
        let mut revert_slots = Vec::new();

        for slot_response in response.slots {
            let status = Status::try_from(slot_response.status)
                .map_err(|_| SlotLockError::InvalidResponse("Invalid status".to_string()))?;

            match status {
                Status::Unknown => {
                    return Ok(SlotLockResponse {
                        decision: SlotLockDecision::BlockTx {
                            reason: "Sentinel returned unknown status".to_string(),
                        },
                        broadcast_result: None,
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

                    return Ok(SlotLockResponse {
                        decision: SlotLockDecision::BlockTx {
                            reason: format!(
                                "Storage slot is locked: {}:{}",
                                slot_response.contract_address,
                                hex::encode(&slot_response.slot_index)
                            ),
                        },
                        broadcast_result: None,
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

            Ok(SlotLockResponse {
                decision: SlotLockDecision::RevertTxWithSlotData {
                    slots: revert_slots,
                },
                broadcast_result: None,
            })
        } else {
            // Check if this is a broadcast precompile
            if request.precompile_call.is_some() {
                let broadcast_result = BroadcastResult {
                    txid: None, // Will be set by the actual precompile execution
                    block: Some(request.block_context.btc_block_height),
                };

                Ok(SlotLockResponse {
                    decision: SlotLockDecision::AllowTx,
                    broadcast_result: Some(broadcast_result),
                })
            } else {
                Ok(SlotLockResponse {
                    decision: SlotLockDecision::AllowTx,
                    broadcast_result: None,
                })
            }
        }
    }

    pub fn check_evm_state(
        &self,
        evm_state: &revm::state::EvmState,
        transaction_context: TransactionContext,
        block_context: BlockContext,
        precompile_call: Option<PrecompileCall>,
    ) -> Result<SlotLockResponse, SlotLockError> {
        // Convert EvmState to StorageAccess format for internal processing
        let storage_accesses = self.extract_storage_accesses_from_evm_state(evm_state);

        // Create SlotLockRequest with the extracted data
        let request = SlotLockRequest {
            transaction_context,
            block_context,
            precompile_call,
            storage_accesses,
        };

        self.check_storage_access_locks(request)
    }

    /// ---- TX INTROSPECTION ----

    fn update_broadcast_accessed_storage(&self, accesses: &[StorageAccess]) {
        let mut cache = self.cache.write();
        cache.broadcast_accessed_storage.clear();

        for access in accesses {
            let change = SlotChange {
                key: U256::from_be_bytes(access.slot.0),
                value: access.new_value,
                had_value: Some(access.previous_value),
            };

            cache.insert_broadcast_accessed_storage(access.address, access.slot, change);
        }
    }

    async fn check_locks(
        &self,
        request: &SlotLockRequest,
    ) -> Result<SlotLockDecision, SlotLockError> {
        let cache = self.cache.read();
        let accessed_storage = cache.broadcast_accessed_storage.clone();

        // return early if there havent been any BTC Broadcast precompile calls
        if accessed_storage.0.is_empty() {
            return Ok(SlotLockDecision::AllowTx);
        }

        let response = self
            .sentinel_client
            .batch_get_locked_status(
                &accessed_storage,
                request.block_context.number,
                request.block_context.btc_block_height,
            )
            .await?;

        debug!("sentinel batch_get_locked_status response {:?}", response);

        let mut revert_slots = Vec::new();

        for slot_response in response.slots {
            let status = Status::try_from(slot_response.status)
                .map_err(|_| SlotLockError::InvalidResponse("Invalid status".to_string()))?;

            match status {
                Status::Unknown => {
                    return Ok(SlotLockDecision::BlockTx {
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

                    return Ok(SlotLockDecision::BlockTx {
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

            Ok(SlotLockDecision::RevertTxWithSlotData {
                slots: revert_slots,
            })
        } else {
            Ok(SlotLockDecision::AllowTx)
        }
    }

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
                    decision: SlotLockDecision::AllowTx,
                    broadcast_result: None,
                }),
            }
        } else {
            // Not a precompile call, check if it's to SovaBTC contract
            if request.transaction_context.target == SOVA_BTC_CONTRACT_ADDRESS {
                self.check_storage_locks(request).await
            } else {
                Ok(SlotLockResponse {
                    decision: SlotLockDecision::AllowTx,
                    broadcast_result: None,
                })
            }
        }
    }

    async fn handle_broadcast_transaction(
        &self,
        request: SlotLockRequest,
    ) -> Result<SlotLockResponse, SlotLockError> {
        self.update_broadcast_accessed_storage(&request.storage_accesses);

        let decision = self.check_locks(&request).await?;

        if matches!(decision, SlotLockDecision::AllowTx) {
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

    pub fn finalize_broadcast(&self, btc_txid: Vec<u8>, btc_block: u64) {
        let mut cache = self.cache.write();

        // The broadcast_accessed_storage has the slots that were accessed
        // before the broadcast call. Now we commit them with the actual txid.
        let broadcast_result = BroadcastResult {
            txid: Some(btc_txid),
            block: Some(btc_block),
        };

        cache.commit_broadcast(broadcast_result);
    }

    async fn check_storage_locks(
        &self,
        request: SlotLockRequest,
    ) -> Result<SlotLockResponse, SlotLockError> {
        self.update_broadcast_accessed_storage(&request.storage_accesses);
        let decision = self.check_locks(&request).await?;

        Ok(SlotLockResponse {
            decision,
            broadcast_result: None,
        })
    }

    /// ---- UPDATE LOCKS ----

    pub fn update_sentinel_locks(&self, locked_block_number: u64) -> Result<(), SlotLockError> {
        let lock_data = {
            let cache = self.cache.read();
            cache.lock_data.clone()
        };

        for (broadcast_result, accessed_storage) in lock_data.iter() {
            if let (Some(btc_txid), Some(btc_block)) =
                (broadcast_result.txid.as_ref(), broadcast_result.block)
            {
                // Use thread spawn approach for async call
                std::thread::spawn({
                    let sentinel_client = self.sentinel_client.clone();
                    let accessed_storage = accessed_storage.clone();
                    let btc_txid = btc_txid.clone();

                    move || {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        rt.block_on(async move {
                            sentinel_client
                                .batch_lock_slots(
                                    accessed_storage,
                                    locked_block_number,
                                    btc_block,
                                    btc_txid,
                                )
                                .await
                        })
                    }
                })
                .join()
                .map_err(|_| SlotLockError::InvalidResponse("Thread panicked".to_string()))??;
            } else {
                warn!(
                    "Incomplete broadcast result: txid={:?}, block={:?}",
                    broadcast_result.txid.as_ref().map(hex::encode),
                    broadcast_result.block
                );
            }
        }

        // Clear cache after updating locks
        self.cache.write().clear_cache();
        self.slot_revert_cache.write().clear();

        Ok(())
    }
}
