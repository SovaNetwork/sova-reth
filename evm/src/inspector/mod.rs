mod error;
mod handle;
mod provider;
mod sova_trait;
mod storage_cache;

use provider::StorageSlotProvider;

pub use error::SlotProviderError;
pub use handle::InspectorHandle;
pub use provider::SlotProvider;
pub use sova_trait::{Inspector};
pub use storage_cache::{BroadcastResult, StorageCache};

use core::ops::Range;
use std::{str::FromStr, sync::Arc};

use serde_json::json;
use uuid::Uuid;

use alloy_primitives::{Address, Bytes, U256};

use reth_revm::{
    context::{journaled_state::JournalCheckpoint, Block, ContextTr, JournalTr},
    db::{states::StorageSlot, AccountStatus, StorageWithOriginalValues, TransitionAccount},
    inspector::JournalExt,
    interpreter::{
        CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    Inspector as RevmInspector, JournalEntry,
};
use reth_tasks::TaskExecutor;
use reth_tracing::tracing::{debug, error, info, warn};

use crate::{inspector::sova_trait::SlotRevert, precompiles::BitcoinMethodHelper};

use sova_chainspec::{
    BitcoinPrecompileMethod, L1_BLOCK_CURRENT_BLOCK_HEIGHT_SLOT, SOVA_BTC_CONTRACT_ADDRESS,
    SOVA_L1_BLOCK_CONTRACT_ADDRESS,
};
use sova_sentinel_proto::proto::{get_slot_status_response::Status, GetSlotStatusResponse};

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

/// EVM engine inspector for enforcing storage slot locks
#[derive(Debug, Clone)]
pub struct SovaInspector {
    /// accessed storage cache
    pub cache: StorageCache,
    /// client for calling lock storage service
    pub storage_slot_provider: Arc<StorageSlotProvider>,
    /// transition state for applying slot reverts
    pub slot_revert_cache: Vec<(Address, TransitionAccount)>,
    /// Journal checkpoint for the current transaction
    checkpoint: Option<JournalCheckpoint>,
    /// Unique operation ID for tracking this transaction's slot operations
    operation_id: Option<Uuid>,
}

impl SovaInspector {
    pub fn new(
        bitcoin_precompile_addresses: [Address; 4],
        excluded_addresses: impl IntoIterator<Item = Address>,
        sentinel_url: String,
        task_executor: TaskExecutor,
    ) -> Result<Self, SlotProviderError> {
        let storage_slot_provider =
            Arc::new(StorageSlotProvider::new(sentinel_url, task_executor)?);

        Ok(Self {
            cache: StorageCache::new(bitcoin_precompile_addresses, excluded_addresses),
            storage_slot_provider,
            slot_revert_cache: Vec::new(),
            checkpoint: None,
            operation_id: None,
        })
    }

    /// Clear all storage data for a new block
    fn clear_cache(&mut self) {
        self.cache.clear_cache();
        self.slot_revert_cache.clear();
    }

    /// Move the captured revert transitions out of the inspector.
    /// This is used between pass #1 (simulation) and pass #2 (final execution).
    pub fn take_slot_revert_cache(&mut self) -> Vec<(Address, TransitionAccount)> {
        core::mem::take(&mut self.slot_revert_cache)
    }

    /// Unlock all revereted storage slots and lock all accessed storage slots at the end of execution
    pub fn update_sentinel_locks(
        &mut self,
        locked_block_number: u64,
    ) -> Result<(), SlotProviderError> {
        // Handle locking of storage slots for each btc broadcast transaction
        for (broadcast_result, accessed_storage) in self.cache.lock_data.iter() {
            if let (Some(btc_txid), Some(btc_block)) =
                (broadcast_result.txid.as_ref(), broadcast_result.block)
            {
                // Lock the storage with this transaction's details
                match self.storage_slot_provider.batch_lock_slots(
                    accessed_storage.clone(),
                    locked_block_number,
                    btc_block,
                    btc_txid.clone(),
                ) {
                    Ok(()) => {
                        // Lock operation successful
                    }
                    Err(SlotProviderError::BitcoinNodeUnavailable(msg)) => {
                        warn!("Bitcoin node unavailable during lock operation: {}", msg);
                        // For lock operations, we might want to retry or defer
                        // For now, propagate the error
                        return Err(SlotProviderError::BitcoinNodeUnavailable(msg));
                    }
                    Err(SlotProviderError::ServiceUnavailable(msg)) => {
                        warn!(
                            "Sentinel service unavailable during lock operation: {}",
                            msg
                        );
                        return Err(SlotProviderError::ServiceUnavailable(msg));
                    }
                    Err(SlotProviderError::InvalidRequest(msg)) => {
                        // This is likely a programming error
                        warn!("Invalid lock request: {}", msg);
                        return Err(SlotProviderError::InvalidRequest(msg));
                    }
                    Err(other_error) => {
                        warn!("Failed to lock storage slots: {}", other_error);
                        return Err(other_error);
                    }
                }
            } else {
                warn!(
                    "Incomplete broadcast result: txid={:?}, block={:?}",
                    broadcast_result.txid.as_ref().map(hex::encode),
                    broadcast_result.block
                );
            }
        }

        self.clear_cache();

        Ok(())
    }

    /// helper to load L1Block data from state
    fn get_l1_block_data<CTX: ContextTr<Journal: JournalExt>>(
        context: &mut CTX,
    ) -> Result<u64, String> {
        let (_, journal) = context.tx_journal_mut();

        // load the account
        match journal.load_account(SOVA_L1_BLOCK_CONTRACT_ADDRESS) {
            Ok(_) => {
                // try to load the storage
                match journal.sload(
                    SOVA_L1_BLOCK_CONTRACT_ADDRESS,
                    L1_BLOCK_CURRENT_BLOCK_HEIGHT_SLOT,
                ) {
                    Ok(state_load) => {
                        debug!(
                            "Got Bitcoin block height from state: {}",
                            state_load.data.as_limbs()[0]
                        );
                        Ok(state_load.data.as_limbs()[0])
                    }
                    Err(err) => {
                        warn!("Storage load error: {}", err);
                        Ok(0)
                    }
                }
            }
            Err(err) => {
                warn!("Account load error: {}", err);
                Ok(0)
            }
        }
    }

    /// Process storage changes from journal entries and update accessed storage cache
    fn process_storage_journal_entries<CTX: ContextTr<Journal: JournalExt>>(
        &mut self,
        context: &mut CTX,
    ) {
        // Clear the broadcast accessed storage before processing
        self.cache.broadcast_accessed_storage.0.clear();

        // Iterate through journal entries since last checkpoint and add to broadcast_accessed_storage cache
        for entry in context.journal_ref().journal() {
            if let JournalEntry::StorageChanged {
                address,
                key,
                had_value,
            } = entry
            {
                let value = context.journal_ref().evm_state()[address].storage[key].present_value();

                let storage_change = StorageChange {
                    key: *key,
                    value,
                    had_value: Some(*had_value),
                };

                self.cache.insert_broadcast_accessed_storage(
                    *address,
                    (*key).into(),
                    storage_change,
                );
            }
        }
    }

    /// Create a revert outcome with an error message
    fn create_revert_outcome(
        message: String,
        gas_limit: u64,
        memory_offset: Range<usize>,
    ) -> CallOutcome {
        warn!("Inspector revert message: {}", message);

        CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::Revert,
                output: Bytes::copy_from_slice(message.as_bytes()),
                gas: Gas::new_spent(gas_limit),
            },
            memory_offset,
        }
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
            ("error", _) | (_, "failed_to_get_btc_height") => {
                error!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Invalid data or status
            ("invalid", _) | ("unknown", _) => {
                error!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Transaction blocking events
            ("locked", _) | (_, "transaction_reverted") => {
                warn!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // State reversions
            ("reverted", _) | (_, "slot_reverted_to_previous_value") => {
                debug!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Routine successful operations
            ("unlocked", "transaction_continues") | ("checking", "batch_lock_check_started") => {
                debug!(target: "sova_slot_tracker", "{}", log_entry);
            }
            // Default to info for any other combinations
            _ => {
                info!(target: "sova_slot_tracker", "{}", log_entry);
            }
        }
    }

    /// Triggered at the beginning of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode.
    /// This inspector hook is primarily used for storage slot lock enforcement.
    /// Any cached storage access prior to a broadcast btc tx CALL will be checked for a lock.
    /// Only one btc broadcast tx call is allowed per tx.
    fn call_inner<CTX: ContextTr<Journal: JournalExt>>(
        &mut self,
        context: &mut CTX,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        if self
            .cache
            .bitcoin_precompile_addresses
            .contains(&inputs.target_address)
            && inputs.caller != SOVA_BTC_CONTRACT_ADDRESS
        {
            return Some(Self::create_revert_outcome(
                "Unauthorized caller for bitcoin precompile".to_string(),
                inputs.gas_limit,
                inputs.return_memory_offset.clone(),
            ));
        }

        // intercept all BTC broadcast precompile calls and check locks
        if !self
            .cache
            .bitcoin_precompile_addresses
            .contains(&inputs.target_address)
        {
            return None;
        }
        debug!("----- precompile call hook -----");

        let method = BitcoinMethodHelper::method_from_address(inputs.target_address);

        match method {
            Ok(BitcoinPrecompileMethod::BroadcastTransaction) => {
                debug!("-> Broadcast call hook");

                // Process storage journal entries to find sstores before checking locks
                self.process_storage_journal_entries(context);

                // check locks
                self.handle_lock_checks(context, inputs)
            }
            Ok(_) => None, // Other methods we don't care about
            Err(err) => {
                // Return an error if we couldn't parse the method
                Some(Self::create_revert_outcome(
                    format!("Invalid Bitcoin method: {err}"),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ))
            }
        }
    }

    /// Check to see if any of the broadcast storage slots are locked
    fn handle_lock_checks<CTX: ContextTr<Journal: JournalExt>>(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Option<CallOutcome> {
        // Generate unique operation ID for this transaction
        if self.operation_id.is_none() {
            self.operation_id = Some(Uuid::new_v4());
        }

        let block_number = context.block().number().to();

        // load current btc block height from state
        let current_btc_block_height = match Self::get_l1_block_data(context) {
            Ok(height) => height,
            Err(err) => {
                self.log_slot_decision(
                    "system",
                    &[],
                    "error",
                    "failed_to_get_btc_height",
                    block_number,
                    Some(json!({ "error": err })),
                );
                return Some(Self::create_revert_outcome(
                    format!("Failed to get current Bitcoin block height from state: {err}"),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ));
            }
        };

        let (_, journal) = context.tx_journal_mut();

        self.log_slot_decision(
            "batch",
            &[],
            "checking",
            "batch_lock_check_started",
            block_number,
            Some(json!({
                "btc_block_height": current_btc_block_height,
                "slots_count": self.cache.broadcast_accessed_storage.0.len(),
                "caller": inputs.caller.to_string(),
                "target": inputs.target_address.to_string()
            })),
        );

        // check if any of the storage slots in broadcast_accessed_storage are locked
        match self.storage_slot_provider.batch_get_locked_status(
            &self.cache.broadcast_accessed_storage,
            block_number,
            current_btc_block_height,
        ) {
            Ok(batch_response) => {
                for response in batch_response.slots {
                    let status = match Status::try_from(response.status) {
                        Ok(status) => status,
                        Err(_) => {
                            self.log_slot_decision(
                                &response.contract_address,
                                &response.slot_index,
                                "invalid",
                                "transaction_reverted",
                                block_number,
                                Some(json!({ "invalid_status_value": response.status })),
                            );
                            return Some(Self::create_revert_outcome(
                                format!("Invalid status value {} from sentinel", response.status),
                                inputs.gas_limit,
                                inputs.return_memory_offset.clone(),
                            ));
                        }
                    };

                    match status {
                        Status::Unknown => {
                            // This should have been caught by the provider validation,
                            // but handle it here as well for defense in depth
                            self.log_slot_decision(
                                &response.contract_address,
                                &response.slot_index,
                                "unknown",
                                "transaction_reverted",
                                block_number,
                                Some(json!({ "reason": "sentinel_connectivity_issue" })),
                            );
                            return Some(Self::create_revert_outcome(
                                "Sentinel returned unknown status".to_string(),
                                inputs.gas_limit,
                                inputs.return_memory_offset.clone(),
                            ));
                        }
                        Status::Locked => {
                            self.log_slot_decision(
                                &response.contract_address,
                                &response.slot_index,
                                "locked",
                                "transaction_reverted",
                                block_number,
                                Some(json!({ "reason": "slot_locked" })),
                            );

                            // Clear revert cache on locked status
                            self.slot_revert_cache.clear();

                            // CRITICAL: Always revert state changes in journal when a lock is detected
                            if let Some(checkpoint) = self.checkpoint {
                                journal.checkpoint_revert(checkpoint);
                            } else {
                                warn!("WARNING: No checkpoint available for reversion");
                            }

                            return Some(Self::create_revert_outcome(
                                format!(
                                    "Storage slot is locked: {}:{}",
                                    response.contract_address,
                                    hex::encode(&response.slot_index)
                                ),
                                inputs.gas_limit,
                                inputs.return_memory_offset.clone(),
                            ));
                        }
                        Status::Unlocked => {
                            self.log_slot_decision(
                                &response.contract_address,
                                &response.slot_index,
                                "unlocked",
                                "transaction_continues",
                                block_number,
                                None,
                            );
                        }
                        Status::Reverted => {
                            self.log_slot_decision(
                                &response.contract_address,
                                &response.slot_index,
                                "reverted",
                                "slot_reverted_to_previous_value",
                                block_number,
                                Some(json!({
                                    "revert_value": hex::encode(&response.revert_value),
                                    "current_value": hex::encode(&response.current_value)
                                })),
                            );

                            self.handle_revert_status(response);
                        }
                    }
                }
                None
            }
            Err(err) => {
                self.log_slot_decision(
                    "batch",
                    &[],
                    "error",
                    "transaction_reverted",
                    block_number,
                    Some(json!({
                        "error_type": format!("{:?}", std::mem::discriminant(&err)),
                        "error_message": err.to_string()
                    })),
                );

                // Handle different error types with appropriate messages and actions
                match &err {
                    SlotProviderError::BitcoinNodeUnavailable(msg) => {
                        warn!("Bitcoin node unavailable: {}", msg);
                        Some(Self::create_revert_outcome(
                            "Bitcoin node unavailable - cannot verify slot locks".to_string(),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ))
                    }
                    SlotProviderError::ServiceUnavailable(msg) => {
                        warn!("Sentinel service unavailable: {}", msg);
                        Some(Self::create_revert_outcome(
                            "Sentinel service unavailable - cannot verify slot locks".to_string(),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ))
                    }
                    SlotProviderError::UnknownSlotStatus {
                        contract_address,
                        slot_index,
                        message,
                    } => {
                        warn!(
                            "Unknown slot status for {}:{}: {}",
                            contract_address,
                            hex::encode(slot_index),
                            message
                        );
                        Some(Self::create_revert_outcome(
                            format!("Unknown slot status - {message}"),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ))
                    }
                    SlotProviderError::Timeout(msg) => {
                        warn!("Timeout communicating with sentinel: {}", msg);
                        Some(Self::create_revert_outcome(
                            "Timeout verifying slot locks - transaction reverted for safety"
                                .to_string(),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ))
                    }
                    SlotProviderError::InvalidRequest(msg) => {
                        warn!("Invalid request to sentinel: {}", msg);
                        Some(Self::create_revert_outcome(
                            "Invalid lock check request".to_string(),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ))
                    }
                    _ => {
                        warn!("Failed to get lock status from sentinel: {}", err);
                        Some(Self::create_revert_outcome(
                            "Failed to verify slot locks - transaction reverted for safety"
                                .to_string(),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ))
                    }
                }
            }
        }
    }

    // Parse revert info from the sentinel and update the revert cache
    fn handle_revert_status(&mut self, response: GetSlotStatusResponse) {
        // Parse contract address
        let address = Address::from_str(&response.contract_address)
            .expect("Invalid contract address from sentinel");

        // Convert slot index bytes to U256 key
        let mut key_bytes = [0u8; 32];
        key_bytes[32 - response.slot_index.len()..].copy_from_slice(&response.slot_index);
        let key = U256::from_be_bytes(key_bytes);

        // Convert current value bytes to U256
        let mut current_bytes = [0u8; 32];
        current_bytes[32 - response.current_value.len()..].copy_from_slice(&response.current_value);
        let current_value = U256::from_be_bytes(current_bytes);

        // Convert revert value bytes to U256
        let mut revert_bytes = [0u8; 32];
        revert_bytes[32 - response.revert_value.len()..].copy_from_slice(&response.revert_value);
        let revert_value = U256::from_be_bytes(revert_bytes);

        // Create storage with both current and previous values
        let mut storage = StorageWithOriginalValues::default();
        let storage_slot = StorageSlot::new_changed(current_value, revert_value);
        storage.insert(key, storage_slot);

        let transition: TransitionAccount = TransitionAccount {
            info: None,
            status: AccountStatus::Changed,
            previous_info: None,
            previous_status: AccountStatus::Loaded,
            storage,
            storage_was_destroyed: false,
        };

        // Add to transition state
        self.slot_revert_cache.push((address, transition));
    }

    /// Triggered at the end of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode
    /// This inspector hook is primarily used for locking accessed
    /// storage slots if a bitcoin broadcast tx precompile executed successfully.
    fn call_end_inner<CTX: ContextTr<Journal: JournalExt>>(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        // Skip unauthorized bitcoin precompile calls
        if self
            .cache
            .bitcoin_precompile_addresses
            .contains(&inputs.target_address)
            && inputs.caller != SOVA_BTC_CONTRACT_ADDRESS
        {
            return;
        }

        // Handle Bitcoin precompile calls
        if self
            .cache
            .bitcoin_precompile_addresses
            .contains(&inputs.target_address)
        {
            debug!("----- precompile call end hook -----");

            // Only process Bitcoin methods for Bitcoin precompile calls
            let method = BitcoinMethodHelper::method_from_address(inputs.target_address);
            match method {
                Ok(BitcoinPrecompileMethod::BroadcastTransaction) => {
                    debug!("-> Broadcast call end hook");

                    // Only cache data if call was successful
                    if outcome.result.result == InstructionResult::Return {
                        if let Some(revert_outcome) =
                            self.handle_cache_btc_data(context, inputs, outcome)
                        {
                            *outcome = revert_outcome;
                        }
                    } else {
                        *outcome = Self::create_revert_outcome(
                            "Broadcast btc precompile execution failed".to_string(),
                            inputs.gas_limit,
                            outcome.memory_offset.clone(),
                        );
                    }
                }
                Ok(_) => {
                    // Other Bitcoin methods we don't care about
                }
                Err(err) => {
                    *outcome = Self::create_revert_outcome(
                        format!("Invalid Bitcoin method: {err}"),
                        inputs.gas_limit,
                        inputs.return_memory_offset.clone(),
                    )
                }
            }
        }
        // For non-Bitcoin precompile calls to the SovaBTC contract, check locks for any SSTORE operations
        else if inputs.target_address == SOVA_BTC_CONTRACT_ADDRESS {
            // Process storage journal entries before checking locks
            self.process_storage_journal_entries(context);

            // Check if any storage modifications conflict with locks
            if let Some(revert_outcome) = self.handle_lock_checks(context, inputs) {
                // Replace successful outcome with revert due to lock conflict
                *outcome = revert_outcome;
                // Clear checkpoint after reverting
                self.checkpoint = None;
            }
        }
    }

    /// Cache the broadcast btc precompile result for future use in lock storage enforcement
    fn handle_cache_btc_data<CTX: ContextTr<Journal: JournalExt>>(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) -> Option<CallOutcome> {
        if outcome.result.output.len() < 32 {
            warn!(
                "Broadcast btc precompile output too short: {} bytes",
                outcome.result.output.len()
            );
            return Some(Self::create_revert_outcome(
                "Broadcast precompile output too short".to_string(),
                inputs.gas_limit,
                inputs.return_memory_offset.clone(),
            ));
        }

        let broadcast_txid = outcome.result.output[..32].to_vec();

        // load current btc block height from state
        let broadcast_block = match Self::get_l1_block_data(context) {
            Ok(height) => height,
            Err(err) => {
                warn!(
                    "Failed to get current Bitcoin block height from state: {}",
                    err
                );
                return Some(Self::create_revert_outcome(
                    format!("Failed to get current Bitcoin block height from state: {err}",),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ));
            }
        };

        debug!(
            "Caching btc data from broadcast precompile call. Bitcoin block height from state: {}",
            broadcast_block
        );

        // set broadcast txid and block in broadcast result
        let broadcast_result = BroadcastResult {
            txid: Some(broadcast_txid),
            block: Some(broadcast_block),
        };

        // Commit the broadcast storage to block storage and lock data
        self.cache.commit_broadcast(broadcast_result);

        None
    }
}

impl<CTX> RevmInspector<CTX> for SovaInspector
where
    CTX: ContextTr<Journal: JournalExt>,
{
    fn initialize_interp(&mut self, _interp: &mut Interpreter, context: &mut CTX) {
        let (_, journal) = context.tx_journal_mut();

        // Ensure clean cache
        self.clear_cache();

        // create new operation ID
        self.operation_id = Some(Uuid::new_v4());

        // Create a new checkpoint
        self.checkpoint = Some(journal.checkpoint());
    }

    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let (_, journal) = context.tx_journal_mut();

        // Create a checkpoint if there isnt one already
        if self.checkpoint.is_none() {
            self.checkpoint = Some(journal.checkpoint());
        }

        self.call_inner(context, inputs)
    }

    fn call_end(&mut self, context: &mut CTX, inputs: &CallInputs, outcome: &mut CallOutcome) {
        self.call_end_inner(context, inputs, outcome);
    }
}

impl Inspector for SovaInspector {
    fn on_tx_start(&mut self, _tx_hash: alloy_primitives::B256) {
        self.slot_revert_cache.clear();
    }

    fn on_sstore(&mut self, addr: Address, slot: U256, prev: U256, new: U256) {
        let storage_change = StorageChange {
            key: slot,
            value: new,
            had_value: Some(prev),
        };

        self.cache
            .insert_broadcast_accessed_storage(addr, slot.into(), storage_change);
    }

    fn on_broadcast_end(&mut self, txid: [u8; 32], btc_block: u64) {
        let broadcast_result = BroadcastResult {
            txid: Some(txid.to_vec()),
            block: Some(btc_block),
        };

        self.cache.commit_broadcast(broadcast_result);
    }

    fn take_slot_reverts(&mut self) -> Vec<(Address, SlotRevert)> {
        let mut slot_reverts = Vec::new();

        for (address, transition_account) in std::mem::take(&mut self.slot_revert_cache) {
            for (slot, storage_slot) in transition_account.storage.iter() {
                let slot_revert = SlotRevert {
                    slot: *slot,
                    previous_value: storage_slot.original_value(),
                };
                slot_reverts.push((address, slot_revert));
            }
        }

        slot_reverts
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
