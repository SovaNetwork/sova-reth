mod error;
mod provider;
mod storage_cache;

use error::SlotProviderError;
use provider::StorageSlotProvider;
use reth_tasks::TaskExecutor;
use sova_sentinel_proto::proto::{get_slot_status_response::Status, GetSlotStatusResponse};

pub use provider::SlotProvider;
pub use storage_cache::{AccessedStorage, BroadcastResult, StorageCache};

use core::ops::Range;
use std::{str::FromStr, sync::Arc};

use parking_lot::RwLock;

use alloy_primitives::{Address, Bytes, U256};

use reth_revm::{
    db::{states::StorageSlot, AccountStatus, StorageWithOriginalValues},
    interpreter::{
        CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    Database, EvmContext, Inspector, JournalCheckpoint, JournalEntry, TransitionAccount,
};
use reth_tracing::tracing::{debug, warn};

use crate::{precompiles::BitcoinMethod, BitcoinClient};

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

pub struct SovaInspector {
    /// accessed storage cache
    pub cache: StorageCache,
    /// client for calling lock storage service
    pub storage_slot_provider: Arc<StorageSlotProvider>,
    /// btc client
    btc_client: Arc<BitcoinClient>,
    /// transition state for applying slot reverts
    pub slot_revert_cache: Vec<(Address, TransitionAccount)>,
    /// Journal checkpoint for the current transaction
    checkpoint: Option<JournalCheckpoint>,
}

impl SovaInspector {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
        sentinel_url: String,
        task_executor: TaskExecutor,
        btc_client: Arc<BitcoinClient>,
    ) -> Result<Self, SlotProviderError> {
        let storage_slot_provider =
            Arc::new(StorageSlotProvider::new(sentinel_url, task_executor)?);

        Ok(Self {
            cache: StorageCache::new(bitcoin_precompile_address, excluded_addresses),
            storage_slot_provider,
            btc_client,
            slot_revert_cache: Vec::new(),
            checkpoint: None,
        })
    }

    /// Unlock all revereted storage slots and lock all accessed storage slots atend of execution
    pub fn update_sentinel_locks(
        &mut self,
        sova_block_number: u64,
    ) -> Result<(), SlotProviderError> {
        // Handle locking of storage slots for each btc broadcast transaction
        for (broadcast_result, accessed_storage) in self.cache.lock_data.iter() {
            if let (Some(btc_txid), Some(btc_block)) =
                (broadcast_result.txid.as_ref(), broadcast_result.block)
            {
                // Lock the storage with this transaction's details
                self.storage_slot_provider.batch_lock_slots(
                    accessed_storage.clone(),
                    sova_block_number,
                    btc_block,
                    btc_txid.clone(),
                )?;
            }
        }

        // Clear the cache for next block
        self.cache.clear_cache();
        // Clear the revert cache
        self.slot_revert_cache.clear();

        Ok(())
    }

    /// Process storage changes from journal entries and update accessed storage cache
    fn process_storage_journal_entries(&mut self, context: &EvmContext<impl Database>) {
        // Clear the broadcast accessed storage before processing
        self.cache.broadcast_accessed_storage.0.clear();

        // Iterate through journal entries
        for journal_entries in context.journaled_state.journal.iter() {
            for entry in journal_entries.iter() {
                if let JournalEntry::StorageChanged {
                    address,
                    key,
                    had_value,
                } = entry
                {
                    let value = context.journaled_state.state[address].storage[key].present_value();

                    let storage_change = StorageChange {
                        key: *key,
                        value,
                        had_value: Some(*had_value),
                    };

                    self.cache.insert_accessed_storage_step_end(
                        *address,
                        (*key).into(),
                        storage_change,
                    );
                }
            }
        }
    }

    /// Create a revert outcome with an error message
    fn create_revert_outcome(
        message: String,
        gas_limit: u64,
        memory_offset: Range<usize>,
    ) -> CallOutcome {
        CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::Revert,
                output: Bytes::from(message),
                gas: Gas::new_spent(gas_limit),
            },
            memory_offset,
        }
    }

    /// Triggered at the beginning of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode.
    /// This inspector hook is primarily used for storage slot lock enforcement.
    /// Any cached storage access prior to a broadcast btc tx CALL will be checked for a lock.
    /// Only one btc broadcast tx call is allowed per tx.
    fn call_inner(
        &mut self,
        context: &mut EvmContext<impl Database>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        // intercept all BTC broadcast precompile calls and check locks
        if inputs.target_address != self.cache.bitcoin_precompile_address {
            return None;
        }
        debug!("----- precompile call hook -----");

        match BitcoinMethod::try_from(&inputs.input) {
            Ok(BitcoinMethod::BroadcastTransaction) => {
                debug!("-> Broadcast call hook");

                // Process storage journal entries to find sstores before checking locks
                self.process_storage_journal_entries(context);

                // always check locks
                self.handle_lock_checks(context, inputs)
            }
            Ok(_) => None, // Other methods we don't care about
            Err(err) => {
                // Return an error if we couldn't parse the method
                Some(Self::create_revert_outcome(
                    format!("Invalid Bitcoin method: {}", err),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ))
            }
        }
    }

    /// Check to see if any of the broadcast storage slots are locked
    fn handle_lock_checks(
        &mut self,
        context: &mut EvmContext<impl Database>,
        inputs: &CallInputs,
    ) -> Option<CallOutcome> {
        // get current btc block height
        let current_btc_block_height = match self.btc_client.get_block_height() {
            Ok(height) => height,
            Err(err) => {
                warn!("ERROR: Failed to get current btc block height: {}", err);
                return Some(Self::create_revert_outcome(
                    format!("Failed to get current btc block height: {}", err),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ));
            }
        };

        // check if any of the storage slots in broadcast_accessed_storage are locked
        match self.storage_slot_provider.batch_get_locked_status(
            &self.cache.broadcast_accessed_storage,
            context.env.block.number.saturating_to(),
            current_btc_block_height,
        ) {
            Ok(batch_response) => {
                for response in batch_response.slots {
                    debug!("GetSlotStatusResponse: {:?}", response);

                    let status = match Status::try_from(response.status) {
                        Ok(status) => status,
                        Err(_) => {
                            warn!("Unknown status value: {}", response.status);
                            continue;
                        }
                    };

                    match status {
                        Status::Unknown => {
                            warn!("WARNING: Status::Unknown returned from sentinel");
                        }
                        Status::Locked => {
                            debug!("Storage slot is locked");
                            // Clear revert cache on locked status
                            self.slot_revert_cache.clear();

                            // CRITICAL: Always revert state changes in journal when a lock is detected
                            if let Some(checkpoint) = self.checkpoint {
                                context.journaled_state.checkpoint_revert(checkpoint);
                            } else {
                                // No checkpoint available, this is usually not good and a potential edge case
                                warn!("WARNING: No checkpoint available for reversion");
                            }

                            return Some(Self::create_revert_outcome(
                                "Storage slot is locked".to_string(),
                                inputs.gas_limit,
                                inputs.return_memory_offset.clone(),
                            ));
                        }
                        Status::Unlocked => {
                            debug!("Storage slot is unlocked");
                        }
                        Status::Reverted => {
                            debug!("Storage slot to be reverted");
                            self.handle_revert_status(response);
                        }
                    }
                }
                None
            }
            Err(err) => {
                warn!("WARNING: Failed to get lock status from provider: {}", err);
                Some(Self::create_revert_outcome(
                    format!("Failed to get lock status from provider: {}", err),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ))
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
        let storage_slot = StorageSlot::new_changed(revert_value, current_value);
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
    fn call_end_inner(
        &mut self,
        context: &mut EvmContext<impl Database>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        // For all cases where a BTC precompile is not involved, there could be a SSTORE operation. Check locks
        if inputs.target_address != self.cache.bitcoin_precompile_address {
            // CHECK LOCKS FOR ANY SSTORE IN ANY TX
            // Process storage journal entries before checking locks
            self.process_storage_journal_entries(context);

            match self.handle_lock_checks(context, inputs) {
                Some(revert_outcome) => {
                    // clear checkpoint after reverting
                    self.checkpoint = None;

                    return revert_outcome;
                }
                None => return outcome,
            }
        }
        debug!("----- precompile call end hook -----");

        // Update the btc tx data cache
        match BitcoinMethod::try_from(&inputs.input) {
            Ok(BitcoinMethod::BroadcastTransaction) => {
                debug!("-> Broadcast call end hook");
                self.handle_cache_btc_data(inputs, &outcome)
                    .unwrap_or(outcome)
            }
            Ok(_) => outcome, // Other methods we don't care about
            Err(err) => Self::create_revert_outcome(
                format!("Invalid Bitcoin method: {}", err),
                inputs.gas_limit,
                outcome.memory_offset,
            ),
        }
    }

    /// Cache the broadcast btc precompile result for future use in lock storage enforcement
    fn handle_cache_btc_data(
        &mut self,
        inputs: &CallInputs,
        outcome: &CallOutcome,
    ) -> Option<CallOutcome> {
        // only update if call was successful
        if outcome.result.result != InstructionResult::Return {
            debug!("Broadcast btc precompile execution failed");
            return Some(Self::create_revert_outcome(
                "Broadcast btc precompile execution failed".to_string(),
                inputs.gas_limit,
                outcome.memory_offset.clone(),
            ));
        }

        let broadcast_txid = outcome.result.output[..32].to_vec();
        let broadcast_block = u64::from_be_bytes(outcome.result.output[32..40].try_into().unwrap());

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

impl<DB> Inspector<DB> for SovaInspector
where
    DB: reth_revm::Database,
{
    fn initialize_interp(&mut self, _interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        // Reset accessed storage tracking at the start of interpretation
        self.cache.clear_cache();

        // Reset slot revert cache
        self.slot_revert_cache.clear();

        // Create a checkpoint if one doesn't exist yet
        if self.checkpoint.is_none() {
            self.checkpoint = Some(context.journaled_state.checkpoint());
        }
    }

    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        // Create a checkpoint if there isnt one already
        if self.checkpoint.is_none() {
            self.checkpoint = Some(context.journaled_state.checkpoint());
        }

        self.call_inner(context, inputs)
    }

    fn call_end(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        self.call_end_inner(context, inputs, outcome)
    }
}

pub trait WithInspector {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>>;
}
