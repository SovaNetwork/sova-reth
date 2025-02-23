mod provider;
mod storage_cache;

pub use provider::SlotProvider;
use provider::{SlotProviderError, StorageSlotProvider};
use reth_tasks::TaskExecutor;
use sova_sentinel_proto::proto::GetSlotStatusResponse;
pub use storage_cache::{AccessedStorage, BroadcastResult, StorageCache};

use core::ops::Range;
use std::{str::FromStr, sync::Arc};

use parking_lot::RwLock;

use alloy_primitives::{Address, Bytes, U256};

use reth_revm::{
    db::{states::StorageSlot, AccountStatus, StorageWithOriginalValues}, interpreter::{CallInputs, CallOutcome, Gas, InstructionResult, InterpreterResult}, Database, EvmContext, Inspector, JournalEntry, TransitionAccount
};
use reth_tracing::tracing::info;

use crate::{
    precompiles::{BitcoinMethod, MethodError},
    BitcoinClient,
};

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
    /// client for calling external storage service
    pub storage_slot_provider: Arc<StorageSlotProvider>,
    /// btc client
    btc_client: Arc<BitcoinClient>,
    /// transition state for sentinel reverts
    pub slot_revert_cache: Vec<(Address, TransitionAccount)>,
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
        })
    }

    /// Unlock all revereted storage slots and lock all accessed storage slots atend of execution
    pub fn update_sentinel_locks(&mut self, sova_block_number: u64) -> Result<(), SlotProviderError> {
        // get current btc block height
        // TODO: optimize btc block height handling/storage/reference
        let current_btc_block_height = match self.btc_client.get_block_height() {
            Ok(height) => height,
            Err(err) => {
                info!("Failed to get current btc block height: {}", err);
                return Err(SlotProviderError::BitcoinError(err));
            }
        };

        // Handle unlocking of reverted slots
        if !self.slot_revert_cache.is_empty() {
            self.storage_slot_provider
                .unlock_slot(current_btc_block_height, self.slot_revert_cache.clone())?;
        }

        // Handle locking of storage slots for each btc broadcast transaction
        // TODO: different source of block height being used in the lock_slots flow here
        for (broadcast_result, accessed_storage) in self.cache.lock_data.iter() {
            if let (Some(btc_txid), Some(btc_block)) =
                (broadcast_result.txid.as_ref(), broadcast_result.block)
            {
                // Lock the storage with this transaction's details
                self.storage_slot_provider.lock_slots(
                    accessed_storage.clone(),
                    sova_block_number,
                    btc_txid.clone(),
                    btc_block,
                )?;
            }
        }

        // Clear the cache for next block
        self.cache.clear_cache();
        // Clear the revert cache
        self.slot_revert_cache.clear();

        Ok(())
    }
    
    /// Parse the Bitcoin method from input data
    fn get_btc_precompile_method(input: &Bytes) -> Result<BitcoinMethod, MethodError> {
        BitcoinMethod::try_from(input)
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
        if inputs.target_address != self.cache.bitcoin_precompile_address {
            return None;
        }
        info!("----- precompile call hook -----");

        match Self::get_btc_precompile_method(&inputs.input) {
            Ok(BitcoinMethod::BroadcastTransaction) => {
                info!("-> Broadcast call hook");

                // Process sstrore journal entries before checking locks
                for journal_entries in context.journaled_state.journal.iter() {
                    for entry in journal_entries.iter() {
                        if let JournalEntry::StorageChanged {
                            address,
                            key,
                            had_value,
                        } = entry
                        {
                            let value =
                                context.journaled_state.state[address].storage[key].present_value();
                            info!(
                                "Found storage change: key: {}, old_value: {}, new_value: {}, address: {}",
                                key, had_value, value, address
                            );

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

                // always check locks prior to broadcast any btc tx
                self.handle_lock_checks(inputs)
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

    /// Pre broadcast precompile call
    /// Check to see if any of the broadcast storage slots are locked
    fn handle_lock_checks(&mut self, inputs: &CallInputs) -> Option<CallOutcome> {
        // Check if any of the broadcast storage slots are already in block storage
        if self
            .cache
            .block_accessed_storage
            .contains_any(&self.cache.broadcast_accessed_storage)
        {
            info!("Storage slots already accessed in this block");
            return Some(Self::create_revert_outcome(
                "Storage slots already accessed in this block".to_string(),
                inputs.gas_limit,
                inputs.return_memory_offset.clone(),
            ));
        }

        // get current btc block height
        let current_btc_block_height = match self.btc_client.get_block_height() {
            Ok(height) => height,
            Err(err) => {
                info!("Failed to get current btc block height: {}", err);
                return Some(Self::create_revert_outcome(
                    format!("Failed to get current btc block height: {}", err),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ));
            }
        };

        // check if any of the storage slots in broadcast_accessed_storage are locked in the sentinel
        match self.storage_slot_provider.get_locked_status(
            self.cache.broadcast_accessed_storage.clone(),
            current_btc_block_height,
        ) {
            Ok(responses) => {
                for response in responses {
                    info!("GetSlotStatusResponse: {:?}", response);

                    // UNKNOWN
                    if response.status == 0 {
                        info!("Unknown returned from sentinel");
                    }
                    // LOCKED
                    if response.status == 1 {
                        info!("Storage slot is locked");
                        // Clear transition state on any reverts
                        self.slot_revert_cache.clear();

                        return Some(Self::create_revert_outcome(
                            "Storage slot is locked".to_string(),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ));
                    }
                    // UNLOCKED
                    if response.status == 2 {
                        info!("Storage slot is unlocked");
                    }
                    // REVERT
                    if response.status == 3 {
                        info!("Storage slot to be reverted");
                        self.handle_revert_status(response);
                    }
                }
                None
            }
            Err(err) => {
                info!("Failed to get lock status from provider: {}", err);
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

        info!(
            "Creating transition for address {:?}: current_value={:?}, revert_value={:?}",
            address, current_value, revert_value
        );

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
    fn call_end_inner(&mut self, inputs: &CallInputs, outcome: CallOutcome) -> CallOutcome {
        if inputs.target_address != self.cache.bitcoin_precompile_address {
            return outcome;
        }
        info!("----- precompile call end hook -----");

        match Self::get_btc_precompile_method(&inputs.input) {
            Ok(BitcoinMethod::BroadcastTransaction) => {
                info!("-> Broadcast call end hook");
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
        // check if call was successful
        if outcome.result.result != InstructionResult::Return {
            info!("Broadcast btc precompile execution failed");
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
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        self.call_inner(context, inputs)
    }

    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        self.call_end_inner(inputs, outcome)
    }
}

pub trait WithInspector {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>>;
}
