mod error;
mod provider;
mod storage_cache;

use error::SlotProviderError;
use provider::StorageSlotProvider;

use sova_sentinel_proto::proto::{get_slot_status_response::Status, GetSlotStatusResponse};

pub use provider::SlotProvider;
pub use storage_cache::{AccessedStorage, BroadcastResult, StorageCache};

use std::{str::FromStr, sync::Arc, collections::BTreeMap};
use core::ops::Range;

use parking_lot::RwLock;

use alloy_primitives::{Address, Bytes, U256};

use reth_revm::{
    context::JournalTr, context_interface::{journaled_state::JournalCheckpoint, ContextTr}, inspector::{Inspector, JournalExt}, interpreter::{
        CallInputs, CallOutcome, CreateInputs, CreateOutcome, Gas, InstructionResult, Interpreter, InterpreterResult
    }, Database, DatabaseCommit, DatabaseRef, JournalEntry
};
use reth_tasks::TaskExecutor;
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

/// Our custom implementation to track storage for Bitcoin transactions
pub struct SovaInspector {
    /// accessed storage cache
    pub cache: StorageCache,
    /// client for calling lock storage service
    pub storage_slot_provider: Arc<StorageSlotProvider>,
    /// btc client
    btc_client: Arc<BitcoinClient>,
    /// transition state for applying slot reverts  
    pub slot_revert_cache: Vec<(Address, BTreeMap<U256, U256>)>,
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

    /// Clear all storage data for a new block
    fn clear_cache(&mut self) {
        self.cache.clear_cache();
        self.slot_revert_cache.clear();
    }

    /// Unlock all revereted storage slots and lock all accessed storage slots at end of execution
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
                self.storage_slot_provider.batch_lock_slots(
                    accessed_storage.clone(),
                    locked_block_number,
                    btc_block,
                    btc_txid.clone(),
                )?;
            }
        }

        self.clear_cache();

        Ok(())
    }

    /// Process storage changes from journal entries and update accessed storage cache
    fn process_storage_journal_entries<CTX: ContextTr<Journal: JournalExt> + DatabaseRef>(
        &mut self, 
        context: &CTX,
    ) {
        // Clear the broadcast accessed storage before processing
        self.cache.broadcast_accessed_storage.0.clear();

        // Access journal directly
        for journal_entries in context.journal_ref().journal().iter() {
            for entry in journal_entries.iter() {
                if let JournalEntry::StorageChanged {
                    address,
                    key,
                    had_value,
                } = entry
                {
                    // Try to get the current value from state
                    let value = match context.db_ref().basic(address) {
                        Ok(Some(account)) => {
                            match context.db_ref().storage(address, key) {
                                Ok(slot) => slot,
                                _ => U256::ZERO,
                            }
                        },
                        _ => U256::ZERO,
                    };

                    let storage_change = StorageChange {
                        key: *key,
                        value,
                        had_value: Some(*had_value),
                    };

                    // Record the storage change
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
                gas: Gas::new(gas_limit),
            },
            memory_offset,
        }
    }

    /// Triggered at the beginning of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode.
    /// This inspector hook is primarily used for storage slot lock enforcement.
    /// Any cached storage access prior to a broadcast btc tx CALL will be checked for a lock.
    fn call_inner<CTX: ContextTr<Journal: JournalExt> + DatabaseRef>(
        &mut self,
        context: &mut CTX,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        // Only do checks for calls to the Bitcoin precompile address
        if inputs.target_address == self.cache.bitcoin_precompile_address {
            let data = &inputs.input;
            
            // Parse the method from call data
            if let Ok(method) = BitcoinMethod::try_from(&data.to_vec()[..]) {
                // Only check locks for BroadcastTransaction calls
                if method == BitcoinMethod::BroadcastTransaction {
                    // Process any storage changes that have happened since the last journal checkpoint
                    self.process_storage_journal_entries(context);
                    
                    // Check if any slots are locked and return revert if needed
                    return self.handle_lock_checks(context, inputs);
                }
            }
        }
        
        None
    }

    /// Check to see if any of the broadcast storage slots are locked
    fn handle_lock_checks<CTX: ContextTr<Journal: JournalExt>>(
        &mut self,
        context: &mut CTX,
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

        // Check if any of the storage slots in broadcast_accessed_storage are locked
        let block_number = context.env().block.number;
        match self.storage_slot_provider.batch_get_locked_status(
            &self.cache.broadcast_accessed_storage,
            block_number.saturating_to(),
            current_btc_block_height,
        ) {
            Ok(responses) => {
                // Loop through responses and look for locks
                for response in responses {
                    match response.status() {
                        Status::Locked => {
                            // It's locked by someone else, revert the transaction
                            warn!(
                                "REVERTED: Slot locked by tx {}, height {} (this tx height: {})",
                                hex::encode(&response.bitcoin_txid),
                                response.bitcoin_block_height,
                                current_btc_block_height
                            );
                            
                            return Some(Self::create_revert_outcome(
                                format!(
                                    "Slot already locked by tx {} at btc height {} (current height: {})",
                                    hex::encode(&response.bitcoin_txid),
                                    response.bitcoin_block_height,
                                    current_btc_block_height
                                ),
                                inputs.gas_limit,
                                inputs.return_memory_offset.clone(),
                            ));
                        }
                        Status::LockedForRevert => {
                            // Handle reverting to previous values
                            self.handle_revert_status(response);
                        }
                        _ => {
                            // Not locked, continue
                        }
                    }
                }
            }
            Err(err) => {
                warn!("ERROR: Failed to get slot status: {}", err);
                return Some(Self::create_revert_outcome(
                    format!("Failed to get slot status: {}", err),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ));
            }
        }
        
        None
    }

    fn handle_revert_status(&mut self, response: GetSlotStatusResponse) {
        // Parse contract address
        let address = Address::from_str(&response.contract_address)
            .expect("Invalid contract address from sentinel");

        // Convert slot index bytes to U256 key
        let mut key_bytes = [0u8; 32];
        key_bytes[32 - response.slot_index.len()..].copy_from_slice(&response.slot_index);
        let key = U256::from_be_bytes(key_bytes);

        // Convert revert value bytes to U256
        let mut revert_bytes = [0u8; 32];
        revert_bytes[32 - response.revert_value.len()..].copy_from_slice(&response.revert_value);
        let revert_value = U256::from_be_bytes(revert_bytes);

        // Find or create storage entry for this address
        let storage_entry = self.slot_revert_cache.iter_mut()
            .find(|(addr, _)| *addr == address);
        
        if let Some((_, storage)) = storage_entry {
            // Update existing storage entry
            storage.insert(key, revert_value);
        } else {
            // Create new storage entry
            let mut storage_map = BTreeMap::new();
            storage_map.insert(key, revert_value);
            self.slot_revert_cache.push((address, storage_map));
        }
    }

    /// Triggered at the end of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode
    /// This inspector hook is primarily used for locking accessed
    /// storage slots after a successful bitcoin transaction broadcast
    fn call_end_inner<CTX: ContextTr<Journal: JournalExt> + DatabaseRef>(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        // Only care about calls to Bitcoin precompile address that succeeded
        if inputs.target_address == self.cache.bitcoin_precompile_address && !outcome.result.is_revert() {
            let data = &inputs.input;
            
            // Parse the method from call data
            if let Ok(method) = BitcoinMethod::try_from(&data.to_vec()[..]) {
                // Only process broadcast transactions
                if method == BitcoinMethod::BroadcastTransaction {
                    // Process any storage changes that happened during this call
                    self.process_storage_journal_entries(context);
                    
                    // Handle broadcast result
                    if outcome.result.output.len() >= 40 {
                        // First 32 bytes are the txid, next 8 bytes are the block height
                        let btc_txid = outcome.result.output[0..32].to_vec();
                        let btc_block = u64::from_be_bytes(
                            outcome.result.output[32..40].try_into().unwrap_or([0; 8]),
                        );
                        
                        // set broadcast txid and block in broadcast result
                        let broadcast_result = BroadcastResult {
                            txid: Some(btc_txid),
                            block: Some(btc_block),
                        };

                        // Commit the broadcast storage to block storage and lock data
                        self.cache.commit_broadcast(broadcast_result);
                    }
                }
            }
        }
    }
}

impl<CTX> Inspector<CTX> for SovaInspector
where
    CTX: ContextTr<Journal: JournalExt> + DatabaseRef + DatabaseCommit
{
    fn initialize_interp(&mut self, _interp: &mut Interpreter, context: &mut CTX) {
        // Ensure clean cache
        self.clear_cache();

        // Create a checkpoint if one doesn't exist yet
        if self.checkpoint.is_none() {
            self.checkpoint = Some(context.journal().checkpoint());
        }
    }

    fn call(
        &mut self,
        context: &mut CTX,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        // Create a checkpoint if there isnt one already
        if self.checkpoint.is_none() {
            self.checkpoint = Some(context.journal().checkpoint());
        }

        self.call_inner(context, inputs)
    }

    fn call_end(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
        outcome: &mut CallOutcome,
    ) {
        self.call_end_inner(context, inputs, outcome);
    }
}

pub trait WithInspector {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>>;
}
