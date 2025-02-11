mod provider;
mod storage_cache;

pub use provider::SlotProvider;
use provider::{SlotProviderError, StorageSlotProvider};
use reth_tasks::TaskExecutor;
pub use storage_cache::{AccessedStorage, BroadcastResult, StorageCache};

use core::ops::Range;
use std::sync::Arc;

use parking_lot::RwLock;

use alloy_primitives::{Address, Bytes, StorageKey, U256};

use reth_revm::{
    interpreter::{
        opcode, CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    primitives::EVMError,
    Database, EvmContext, Inspector,
};
use reth_tracing::tracing::info;

use crate::precompiles::{BitcoinMethod, MethodError};

pub struct SovaInspector {
    /// accessed storage cache
    pub cache: StorageCache,
    /// client for calling external storage service
    pub storage_slot_provider: Arc<StorageSlotProvider>,
}

impl SovaInspector {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
        sentinel_url: String,
        task_executor: TaskExecutor,
    ) -> Result<Self, SlotProviderError> {
        let storage_slot_provider =
            Arc::new(StorageSlotProvider::new(sentinel_url, task_executor)?);

        Ok(Self {
            cache: StorageCache::new(bitcoin_precompile_address, excluded_addresses),
            storage_slot_provider,
        })
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

    /// Get the value of a storage slot using journaled state sload
    fn get_slot_value<DB: Database>(
        &self,
        context: &mut EvmContext<DB>,
        address: Address,
        key: U256,
    ) -> Result<U256, EVMError<DB::Error>> {
        match context
            .inner
            .journaled_state
            .sload(address, key, &mut context.inner.db)
        {
            Ok(value) => Ok(value.data),
            Err(err) => Err(err),
        }
    }

    /// Call storage slot provider to lock slots
    pub fn lock_accessed_storage_for_btc_tx(
        &mut self,
        block_number: u64,
        accessed_storage: AccessedStorage,
        btc_txid: Vec<u8>,
        btc_block: u64,
    ) -> Result<(), SlotProviderError> {
        self.storage_slot_provider
            .lock_slots(accessed_storage, block_number, btc_txid, btc_block)
    }

    /// Call storage slot provider to check if slots are locked
    fn handle_lock_checks(
        &mut self,
        context: &mut EvmContext<impl Database>,
        inputs: &CallInputs,
    ) -> Option<CallOutcome> {
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

        // check if the new storage slots in broadcast_accessed_storage are already locked
        if let Ok(locked) = self.storage_slot_provider.get_locked_status(
            self.cache.broadcast_accessed_storage.clone(),
            context.env.block.number.saturating_to::<u64>(),
        ) {
            info!("Lock status from provider: {:?}", locked);
            if locked {
                return Some(Self::create_revert_outcome(
                    "Storage slots are locked".to_string(),
                    inputs.gas_limit,
                    inputs.return_memory_offset.clone(),
                ));
            }
        }
        None
    }

    /// Cache the broadcast btc precompile result for future use by ExecutionStrategy
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

    /// Lock all accessed storage slots at end of block
    pub fn lock_accessed_storage_for_block(
        &mut self,
        block_number: u64,
    ) -> Result<(), SlotProviderError> {
        // For each broadcast transaction
        for (broadcast_result, accessed_storage) in self.cache.lock_data.iter() {
            if let (Some(btc_txid), Some(btc_block)) =
                (broadcast_result.txid.as_ref(), broadcast_result.block)
            {
                // Lock the storage with this transaction's details
                self.storage_slot_provider.lock_slots(
                    accessed_storage.clone(),
                    block_number,
                    btc_txid.clone(),
                    btc_block,
                )?;
            }
        }

        // Clear the cache for next block
        self.cache.clear_cache();

        Ok(())
    }

    /// Called at beginning of each step of the interpreter
    /// Cache storage access if there is a btc tx broadcast in this tx
    fn step_inner(&mut self, interp: &mut Interpreter, context: &mut EvmContext<impl Database>) {
        if interp.current_opcode() != opcode::SSTORE {
            return;
        }

        let Ok(slot) = interp.stack().peek(0) else {
            return;
        };

        let address = interp.contract.target_address;
        let key = StorageKey::from(slot);

        // get the previous value and cache it
        match self.get_slot_value(context, address, slot) {
            Ok(previous_value) => {
                self.cache
                    .insert_accessed_storage_before(address, key, previous_value);
            }
            Err(_) => {
                info!("SovaInspector::step_inner(): Failed to get previous storage value. Address: {:?}, Slot: {:?}", address, slot);

                // Set the interpreter result to Revert
                // This is important as storage errors could result in inaccurate sentinel data
                interp.instruction_result = InstructionResult::Revert;
            }
        }
    }

    /// Called at end of each step of the interpreter.
    /// Cache storage access if there is a btc tx broadcast in this tx
    fn step_end_inner(
        &mut self,
        interp: &mut Interpreter,
        context: &mut EvmContext<impl Database>,
    ) {
        if interp.current_opcode() != opcode::SSTORE {
            return;
        }

        let Ok(slot) = interp.stack().peek(0) else {
            return;
        };

        let address = interp.contract.target_address;
        let key = StorageKey::from(slot);

        // get the new value after opcode execution and cache it
        match self.get_slot_value(context, address, slot) {
            Ok(current_value) => {
                self.cache
                    .insert_accessed_storage_after(address, key, current_value);
            }
            Err(_) => {
                info!("SovaInspector::step_end_inner(): Failed to get current storage value. Address: {:?}, Slot: {:?}", address, slot);

                // Set the interpreter result to Revert
                // This is important as storage errors could result in inaccurate sentinel data
                interp.instruction_result = InstructionResult::Revert;
            }
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

        info!("----- call hook -----");
        info!("Bitcoin precompile called");

        match Self::get_btc_precompile_method(&inputs.input) {
            Ok(BitcoinMethod::BroadcastTransaction) => {
                info!("-> Broadcast call hook");
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

    /// Triggered at the end of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode
    /// This inspector hook is primarily used for locking accessed
    /// storage slots if a bitcoin broadcast tx precompile executed successfully.
    fn call_end_inner(&mut self, inputs: &CallInputs, outcome: CallOutcome) -> CallOutcome {
        if inputs.target_address != self.cache.bitcoin_precompile_address {
            return outcome;
        }

        info!("----- call end hook -----");
        info!("Bitcoin precompile called");

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
}

impl<DB> Inspector<DB> for SovaInspector
where
    DB: reth_revm::Database,
{
    fn step(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.step_inner(interp, context);
    }

    fn step_end(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        self.step_end_inner(interp, context);
    }

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
