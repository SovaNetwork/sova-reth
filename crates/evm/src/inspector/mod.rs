mod provider;
mod storage_cache;

pub use provider::SlotProvider;
use provider::{ProviderError, StorageSlotProvider};
use reth_tasks::TaskExecutor;
pub use storage_cache::{AccessedStorage, StorageCache};

use core::ops::Range;
use std::sync::Arc;

use alloy_primitives::{Address, Bytes, StorageKey, U256};
use parking_lot::RwLock;

use reth_revm::{
    interpreter::{
        opcode, CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    primitives::EVMError,
    Database, EvmContext, Inspector,
};
use reth_tracing::tracing::info;

use crate::precompiles::{BitcoinMethod, MethodError};

#[derive(Clone, Default)]
pub struct BroadcastResult {
    pub txid: Option<Vec<u8>>,
    pub block: Option<u64>,
}

pub struct SovaInspector {
    /// accessed storage cache
    pub cache: StorageCache,
    /// client for calling external storage service
    pub storage_slot_provider: Arc<StorageSlotProvider>,
    /// Result of the last broadcast call
    pub broadcast_result: BroadcastResult,
}

impl SovaInspector {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
        sentinel_url: String,
        task_executor: TaskExecutor,
    ) -> Result<Self, ProviderError> {
        let storage_slot_provider =
            Arc::new(StorageSlotProvider::new(sentinel_url, task_executor)?);

        Ok(Self {
            cache: StorageCache::new(bitcoin_precompile_address, excluded_addresses),
            storage_slot_provider,
            broadcast_result: BroadcastResult::default(),
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

    /// Handle broadcast result and lock slots if necessary, then clear state
    pub fn handle_broadcast(
        &mut self,
        block_number: u64,
        accessed_storage: AccessedStorage,
        btc_info: BroadcastResult,
    ) -> Result<(), ProviderError> {
        if let (Some(txid), Some(block)) = (btc_info.txid, btc_info.block) {
            self.storage_slot_provider
                .lock_slots(accessed_storage, block_number, txid, block)?;
        }

        Ok(())
    }
}

impl<DB> Inspector<DB> for SovaInspector
where
    DB: reth_revm::Database,
{
    /// Called at beginning of each step of the interpreter
    /// Cache storage access if there is a btc tx broadcast in this tx
    fn step(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);

                // get the previous value and cache it
                let previous_value = match self.get_slot_value(context, address, slot) {
                    Ok(value) => value,
                    Err(_) => {
                        panic!("Failed to get previous storage value");
                    }
                };

                self.cache
                    .insert_accessed_storage_before(address, key, previous_value);
            }
        }
    }

    /// Called at end of each step of the interpreter.
    /// Cache storage access if there is a btc tx broadcast in this tx
    fn step_end(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);

                // get the new value after opcode execution and cache it
                let current_value = match self.get_slot_value(context, address, slot) {
                    Ok(value) => value,
                    Err(_) => {
                        panic!("Failed to get current storage value");
                    }
                };

                self.cache
                    .insert_accessed_storage_after(address, key, current_value);
            }
        }
    }

    /// Triggered at the beginning of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode.
    /// This inspector hook is primarily used for storage slot lock enforcement.
    /// Any cached storage access prior to a broadcast btc tx CALL will be checked for a lock.
    /// Only one btc broadcast tx call is allowed per tx.
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        if inputs.target_address == self.cache.bitcoin_precompile_address {
            info!("----- call hook -----");
            info!("Bitcoin precompile called");

            match Self::get_btc_precompile_method(&inputs.input) {
                Ok(BitcoinMethod::BroadcastTransaction) => {
                    info!("----- broadcast call hook -----");
                    // check if there has already been a broadcast in this tx
                    if self.broadcast_result.txid.is_some() {
                        info!("Broadcast transaction already called");
                        return Some(Self::create_revert_outcome(
                            "Broadcast transaction already called".to_string(),
                            inputs.gas_limit,
                            inputs.return_memory_offset.clone(),
                        ));
                    }
                    // check if storage slots are locked
                    if let Ok(locked) = self.storage_slot_provider.get_locked_status(
                        self.cache.accessed_storage.clone(),
                        context.env.block.number,
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
                }
                Ok(_) => {} // Other methods we don't care about
                Err(err) => {
                    // Return an error if we couldn't parse the method
                    return Some(Self::create_revert_outcome(
                        format!("Invalid Bitcoin method: {}", err),
                        inputs.gas_limit,
                        inputs.return_memory_offset.clone(),
                    ));
                }
            }
        }

        None
    }

    /// Triggered at the end of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode
    /// This inspector hook is primarily used for locking accessed
    /// storage slots if a bitcoin broadcast tx precompile executed successfully.
    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        if inputs.target_address == self.cache.bitcoin_precompile_address {
            info!("----- call end hook -----");
            info!("Bitcoin precompile called");

            match Self::get_btc_precompile_method(&inputs.input) {
                Ok(BitcoinMethod::BroadcastTransaction) => {
                    info!("----- broadcast call end hook -----");
                    if outcome.result.result == InstructionResult::Return {
                        let broadcast_txid = outcome.result.output[..32].to_vec();
                        let broadcast_block =
                            u64::from_be_bytes(outcome.result.output[32..40].try_into().unwrap());

                        // set broadcast txid and block in broadcast result
                        self.broadcast_result = BroadcastResult {
                            txid: Some(broadcast_txid),
                            block: Some(broadcast_block),
                        };
                    } else {
                        info!("Broadcast transaction failed");
                        return Self::create_revert_outcome(
                            "Broadcast transaction failed".to_string(),
                            inputs.gas_limit,
                            outcome.memory_offset,
                        );
                    }
                }
                Ok(_) => {} // Other methods we don't care about
                Err(err) => {
                    return Self::create_revert_outcome(
                        format!("Invalid Bitcoin method: {}", err),
                        inputs.gas_limit,
                        outcome.memory_offset,
                    );
                }
            }
        }

        outcome
    }
}

pub trait WithInspector {
    fn with_inspector(&self) -> &Arc<RwLock<SovaInspector>>;
}
