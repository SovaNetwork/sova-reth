mod provider;
mod storage_cache;

use bitcoin::consensus::deserialize;
use provider::{ProviderError, SlotProvider, StorageSlotProvider};
use reth_tasks::TaskExecutor;
use storage_cache::StorageCache;

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

pub struct SovaInspector {
    /// accessed storage cache
    cache: StorageCache,
    /// client for calling external storage service
    storage_slot_provider: StorageSlotProvider,
}

impl SovaInspector {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
        sentinel_url: String,
        task_executor: TaskExecutor,
    ) -> Result<Self, ProviderError> {
        let storage_slot_provider = StorageSlotProvider::new(sentinel_url, task_executor)?;

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
            Ok(value) => return Ok(value.data),
            Err(err) => return Err(err),
        };
    }
}

impl<DB> Inspector<DB> for SovaInspector
where
    DB: reth_revm::Database,
{
    /// Called at beginning of each step of the interpreter
    fn step(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        // cache storage access for reference if there is a btc tx broadcast in this tx
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);

                // get the previous value
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

    /// Called at beginning of each step of the interpreter
    fn step_end(&mut self, interp: &mut Interpreter, context: &mut EvmContext<DB>) {
        // cache storage access for reference if there is a btc tx broadcast in this tx
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);

                // get the new value
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
                    if let Ok(locked) = self.storage_slot_provider.get_locked_status(
                        self.cache.accessed_storage.clone(),
                        context.env.block.number,
                    ) {
                        info!("Locks from provider: {:?}", locked);
                        if !locked {
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
    /// storage slots if a bitcoin boradcast tx precompile executed successfully.
    fn call_end(
        &mut self,
        context: &mut EvmContext<DB>,
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
                        // get bitcoin transaction data
                        let tx: bitcoin::Transaction = match deserialize(outcome.output()) {
                            Ok(tx) => tx,
                            Err(_) => {
                                info!("Inspector: Failed to deserialize bitcoin transaction");
                                return Self::create_revert_outcome(
                                    "Failed to deserialize bitcoin transaction".to_string(),
                                    inputs.gas_limit,
                                    outcome.memory_offset,
                                );
                            }
                        };

                        // Lock all accessed slots if the call was successful
                        if let Err(err) = self.storage_slot_provider.lock_slots(
                            self.cache.accessed_storage.clone(),
                            context.env.block.number,
                            tx.input[0].previous_output.txid,
                            tx.input[0].previous_output.vout,
                        ) {
                            return Self::create_revert_outcome(
                                format!("Failed to lock storage slots: {:?}", err),
                                inputs.gas_limit,
                                outcome.memory_offset,
                            );
                        }
                    } else {
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
