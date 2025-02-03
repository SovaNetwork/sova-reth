use core::ops::Range;
use std::sync::Arc;

use alloy_primitives::{Address, Bytes, StorageKey};
use parking_lot::RwLock;

use reth_revm::{
    interpreter::{
        opcode, CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    EvmContext, Inspector,
};
use reth_tracing::tracing::info;

use crate::{
    inspector::provider::SlotProvider,
    precompile_utils::{BitcoinMethod, MethodError},
};

use super::{provider::StorageSlotProvider, storage_cache::StorageCache};

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
        storage_slot_provider_url: String,
    ) -> Self {
        Self {
            cache: StorageCache::new(bitcoin_precompile_address, excluded_addresses),
            storage_slot_provider: StorageSlotProvider::new(storage_slot_provider_url),
        }
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
}

impl<DB> Inspector<DB> for SovaInspector
where
    DB: reth_revm::Database,
{
    /// Called on each step of the interpreter
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        // optimistically cache storage accesses for if there is a btc tx broadcast
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);
                self.cache.insert_accessed_storage(address, key);
            }
        }
    }

    /// Triggered at the beginning of any execution step that is a
    /// CALL, CALLCODE, DELEGATECALL, or STATICCALL opcode.
    /// This inspector hook is primarily used for storage slot lock enforcement.
    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        info!("----- call hook -----");
        if inputs.target_address == self.cache.bitcoin_precompile_address {
            info!("Bitcoin precompile called");

            match Self::get_btc_precompile_method(&inputs.input) {
                Ok(BitcoinMethod::BroadcastTransaction) => {
                    info!("----- broadcast call hook -----");
                    if let Ok(locks) = self
                        .storage_slot_provider
                        .get_locks(self.cache.accessed_storage.clone())
                    {
                        info!("Locks from provider: {:?}", locks);
                        if locks.iter().any(|&lock| lock == true) {
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
        _context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        info!("----- call end hook -----");
        if inputs.target_address == self.cache.bitcoin_precompile_address {
            info!("Bitcoin precompile called");

            match Self::get_btc_precompile_method(&inputs.input) {
                Ok(BitcoinMethod::BroadcastTransaction) => {
                    info!("----- broadcast call end hook -----");
                    if outcome.result.result == InstructionResult::Return {
                        // Lock all accessed slots if the call was successful
                        if let Err(err) = self
                            .storage_slot_provider
                            .lock_slots(self.cache.accessed_storage.clone())
                        {
                            return Self::create_revert_outcome(
                                format!("Failed to lock storage slots: {}", err),
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