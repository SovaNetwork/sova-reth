use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use alloy_primitives::{keccak256, Address, Bytes, StorageKey, U256};
use reth::revm::{
    interpreter::{
        opcode, CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
    },
    primitives::EVMError,
    Database, EvmContext, Inspector,
};
use reth_db_api::{models::AddressStorageKey, table::Encode};
use reth_tracing::tracing::{error, info};

use crate::BROADCAST_BTC_TX_ID;

#[derive(Clone, Debug)]
pub struct StorageInspector {
    /// Addresses that should be excluded from tracking (e.g., precompiles)
    pub excluded_addresses: HashSet<Address>,
    /// Maps addresses to their accessed storage slots
    pub accessed_storage: HashMap<Address, BTreeSet<StorageKey>>,
    /// The Bitcoin precompile address
    bitcoin_precompile_address: Address,
}

impl StorageInspector {
    /// Create a new inspector with the given Bitcoin precompile address
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
    ) -> Self {
        Self {
            excluded_addresses: excluded_addresses.into_iter().collect(),
            accessed_storage: HashMap::new(),
            bitcoin_precompile_address,
        }
    }

    /// Check if an address should be tracked
    fn should_track_address(&self, address: Address) -> bool {
        !self.excluded_addresses.contains(&address)
    }

    /// Track a storage access
    fn track_storage_access(&mut self, address: Address, key: StorageKey) {
        info!(
            "Tracking storage access - Address: {:?}, Slot: {:?}",
            address, key
        );
        if self.should_track_address(address) {
            self.accessed_storage
                .entry(address)
                .or_default()
                .insert(key);
        }
    }

    /// Creates a composite key for storage access tracking
    fn storage_key_to_u256(address: Address, slot: StorageKey) -> U256 {
        // Use AddressStorageKey to create the composite key
        let composite = AddressStorageKey((address, slot));
        // Get the encoded bytes
        let encoded = composite.encode();
        // Hash the bytes
        let hash = keccak256(&encoded);
        // Convert the hash to U256
        U256::from_be_bytes(hash.into())
    }

    /// Check if a storage slot is locked by reading the slot's state
    fn is_slot_locked<DB: Database>(
        &self,
        context: &mut EvmContext<DB>,
        address: Address,
        slot: StorageKey,
    ) -> bool {
        let key_u256 = Self::storage_key_to_u256(address, slot);

        info!(
            "Checking lock for address: {:?}, slot: {:?}, composite key: {:?}",
            address, slot, key_u256
        );

        // Use sload through journaled state to get the lock status
        if let Ok(value) =
            context
                .inner
                .journaled_state
                .sload(address, key_u256, &mut context.inner.db)
        {
            let is_locked = value.data == U256::from(1);
            info!(
                "Lock status for slot {:?}: is_locked={}, value={:?}",
                slot, is_locked, value.data
            );
            is_locked
        } else {
            error!("Error reading lock status. ");
            false
        }
    }

    /// Lock a storage slot by writing to state
    fn lock_slot<DB: Database>(
        &self,
        context: &mut EvmContext<DB>,
        address: Address,
        slot: StorageKey,
    ) -> Result<(), EVMError<DB::Error>> {
        let key_u256 = Self::storage_key_to_u256(address, slot);

        info!(
            "Locking slot - address: {:?}, slot: {:?}, composite key: {:?}",
            address, slot, key_u256
        );

        // Use sstore through journaled state to set the lock
        context.inner.journaled_state.sstore(
            address,
            key_u256,
            U256::from(1),
            &mut context.inner.db,
        )?;

        Ok(())
    }
}

impl<DB> Inspector<DB> for StorageInspector
where
    DB: Database,
{
    fn call(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        info!("----- call hook -----");
        if inputs.target_address == self.bitcoin_precompile_address {
            info!("Bitcoin precompile called");
            let input_data = inputs.input.clone();
            let method_selector =
                u32::from_be_bytes([input_data[0], input_data[1], input_data[2], input_data[3]]);

            if method_selector == BROADCAST_BTC_TX_ID {
                info!("----- broadcast call hook -----");
                // Check if any accessed slots are locked
                for (address, slots) in &self.accessed_storage {
                    for slot in slots {
                        if self.is_slot_locked(context, *address, *slot) {
                            // Return error outcome if any slot is locked
                            return Some(CallOutcome {
                                result: InterpreterResult {
                                    result: InstructionResult::Revert,
                                    output: Bytes::from(
                                        "Storage slot is locked by an unconfirmed Bitcoin transaction",
                                    ),
                                    gas: Gas::new_spent(inputs.gas_limit),
                                },
                                memory_offset: inputs.return_memory_offset.clone(),
                            });
                        }
                    }
                }
            }
        }

        None
    }

    fn call_end(
        &mut self,
        context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        info!("----- call end hook -----");
        if inputs.target_address == self.bitcoin_precompile_address {
            info!("Bitcoin precompile called");
            let input_data = inputs.input.clone();
            let method_selector =
                u32::from_be_bytes([input_data[0], input_data[1], input_data[2], input_data[3]]);

            if method_selector == BROADCAST_BTC_TX_ID
                && outcome.result.result == InstructionResult::Return
            {
                // Lock all accessed slots if the call was successful
                for (address, slots) in &self.accessed_storage {
                    for slot in slots {
                        match self.lock_slot(context, *address, *slot) {
                            Ok(_) => {
                                // slot locking succeeded
                                info!(
                                    "Successfully locked slot - address: {:?}, slot: {:?}",
                                    address, slot
                                );
                            }
                            Err(_) => {
                                error!(
                                    "Failed to lock slot - address: {:?}, slot: {:?}",
                                    address, slot,
                                );

                                // Return error outcome, slot locking failed
                                return CallOutcome {
                                    result: InterpreterResult {
                                        result: InstructionResult::Revert,
                                        output: Bytes::from("Failed to lock storage slot"),
                                        gas: outcome.result.gas,
                                    },
                                    memory_offset: outcome.memory_offset,
                                };
                            }
                        }
                    }
                }
            }
        }

        let _ = context;
        let _ = inputs;
        outcome
    }

    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        // track storage writes
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);
                self.track_storage_access(address, key);
            }
        }
    }
}

pub trait WithInspector {
    fn get_inspector(&self) -> &Arc<Mutex<StorageInspector>>;
}
