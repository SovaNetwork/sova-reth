use std::{collections::{BTreeSet, HashMap, HashSet}, sync::Arc};

use alloy_primitives::{Address, Bytes, StorageKey, B256};
use parking_lot::RwLock;
use reth_revm::{interpreter::{opcode, CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult}, Database, EvmContext, Inspector};
use reth_tracing::tracing::info;

/// Maps storage slots to Bitcoin transaction hashes that locked them
#[derive(Default, Debug)]
pub struct UnconfirmedBtcStorageDb {
    /// Maps storage slots to the Bitcoin transaction hash that locked them 
    locked_slots: HashMap<StorageSlotAddress, B256>,
    /// Maps Bitcoin transaction hashes to the slots they've locked
    tx_slots: HashMap<B256, Vec<StorageSlotAddress>>,
}

impl UnconfirmedBtcStorageDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lock_slot(&mut self, slot: StorageSlotAddress, tx_hash: B256) {
        self.locked_slots.insert(slot.clone(), tx_hash);
        self.tx_slots.entry(tx_hash).or_default().push(slot);
    }

    pub fn is_slot_locked(&self, slot: &StorageSlotAddress) -> bool {
        self.locked_slots.contains_key(slot)
    }

    pub fn unlock_slots_for_transaction(&mut self, tx_hash: B256) {
        if let Some(slots) = self.tx_slots.remove(&tx_hash) {
            for slot in slots {
                self.locked_slots.remove(&slot);
            }
        }
    }
}

/// Storage slot identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct StorageSlotAddress {
    pub address: Address,
    pub key: StorageKey,
}

impl StorageSlotAddress {
    pub fn new(address: Address, key: StorageKey) -> Self {
        Self { address, key }
    }
}

/// An Inspector that tracks storage access and Bitcoin precompile interactions
#[derive(Debug)]
pub struct BitcoinStorageInspector {
    /// Addresses that should be excluded from tracking (e.g., precompiles)
    pub excluded_addresses: HashSet<Address>,
    /// Maps addresses to their accessed storage slots
    pub accessed_storage: HashMap<Address, BTreeSet<StorageKey>>,
    /// The Bitcoin precompile address
    bitcoin_precompile_address: Address,
    /// Whether the btc broadcast raw tx precompile was called
    pub broadcast_precompile_called: bool,
    /// Storage database for checking locked slots
    pub storage_db: Arc<RwLock<UnconfirmedBtcStorageDb>>,
}

impl BitcoinStorageInspector {
    /// Create a new inspector with the given Bitcoin precompile address
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
        storage_db: Arc<RwLock<UnconfirmedBtcStorageDb>>,
    ) -> Self {
        Self {
            excluded_addresses: excluded_addresses.into_iter().collect(),
            accessed_storage: HashMap::new(),
            bitcoin_precompile_address,
            broadcast_precompile_called: false,
            storage_db,
        }
    }

    /// Check if an address should be tracked
    fn should_track_address(&self, address: Address) -> bool {
        !self.excluded_addresses.contains(&address)
    }

    /// Track a storage access for an address
    fn track_storage_access(&mut self, address: Address, key: StorageKey) {
        if self.should_track_address(address) {
            self.accessed_storage
                .entry(address)
                .or_default()
                .insert(key);
        }
    }
}

impl<DB> Inspector<DB> for BitcoinStorageInspector
where
    DB: Database,
{
    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        info!("----- call hook -----");
        return Some(CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::Revert,
                output: Bytes::from("Storage slot is locked by an unconfirmed Bitcoin transaction"),
                gas: Gas::new_spent(inputs.gas_limit),
            },
            memory_offset: inputs.return_memory_offset.clone(),
        });

        // if inputs.target_address == self.bitcoin_precompile_address {
        //     info!("----- call hook -----");
        //     info!("Bitcoin precompile call inputs: {:?}", inputs);

        //     let input_data = inputs.input.clone();
        //     let method_selector = u32::from_be_bytes([input_data[0], input_data[1], input_data[2], input_data[3]]);

        //     // only check `call_btc_tx_queue()` precompile
        //     if method_selector == 0x00000001 {
        //         info!("Bitcoin precompile call raw data: {:?}", &input_data[4..]);
        //         self.broadcast_precompile_called = true;

        //         // Check if any accessed storage is locked
        //         let storage_db = self.storage_db.read();
        //         for (address, slots) in &self.accessed_storage {
        //             for slot in slots {
        //                 if storage_db.is_slot_locked(&StorageSlotAddress::new(*address, *slot)) {
        //                     // Return reverted tx result
        //                     return Some(CallOutcome {
        //                         result: InterpreterResult {
        //                             result: InstructionResult::Revert,
        //                             output: Bytes::from("Storage slot is locked by an unconfirmed Bitcoin transaction"),
        //                             gas: Gas::new_spent(inputs.gas_limit),
        //                         },
        //                         memory_offset: inputs.return_memory_offset.clone(),
        //                     });
        //                 }
        //             }
        //         }
        //     }
        // }
        // None
    }

    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        if inputs.target_address == self.bitcoin_precompile_address {
            info!("----- call end hook -----");
            info!("Bitcoin precompile call result: {:?}", outcome);
        }
        outcome
    }

    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        match interp.current_opcode() {
            // Track storage operations
            opcode::SLOAD | opcode::SSTORE => {
                if let Ok(slot) = interp.stack().peek(0) {
                    let address = interp.contract.target_address;
                    let key = StorageKey::from(slot);
                    self.track_storage_access(address, key);
                }
            }
            _ => (),
        }
    }
}