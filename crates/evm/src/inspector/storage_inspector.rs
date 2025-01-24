use std::collections::{BTreeSet, HashMap, HashSet};

use alloy_primitives::{Address, StorageKey};
use reth::revm::{
    interpreter::{opcode, CallInputs, CallOutcome, Interpreter},
    Database, EvmContext, Inspector,
};
use reth_tracing::tracing::info;

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

    fn should_track_address(&self, address: Address) -> bool {
        !self.excluded_addresses.contains(&address)
    }

    fn track_storage_access(&mut self, address: Address, key: StorageKey) {
        if self.should_track_address(address) {
            self.accessed_storage
                .entry(address)
                .or_default()
                .insert(key);
        }
    }
}

impl<DB> Inspector<DB> for StorageInspector
where
    DB: Database,
{
    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        info!("----- call hook -----");
        if inputs.target_address == self.bitcoin_precompile_address {
            info!("Bitcoin precompile called");
            let input_data = inputs.input.clone();
            let method_selector =
                u32::from_be_bytes([input_data[0], input_data[1], input_data[2], input_data[3]]);

            if method_selector == 0x00000001 {
                info!("----- broadcast call hook -----");

                // Are any of the accessed slots locked?
                // If so, return an revert InstructionResult
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

            if method_selector == 0x00000001 {
                info!("----- broadcast call end hook -----");

                // Lock any SSTORE slots that were touched
                // prior to the BTC broadcast call
            }
        }

        let _ = context;
        let _ = inputs;
        outcome
    }

    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        if interp.current_opcode() == opcode::SSTORE {
            if let Ok(slot) = interp.stack().peek(0) {
                let address = interp.contract.target_address;
                let key = StorageKey::from(slot);
                self.track_storage_access(address, key);
            }
        }
    }
}
