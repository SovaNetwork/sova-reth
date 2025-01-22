use std::collections::{BTreeSet, HashMap, HashSet};

use alloy_primitives::{Address, Bytes, StorageKey};
use reth::revm::{
    interpreter::{CallInputs, CallOutcome, Gas, InstructionResult, InterpreterResult},
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

        None
    }
}
