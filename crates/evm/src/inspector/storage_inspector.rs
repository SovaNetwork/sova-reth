use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use alloy_primitives::{Address, Bytes, StorageKey};
use reth::{
    providers::{providers::StaticFileProvider, ProviderFactory},
    revm::{
        interpreter::{
            opcode, CallInputs, CallOutcome, Gas, InstructionResult, Interpreter, InterpreterResult,
        },
        Database, EvmContext, Inspector,
    },
};
use reth_db::{open_db_read_only, DatabaseEnv};
use reth_node_api::NodeTypesWithDBAdapter;
use reth_node_ethereum::EthereumNode;
use reth_tracing::tracing::{error, info};

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

                // get read access to the database
                let db_path = PathBuf::from("./data");
                let db = match open_db_read_only(db_path.join("db").as_path(), Default::default()) {
                    Ok(db) => db,
                    Err(err) => {
                        error!("Failed to open database: {}", err);
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::from("Failed to open database"),
                                gas: Gas::new_spent(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }
                };

                let chain_spec = reth_chainspec::DEV.clone();
                let static_provider =
                    match StaticFileProvider::read_only(db_path.join("static_files"), true) {
                        Ok(provider) => provider,
                        Err(err) => {
                            error!("Failed to create static file provider: {}", err);
                            return Some(CallOutcome {
                                result: InterpreterResult {
                                    result: InstructionResult::Revert,
                                    output: Bytes::from("Failed to create static file provider"),
                                    gas: Gas::new_spent(inputs.gas_limit),
                                },
                                memory_offset: inputs.return_memory_offset.clone(),
                            });
                        }
                    };

                let factory = ProviderFactory::<
                    NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>,
                >::new(Arc::new(db), chain_spec, static_provider);

                // get database provider
                let _provider = match factory.provider_rw() {
                    Ok(provider) => provider,
                    Err(err) => {
                        error!("Failed to create provider: {}", err);
                        return Some(CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::from("Failed to create provider"),
                                gas: Gas::new_spent(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        });
                    }
                };

                // // Check if accessed slots are locked
                // for slot in self.accessed_storage.iter() {
                //     let lock = provider.get_storage_slot_lock(slot);

                //     match lock {
                //         Ok(Some(value)) => {
                //             println!("TXID is: {}", value.txid);
                //                 return Some(CallOutcome {
                //                         result: InterpreterResult {
                //                             result: InstructionResult::Revert,
                //                             output: Bytes::from(
                //                                 "Storage slot is locked by an unconfirmed Bitcoin transaction",
                //                             ),
                //                             gas: Gas::new_spent(inputs.gas_limit),
                //                         },
                //                         memory_offset: inputs.return_memory_offset.clone(),
                //                     });
                //         }
                //         Ok(None) => {
                //             println!("No UTXO was found for key {}", key);
                //             // proceed with precompile execution
                //         }
                //         Err(err) => {
                //             println!("An error occurred reading UTXO: {}", err);
                //             // TODO(powvt): determine outcome here
                //         }
                //     }
                // }
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

                // get write access to the database
                let db_path = PathBuf::from("./data");
                let db = match open_db_read_only(db_path.join("db").as_path(), Default::default()) {
                    Ok(db) => db,
                    Err(err) => {
                        error!("Failed to open database: {}", err);
                        return CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::from("Failed to open database"),
                                gas: Gas::new_spent(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        };
                    }
                };

                let chain_spec = reth_chainspec::DEV.clone();
                let static_provider =
                    match StaticFileProvider::read_only(db_path.join("static_files"), true) {
                        Ok(provider) => provider,
                        Err(err) => {
                            error!("Failed to create static file provider: {}", err);
                            return CallOutcome {
                                result: InterpreterResult {
                                    result: InstructionResult::Revert,
                                    output: Bytes::from("Failed to create static file provider"),
                                    gas: Gas::new_spent(inputs.gas_limit),
                                },
                                memory_offset: inputs.return_memory_offset.clone(),
                            };
                        }
                    };

                let factory = ProviderFactory::<
                    NodeTypesWithDBAdapter<EthereumNode, Arc<DatabaseEnv>>,
                >::new(Arc::new(db), chain_spec, static_provider);

                // get database provider
                let _provider = match factory.provider_rw() {
                    Ok(provider) => provider,
                    Err(err) => {
                        error!("Failed to create provider: {}", err);
                        return CallOutcome {
                            result: InterpreterResult {
                                result: InstructionResult::Revert,
                                output: Bytes::from("Failed to create provider"),
                                gas: Gas::new_spent(inputs.gas_limit),
                            },
                            memory_offset: inputs.return_memory_offset.clone(),
                        };
                    }
                };

                // convert any accessed storage to locked slots using the precompile return data
                // write to database here
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
