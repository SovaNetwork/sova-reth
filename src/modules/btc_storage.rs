use std::collections::{BTreeSet, HashMap, HashSet};

use alloy_primitives::{Address, StorageKey, B256};
use reth_revm::{interpreter::{opcode, Interpreter}, Database, EvmContext, Inspector};

/// Maps storage slots to Bitcoin transaction hashes that locked them
#[derive(Default)]
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

    pub fn lock_slot(&mut self, slot: StorageSlotAddress, btc_tx_hash: B256) {
        self.locked_slots.insert(slot.clone(), btc_tx_hash);
        self.tx_slots.entry(btc_tx_hash).or_default().push(slot);
    }

    pub fn is_slot_locked(&self, slot: &StorageSlotAddress) -> bool {
        self.locked_slots.contains_key(slot)
    }

    pub fn unlock_slots_for_transaction(&mut self, btc_tx_hash: B256) {
        if let Some(slots) = self.tx_slots.remove(&btc_tx_hash) {
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
#[derive(Debug, Default)]
pub struct BitcoinStorageInspector {
    /// Addresses that should be excluded from tracking (e.g., precompiles)
    excluded_addresses: HashSet<Address>,
    /// Maps addresses to their accessed storage slots
    accessed_storage: HashMap<Address, BTreeSet<StorageKey>>,
    /// Whether a Bitcoin precompile was called in this transaction
    bitcoin_precompile_called: bool,
    /// The Bitcoin precompile address
    bitcoin_precompile_address: Address,
}

impl BitcoinStorageInspector {
    /// Create a new inspector with the given Bitcoin precompile address
    pub fn new(bitcoin_precompile_address: Address, excluded_addresses: impl IntoIterator<Item = Address>) -> Self {
        Self {
            excluded_addresses: excluded_addresses.into_iter().collect(),
            bitcoin_precompile_address,
            accessed_storage: HashMap::new(),
            bitcoin_precompile_called: false,
        }
    }

    /// Mark that the Bitcoin precompile has been called
    pub fn mark_bitcoin_precompile_call(&mut self) {
        self.bitcoin_precompile_called = true;
    }

    /// Get all storage accesses and whether Bitcoin precompile was called
    /// Returns (address -> storage_keys mapping, bitcoin_called flag)
    pub fn take_access_list(&mut self) -> (HashMap<Address, BTreeSet<StorageKey>>, bool) {
        let storage = std::mem::take(&mut self.accessed_storage);
        let bitcoin_called = self.bitcoin_precompile_called;
        self.bitcoin_precompile_called = false;
        (storage, bitcoin_called)
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

    /// Track an address access
    fn track_address_access(&mut self, address: Address) {
        if self.should_track_address(address) {
            self.accessed_storage.entry(address).or_default();
        }
    }
}

/// Record all accessed accounts and storage slots at every transaction execution step.
/// If there is a call to the precompile address, flag specific transaction.
/// If flagged all accounts in that transaction that were touched are locked.
impl<DB> Inspector<DB> for BitcoinStorageInspector
where
    DB: Database,
{
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
            // Track external code access
            opcode::EXTCODECOPY | opcode::EXTCODEHASH | opcode::EXTCODESIZE | opcode::BALANCE | opcode::SELFDESTRUCT => {
                if let Ok(slot) = interp.stack().peek(0) {
                    let addr = Address::from_word(B256::from(slot.to_be_bytes()));
                    self.track_address_access(addr);
                }
            }
            // Track call operations
            opcode::DELEGATECALL | opcode::CALL | opcode::STATICCALL | opcode::CALLCODE => {
                if let Ok(slot) = interp.stack().peek(1) {
                    let addr = Address::from_word(B256::from(slot.to_be_bytes()));
                    
                    // Check if this is a call to the Bitcoin precompile
                    if addr == self.bitcoin_precompile_address {
                        self.mark_bitcoin_precompile_call();

                        println!("stack.data(): {:?}", interp.stack().data());
                        println!("return_data_buffer: {:?}", interp.return_data_buffer);
                    }
                    
                    self.track_address_access(addr);
                }
            }
            _ => (),
        }
    }
}