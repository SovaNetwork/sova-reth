use std::collections::{BTreeSet, HashMap, HashSet};

use alloy_primitives::{Address, StorageKey};

pub struct StorageCache {
    /// Bitcoin precompile address used for filtering calls to the broadcast tx method
    bitcoin_precompile_address: Address,
    /// excluded addresses from the inspector
    excluded_addresses: HashSet<Address>,
    /// cache of addresses and storage slots touched during a tx
    accessed_storage: HashMap<Address, BTreeSet<StorageKey>>,
}

impl StorageCache {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>
    ) -> Self {
        Self {
            bitcoin_precompile_address,
            excluded_addresses: excluded_addresses.into_iter().collect(),
            accessed_storage: HashMap::new(),
        }
    }

    pub fn insert_accessed_storage(&mut self, address: Address, storage_key: StorageKey) {
        if !self.excluded_addresses.contains(&address) {
            self.accessed_storage.entry(address).or_default().insert(storage_key);
        }
    }
}