use std::{collections::{BTreeSet, HashMap, HashSet}, ops::Add};

use alloy_primitives::{Address, StorageKey};

pub struct AccessedStorage (HashMap<Address, BTreeSet<StorageKey>>);

impl AccessedStorage {
    fn new() -> Self {
        Self(HashMap::new())
    }

    fn entry(&mut self, address: Address) -> &mut BTreeSet<StorageKey> {
        self.0.entry(address).or_default()
    }

    fn insert(&mut self, address: Address, storage_key: StorageKey) {
        self.entry(address).insert(storage_key);
    }
}

pub struct StorageCache {
    /// Bitcoin precompile address used for filtering calls to the broadcast tx method
    bitcoin_precompile_address: Address,
    /// excluded addresses from the inspector
    excluded_addresses: HashSet<Address>,
    /// cache of addresses and storage slots touched during a tx
    accessed_storage: AccessedStorage,
}

impl StorageCache {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>
    ) -> Self {
        Self {
            bitcoin_precompile_address,
            excluded_addresses: excluded_addresses.into_iter().collect(),
            accessed_storage: AccessedStorage::new(),
        }
    }

    pub fn insert_accessed_storage(&mut self, address: Address, storage_key: StorageKey) {
        if !self.excluded_addresses.contains(&address) {
            self.accessed_storage.entry(address).or_default().insert(storage_key);
        }
    }
}