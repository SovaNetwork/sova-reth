use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, StorageKey, StorageValue, U256};

#[derive(Clone, Debug)]
pub struct SlotData {
    pub previous_value: StorageValue,
    pub current_value: StorageValue,
}

#[derive(Clone, Debug, Default)]
/// Accessed storage cache: address -> storage slot -> slot data
pub struct AccessedStorage(pub HashMap<Address, HashMap<StorageKey, SlotData>>);

impl AccessedStorage {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    fn entry(&mut self, address: Address) -> &mut HashMap<StorageKey, SlotData> {
        self.0.entry(address).or_default()
    }

    pub fn insert(
        &mut self,
        address: Address,
        key: StorageKey,
        previous: StorageValue,
        current: StorageValue,
    ) {
        self.entry(address).insert(
            key,
            SlotData {
                previous_value: previous,
                current_value: current,
            },
        );
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Address, &HashMap<StorageKey, SlotData>)> {
        self.0.iter()
    }
}

pub struct StorageCache {
    /// Bitcoin precompile address used for filtering calls to the broadcast tx method
    pub bitcoin_precompile_address: Address,
    /// excluded addresses from the inspector
    excluded_addresses: HashSet<Address>,
    /// cache of addresses and storage slots touched during a tx
    pub accessed_storage: AccessedStorage,
}

impl StorageCache {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
    ) -> Self {
        Self {
            bitcoin_precompile_address,
            excluded_addresses: excluded_addresses.into_iter().collect(),
            accessed_storage: AccessedStorage::new(),
        }
    }

    pub fn insert_accessed_storage_before(
        &mut self,
        address: Address,
        key: StorageKey,
        previous: StorageValue,
    ) {
        if !self.excluded_addresses.contains(&address) {
            self.accessed_storage
                .insert(address, key, previous, U256::ZERO);
        }
    }

    pub fn insert_accessed_storage_after(
        &mut self,
        address: Address,
        key: StorageKey,
        current: StorageValue,
    ) {
        if !self.excluded_addresses.contains(&address) {
            // If we already have an entry for this address and key,
            // update its current value while preserving the previous value
            if let Some(slot_data) = self.accessed_storage.entry(address).get_mut(&key) {
                slot_data.current_value = current;
            } else {
                // If no entry exists, create a new one with zero as previous value
                self.accessed_storage
                    .insert(address, key, U256::ZERO, current);
            }
        }
    }
}
