use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, StorageKey, StorageValue};

use super::StorageChange;

#[derive(Clone, Debug)]
pub struct SlotHistory {
    pub previous_value: StorageValue,
    pub current_value: StorageValue,
}

#[derive(Clone, Debug, Default)]
/// Accessed storage cache: address -> storage slot -> current and previous slot value
pub struct AccessedStorage(pub HashMap<Address, HashMap<StorageKey, SlotHistory>>);

impl AccessedStorage {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Get the entry for a given address
    fn entry(&mut self, address: Address) -> &mut HashMap<StorageKey, SlotHistory> {
        self.0.entry(address).or_default()
    }

    /// Insert a slot into the storage
    pub fn insert(
        &mut self,
        address: Address,
        key: StorageKey,
        previous_value: StorageValue,
        current_value: StorageValue,
    ) {
        self.entry(address).insert(
            key,
            SlotHistory {
                previous_value,
                current_value,
            },
        );
    }

    /// Iterate over the storage
    pub fn iter(&self) -> impl Iterator<Item = (&Address, &HashMap<StorageKey, SlotHistory>)> {
        self.0.iter()
    }

    /// Cross reference another storage to see if it contains any of the slots
    /// in this storage. If it does, return true.
    pub fn contains_any(&self, other: &AccessedStorage) -> bool {
        for (address, slots) in other.0.iter() {
            if let Some(self_slots) = self.0.get(address) {
                for key in slots.keys() {
                    if self_slots.contains_key(key) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Merge another storage into this one
    pub fn merge(&mut self, other: &AccessedStorage) {
        for (address, slots) in other.0.iter() {
            for (key, slot_data) in slots {
                self.insert(
                    *address,
                    *key,
                    slot_data.previous_value,
                    slot_data.current_value,
                );
            }
        }
    }
}

#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct BroadcastResult {
    pub txid: Option<Vec<u8>>,
    pub block: Option<u64>,
}

pub struct StorageCache {
    /// Bitcoin precompile address used for filtering calls to the broadcast tx method
    pub bitcoin_precompile_address: Address,
    /// Excluded addresses from the inspector
    excluded_addresses: HashSet<Address>,
    /// Local cache of storage slot data for a tx since the last broadcast precompile call
    pub broadcast_accessed_storage: AccessedStorage,
    /// All slots to be locked for the next block
    pub lock_data: HashMap<BroadcastResult, AccessedStorage>,
}

impl StorageCache {
    pub fn new(
        bitcoin_precompile_address: Address,
        excluded_addresses: impl IntoIterator<Item = Address>,
    ) -> Self {
        Self {
            bitcoin_precompile_address,
            excluded_addresses: excluded_addresses.into_iter().collect(),
            broadcast_accessed_storage: AccessedStorage::new(),
            lock_data: HashMap::new(),
        }
    }

    /// Update data in the broadcast storage cache after opcode step
    pub fn insert_accessed_storage_step_end(
        &mut self,
        address: Address,
        key: StorageKey,
        storage_change: StorageChange,
    ) {
        if !self.excluded_addresses.contains(&address) {
            // If we already have an entry for this address and key,
            // update its current value while preserving the previous value
            if let Some(slot_data) = self.broadcast_accessed_storage.entry(address).get_mut(&key) {
                slot_data.current_value = storage_change.value;
            } else {
                // Get the previous value only if the reason is not SLOAD
                let previous_value = if storage_change.had_value.is_some() {
                    storage_change.had_value
                } else {
                    None
                };

                // If we don't have an entry for this address and key, add one
                self.broadcast_accessed_storage.insert(
                    address,
                    key,
                    previous_value.unwrap_or_default(),
                    storage_change.value,
                );
            }
        }
    }

    /// Commit the current broadcast storage to the block storage and lock data
    pub fn commit_broadcast(&mut self, broadcast_result: BroadcastResult) {
        // Add to lock data
        if broadcast_result.txid.is_some() && broadcast_result.block.is_some() {
            self.lock_data
                .insert(broadcast_result, self.broadcast_accessed_storage.clone());
        }

        // Clear broadcast storage for next transaction
        // or if there is a second broadcast precompile call in this tx.
        self.broadcast_accessed_storage.0.clear();
    }

    /// Clear all storage data for a new block
    pub fn clear_cache(&mut self) {
        self.broadcast_accessed_storage.0.clear();
        self.lock_data.clear();
    }
}
