use alloy_primitives::{Address, StorageKey};

struct storage_slot_provider {
    http_client: reqwest::Client,
    storage_slot_url: String,
}

trait StorageSlotProvider {
    /// Get the lock status for vec of accessed storage slots
    fn get_storage_slot_lock(&self, address: Address, slot: StorageKey) -> Result<bool, String>;
    fn lock_storage_slot(&self, address: Address, slot: StorageKey) -> Result<(), String>;
}

impl storage_slot_provider {
    pub fn new(storage_slot_url: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            storage_slot_url,
        }
    }
}