use super::storage_cache::AccessedStorage;

pub trait SlotProvider {
    /// Get the lock status for provided accessed storage slots
    fn get_locks(&self, storage: AccessedStorage) -> Result<Vec<bool>, String>;
    /// Lock the provided accessed storage slots
    fn lock_slots(&self, storage: AccessedStorage) -> Result<(), String>;
}

pub struct StorageSlotProvider {
    http_client: reqwest::Client,
    storage_slot_provider_url: String,
}

impl StorageSlotProvider {
    pub fn new(storage_slot_provider_url: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            storage_slot_provider_url,
        }
    }
}

impl SlotProvider for StorageSlotProvider {
    fn get_locks(&self, _storage: AccessedStorage) -> Result<Vec<bool>, String> {
        // TODO: Implement this

        Ok(vec![])
    }

    fn lock_slots(&self, _storage: AccessedStorage) -> Result<(), String> {
        // TODO: Implement this

        Ok(())
    }
}
