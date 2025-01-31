use alloy_primitives::{Address, StorageKey};
use reth_db_api::table::{Decode, Encode, Table};
use serde::{Deserialize, Serialize};

/// Key for storage locks table: (address, slot)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct StorageLockKey {
    pub address: Address,
    pub slot: StorageKey,
}

impl Encode for StorageLockKey {
    type Encoded = [u8; 64]; // 20 bytes for address + 32 bytes for storage key

    fn encode(self) -> Self::Encoded {
        let mut buffer = [0u8; 64];
        buffer[..20].copy_from_slice(self.address.as_slice());
        buffer[20..].copy_from_slice(self.slot.as_slice());
        buffer
    }
}

impl Decode for StorageLockKey {
    fn decode(encoded: &[u8]) -> Result<Self, reth_db_api::DatabaseError> {
        if encoded.len() != 64 {
            return Err(reth_db_api::DatabaseError::Decode);
        }
        
        Ok(StorageLockKey {
            address: Address::from_slice(&encoded[..20]),
            slot: StorageKey::from_slice(&encoded[20..]),
        })
    }
}

/// Storage locks table
#[derive(Debug, Clone)]
pub struct StorageLockTable;

impl Table for StorageLockTable {
    type Key = StorageLockKey;
    type Value = u64;

    const NAME: &'static str = "storage_locks";
    const DUPSORT: bool = false;
}