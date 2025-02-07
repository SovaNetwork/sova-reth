use std::fmt;

use reth_tasks::TaskExecutor;

use alloy_primitives::U256;

use tonic::transport::Error as TonicError;

use sova_sentinel_client::SlotLockClient;
use sova_sentinel_proto::proto::{GetSlotStatusResponse, LockSlotResponse};

use super::storage_cache::AccessedStorage;

#[derive(Debug)]
pub enum ProviderError {
    Transport(TonicError),
    RpcError(String),
    ConnectionError(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderError::Transport(e) => write!(f, "Transport error: {}", e),
            ProviderError::RpcError(e) => write!(f, "RPC error: {}", e),
            ProviderError::ConnectionError(e) => write!(f, "Connection error: {}", e),
        }
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProviderError::Transport(e) => Some(e),
            ProviderError::RpcError(_) | ProviderError::ConnectionError(_) => None,
        }
    }
}

impl From<TonicError> for ProviderError {
    fn from(err: TonicError) -> Self {
        Self::Transport(err)
    }
}

pub trait SlotProvider {
    /// Provided accessed storage slots, return boolean indicating if all slots are unlocked or not
    fn get_locked_status(
        &self,
        storage: AccessedStorage,
        block: U256,
    ) -> Result<bool, ProviderError>;
    /// Lock the provided accessed storage slots with the corresponding bitcoin txid and vout
    fn lock_slots(
        &self,
        storage: AccessedStorage,
        block: U256,
        btc_txid: Vec<u8>,
        btc_block: u64,
    ) -> Result<(), ProviderError>;
}

pub struct StorageSlotProvider {
    sentinel_url: String,
    task_executor: TaskExecutor,
}

impl StorageSlotProvider {
    pub fn new(sentinel_url: String, task_executor: TaskExecutor) -> Result<Self, ProviderError> {
        Ok(Self {
            sentinel_url,
            task_executor,
        })
    }
}

impl SlotProvider for StorageSlotProvider {
    fn get_locked_status(
        &self,
        storage: AccessedStorage,
        block: U256,
    ) -> Result<bool, ProviderError> {
        let sentinel_url = self.sentinel_url.clone();
    
        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| ProviderError::ConnectionError(e.to_string()))?;
    
                for (address, slots) in storage.iter() {
                    for (slot, _) in slots {
                        let response: GetSlotStatusResponse = client
                            .get_slot_status(
                                block.saturating_to::<u64>(),
                                address.to_string(),
                                slot.to_vec(),
                            )
                            .await
                            .map_err(|e| ProviderError::RpcError(e.to_string()))?
                            .into_inner();
    
                        if response.status == 1 {
                            return Ok(true);
                        }
                    }
                }
    
                Ok(false)
            })
        })
    }
    

    fn lock_slots(
        &self,
        storage: AccessedStorage,
        block: U256,
        btc_txid: Vec<u8>,
        btc_block: u64,
    ) -> Result<(), ProviderError> {
        let sentinel_url = self.sentinel_url.clone();
    
        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| ProviderError::ConnectionError(e.to_string()))?;
    
                for (address, slots) in storage.iter() {
                    for (slot, slot_data) in slots {
                        let _: LockSlotResponse = client
                            .lock_slot(
                                block.saturating_to::<u64>(), 
                                address.to_string(),
                                slot.to_vec(),
                                slot_data.previous_value.to_be_bytes_vec(),
                                slot_data.current_value.to_be_bytes_vec(),
                                hex::encode(&btc_txid),
                                btc_block,
                            )
                            .await
                            .map_err(|e| ProviderError::RpcError(e.to_string()))?
                            .into_inner();
                    }
                }
    
                Ok(())
            })
        })
    }
    
}
