use std::fmt;

use alloy_primitives::Address;
use reth_revm::TransitionAccount;
use reth_tasks::TaskExecutor;

use tonic::transport::Error as TonicError;

use sova_sentinel_client::SlotLockClient;
use sova_sentinel_proto::proto::{GetSlotStatusResponse, LockSlotResponse};

use super::storage_cache::AccessedStorage;

#[derive(Debug)]
pub enum SlotProviderError {
    Transport(TonicError),
    RpcError(String),
    ConnectionError(String),
    BitcoinError(bitcoincore_rpc::Error),
}

impl fmt::Display for SlotProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotProviderError::Transport(e) => write!(f, "Transport error: {}", e),
            SlotProviderError::RpcError(e) => write!(f, "RPC error: {}", e),
            SlotProviderError::ConnectionError(e) => write!(f, "Connection error: {}", e),
            SlotProviderError::BitcoinError(e) => write!(f, "Bitcoin error: {}", e),
        }
    }
}

impl std::error::Error for SlotProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SlotProviderError::Transport(e) => Some(e),
            SlotProviderError::RpcError(_) | SlotProviderError::ConnectionError(_) => None,
            SlotProviderError::BitcoinError(e) => Some(e),
        }
    }
}

impl From<TonicError> for SlotProviderError {
    fn from(err: TonicError) -> Self {
        Self::Transport(err)
    }
}

pub trait SlotProvider {
    /// Provided accessed storage slots, return boolean indicating if all slots are unlocked or not
    fn get_locked_status(
        &self,
        storage: AccessedStorage,
        block: u64,
    ) -> Result<Vec<GetSlotStatusResponse>, SlotProviderError>;
    /// Lock the provided accessed storage slots with the corresponding bitcoin txid and vout
    fn lock_slots(
        &self,
        storage: AccessedStorage,
        block: u64,
        btc_txid: Vec<u8>,
        btc_block: u64,
    ) -> Result<(), SlotProviderError>;

    fn unlock_slot(
        &self,
        btc_block: u64,
        transitions: Vec<(Address, TransitionAccount)>,
    ) -> Result<(), SlotProviderError>;
}

pub struct StorageSlotProvider {
    /// Url endpoint of the sentinel service
    sentinel_url: String,
    /// reth's async task executor
    task_executor: TaskExecutor,
}

impl StorageSlotProvider {
    pub fn new(
        sentinel_url: String,
        task_executor: TaskExecutor,
    ) -> Result<Self, SlotProviderError> {
        Ok(Self {
            sentinel_url,
            task_executor,
        })
    }

    async fn get_locked_status_inner(
        client: &mut SlotLockClient,
        block: u64,
        storage: AccessedStorage,
    ) -> Result<Vec<GetSlotStatusResponse>, SlotProviderError> {
        let mut responses = Vec::new();
        for (address, slots) in storage.iter() {
            for slot in slots.keys() {
                let response: GetSlotStatusResponse = client
                    .get_slot_status(block, address.to_string(), slot.to_vec())
                    .await
                    .map_err(|e| SlotProviderError::RpcError(e.to_string()))?
                    .into_inner();

                responses.push(response);
            }
        }
        Ok(responses)
    }

    async fn lock_slots_inner(
        client: &mut SlotLockClient,
        block: u64,
        storage: AccessedStorage,
        btc_txid: Vec<u8>,
        btc_block: u64,
    ) -> Result<(), SlotProviderError> {
        for (address, slots) in storage.iter() {
            for (slot, slot_data) in slots {
                println!(
                    "Revert value: {:?}, Bytes: {:?}",
                    slot_data.previous_value,
                    slot_data.previous_value.to_be_bytes_vec()
                );
                println!(
                    "Current value: {:?}, Bytes: {:?}",
                    slot_data.current_value,
                    slot_data.current_value.to_be_bytes_vec()
                );

                let _: LockSlotResponse = client
                    .lock_slot(
                        block,
                        address.to_string(),
                        slot.to_vec(),
                        slot_data.previous_value.to_be_bytes_vec(),
                        slot_data.current_value.to_be_bytes_vec(),
                        hex::encode(&btc_txid),
                        btc_block,
                    )
                    .await
                    .map_err(|e| SlotProviderError::RpcError(e.to_string()))?
                    .into_inner();
            }
        }
        Ok(())
    }

    async fn unlock_slots_inner(
        client: &mut SlotLockClient,
        block: u64,
        transitions: &[(Address, TransitionAccount)],
    ) -> Result<(), SlotProviderError> {
        // Process each account in the revert cache
        for (address, transition) in transitions.iter() {
            // Only process accounts that have storage changes
            if !transition.storage.is_empty() {
                // Convert each storage slot to bytes and unlock it
                for (slot, _) in transition.storage.iter() {
                    let slot_bytes = slot.to_be_bytes_vec();

                    let _ = client
                        .unlock_slot(block, address.to_string(), slot_bytes)
                        .await
                        .map_err(|e| SlotProviderError::RpcError(e.to_string()))?
                        .into_inner();
                }
            }
        }
        Ok(())
    }
}

impl SlotProvider for StorageSlotProvider {
    fn get_locked_status(
        &self,
        storage: AccessedStorage,
        block: u64,
    ) -> Result<Vec<GetSlotStatusResponse>, SlotProviderError> {
        let sentinel_url = self.sentinel_url.clone();

        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| SlotProviderError::ConnectionError(e.to_string()))?;

                Self::get_locked_status_inner(&mut client, block, storage).await
            })
        })
    }

    fn lock_slots(
        &self,
        storage: AccessedStorage,
        block: u64,
        btc_txid: Vec<u8>,
        btc_block: u64,
    ) -> Result<(), SlotProviderError> {
        let sentinel_url = self.sentinel_url.clone();

        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| SlotProviderError::ConnectionError(e.to_string()))?;

                Self::lock_slots_inner(&mut client, block, storage, btc_txid, btc_block).await
            })
        })
    }

    fn unlock_slot(
        &self,
        block: u64,
        transitions: Vec<(Address, TransitionAccount)>,
    ) -> Result<(), SlotProviderError> {
        let sentinel_url = self.sentinel_url.clone();

        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| SlotProviderError::ConnectionError(e.to_string()))?;

                Self::unlock_slots_inner(&mut client, block, &transitions).await
            })
        })
    }
}
