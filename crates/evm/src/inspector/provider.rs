use std::fmt;

use alloy_primitives::Address;
use reth_revm::TransitionAccount;
use reth_tasks::TaskExecutor;

use tonic::transport::Error as TonicError;

use sova_sentinel_client::SlotLockClient;
use sova_sentinel_proto::proto::BatchGetSlotStatusResponse;

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
    /// Get the lock status of the provided accessed storage slots
    fn batch_get_locked_status(
        &self,
        storage: &AccessedStorage,
        block: u64,
        btc_block: u64,
    ) -> Result<BatchGetSlotStatusResponse, SlotProviderError>;
    /// Lock the provided accessed storage slots with the corresponding bitcoin txid
    fn batch_lock_slots(
        &self,
        storage: AccessedStorage,
        block: u64,
        btc_block: u64,
        btc_txid: Vec<u8>,
    ) -> Result<(), SlotProviderError>;
    /// EXPERIMENTAL: Unlock the provided accessed storage slots
    /// TODO: Rely in laxy unlocking in sentinel
    fn batch_unlock_slot(
        &self,
        block: u64,
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

    async fn batch_get_locked_status_inner(
        client: &mut SlotLockClient,
        storage: &AccessedStorage,
        block: u64,
        btc_block: u64,
    ) -> Result<BatchGetSlotStatusResponse, SlotProviderError> {
        let mut slots_to_check: Vec<(String, Vec<u8>)> = Vec::new();

        // Process each account in the accessed cache
        for (address, slots) in storage.iter() {
            for slot in slots.keys() {
                slots_to_check.push((address.to_string(), slot.to_vec()));
            }
        }

        match client
            .batch_get_slot_status(block, btc_block, slots_to_check)
            .await
            .map_err(|e| SlotProviderError::RpcError(e.to_string()))
        {
            Ok(res) => Ok(res),
            // TODO: is the this best error handling?
            Err(e) => return Err(SlotProviderError::RpcError(e.to_string())),
        }
    }

    async fn batch_lock_slots_inner(
        client: &mut SlotLockClient,
        storage: AccessedStorage,
        block: u64,
        btc_block: u64,
        btc_txid: Vec<u8>,
    ) -> Result<(), SlotProviderError> {
        let mut slots_to_lock: Vec<sova_sentinel_proto::proto::SlotData> = Vec::new();

        // Process each account in the accessed cache
        for (address, slots) in storage.iter() {
            for (slot, slot_data) in slots {
                slots_to_lock.push(sova_sentinel_proto::proto::SlotData {
                    contract_address: address.to_string(),
                    slot_index: slot.to_vec(),
                    revert_value: slot_data.previous_value.to_be_bytes_vec(),
                    current_value: slot_data.current_value.to_be_bytes_vec(),
                });
            }
        }

        match client
            .batch_lock_slot(block, btc_block, &hex::encode(&btc_txid), slots_to_lock)
            .await
            .map_err(|e| SlotProviderError::RpcError(e.to_string()))
        {
            Ok(_) => Ok(()),
            // TODO: is the this best error handling?
            Err(e) => return Err(SlotProviderError::RpcError(e.to_string())),
        }
    }

    async fn batch_unlock_slots_inner(
        client: &mut SlotLockClient,
        block: u64,
        btc_block: u64,
        transitions: &[(Address, TransitionAccount)],
    ) -> Result<(), SlotProviderError> {
        let mut unlocked_slots: Vec<(String, Vec<u8>)> = Vec::new();

        // Process each account in the revert cache
        for (address, transition) in transitions.iter() {
            // Only process accounts that have storage changes
            if !transition.storage.is_empty() {
                // Convert each storage slot to bytes and unlock it
                for (slot, _) in transition.storage.iter() {
                    let slot_bytes = slot.to_be_bytes_vec();

                    unlocked_slots.push((address.to_string(), slot_bytes));
                }
            }
        }

        match client
            .batch_unlock_slot(block, btc_block, unlocked_slots)
            .await
            .map_err(|e| SlotProviderError::RpcError(e.to_string()))
        {
            Ok(_) => Ok(()),
            // TODO: is the this best error handling?
            Err(e) => return Err(SlotProviderError::RpcError(e.to_string())),
        }
    }
}

impl SlotProvider for StorageSlotProvider {
    fn batch_get_locked_status(
        &self,
        storage: &AccessedStorage,
        block: u64,
        btc_block: u64,
    ) -> Result<BatchGetSlotStatusResponse, SlotProviderError> {
        let sentinel_url = self.sentinel_url.clone();

        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| SlotProviderError::ConnectionError(e.to_string()))?;

                Self::batch_get_locked_status_inner(&mut client, storage, block, btc_block).await
            })
        })
    }

    fn batch_lock_slots(
        &self,
        storage: AccessedStorage,
        block: u64,
        btc_block: u64,
        btc_txid: Vec<u8>,
    ) -> Result<(), SlotProviderError> {
        let sentinel_url = self.sentinel_url.clone();

        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| SlotProviderError::ConnectionError(e.to_string()))?;

                Self::batch_lock_slots_inner(&mut client, storage, block, btc_block, btc_txid).await
            })
        })
    }

    fn batch_unlock_slot(
        &self,
        block: u64,
        btc_block: u64,
        transitions: Vec<(Address, TransitionAccount)>,
    ) -> Result<(), SlotProviderError> {
        let sentinel_url = self.sentinel_url.clone();

        tokio::task::block_in_place(|| {
            let handle = self.task_executor.handle().clone();
            handle.block_on(async {
                let mut client = SlotLockClient::connect(sentinel_url)
                    .await
                    .map_err(|e| SlotProviderError::ConnectionError(e.to_string()))?;

                Self::batch_unlock_slots_inner(&mut client, block, btc_block, &transitions).await
            })
        })
    }
}
