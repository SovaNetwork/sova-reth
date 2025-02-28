use reth_tasks::TaskExecutor;

use sova_sentinel_client::SlotLockClient;
use sova_sentinel_proto::proto::{BatchGetSlotStatusResponse, SlotData};

use super::{error::SlotProviderError, storage_cache::AccessedStorage};

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
            Err(e) => Err(SlotProviderError::RpcError(e.to_string()))
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
                slots_to_lock.push(SlotData {
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
            Err(e) => Err(SlotProviderError::RpcError(e.to_string()))
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
}
