use tonic::Code;

use reth_tasks::TaskExecutor;

use sova_sentinel_client::SlotLockClient;
use sova_sentinel_proto::proto::{
    get_slot_status_response::Status, BatchGetSlotStatusResponse, SlotData, SlotIdentifier,
};

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

#[derive(Debug)]
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
        let mut slots_to_check: Vec<SlotIdentifier> = Vec::new();

        // Process each account in the accessed cache
        for (address, slots) in storage.iter() {
            for slot in slots.keys() {
                slots_to_check.push(SlotIdentifier {
                    contract_address: address.to_string(),
                    slot_index: slot.to_vec(),
                });
            }
        }

        let response = client
            .batch_get_slot_status(block, btc_block, slots_to_check)
            .await
            .map_err(Self::map_client_error)?;

        // Validate response format and check for UNKNOWN statuses
        Self::validate_response(&response)?;

        Ok(response)
    }

    async fn batch_lock_slots_inner(
        client: &mut SlotLockClient,
        storage: AccessedStorage,
        block: u64,
        btc_block: u64,
        btc_txid_bytes: Vec<u8>,
    ) -> Result<(), SlotProviderError> {
        let mut slots_to_lock: Vec<SlotData> = Vec::new();
        let btc_txid = &hex::encode(&btc_txid_bytes);

        // Process each account in the accessed cache
        for (address, slots) in storage.iter() {
            for (slot, slot_data) in slots {
                slots_to_lock.push(SlotData {
                    contract_address: address.to_string(),
                    btc_txid: btc_txid.clone(),
                    slot_index: slot.to_vec(),
                    revert_value: slot_data.previous_value.to_be_bytes_vec(),
                    current_value: slot_data.current_value.to_be_bytes_vec(),
                });
            }
        }

        client
            .batch_lock_slot(block, btc_block, slots_to_lock)
            .await
            .map_err(Self::map_tonic_error)?;

        Ok(())
    }

    /// Map client errors (Box<dyn std::error::Error>) to structured SlotProviderError types
    fn map_client_error(error: Box<dyn std::error::Error>) -> SlotProviderError {
        let error_str = error.to_string();

        // Check for common error patterns in the error message
        if error_str.contains("Bitcoin node") || error_str.contains("Bitcoin RPC") {
            SlotProviderError::BitcoinNodeUnavailable(error_str)
        } else if error_str.contains("unavailable") || error_str.contains("connection refused") {
            SlotProviderError::ServiceUnavailable(error_str)
        } else if error_str.contains("timeout") || error_str.contains("deadline") {
            SlotProviderError::Timeout(error_str)
        } else if error_str.contains("invalid") || error_str.contains("argument") {
            SlotProviderError::InvalidRequest(error_str)
        } else {
            SlotProviderError::RpcError(error_str)
        }
    }

    /// Map tonic errors (tonic::Status) to structured SlotProviderError types
    fn map_tonic_error(error: tonic::Status) -> SlotProviderError {
        match error.code() {
            Code::Unavailable => {
                // Distinguish between Bitcoin node issues and sentinel service issues
                let message = error.message();
                if message.contains("Bitcoin node") || message.contains("Bitcoin RPC") {
                    SlotProviderError::BitcoinNodeUnavailable(message.to_string())
                } else {
                    SlotProviderError::ServiceUnavailable(message.to_string())
                }
            }
            Code::InvalidArgument => SlotProviderError::InvalidRequest(error.message().to_string()),
            Code::Internal => SlotProviderError::InternalError(error.message().to_string()),
            Code::DeadlineExceeded => SlotProviderError::Timeout(error.message().to_string()),
            Code::Unauthenticated => {
                SlotProviderError::RpcError(format!("Authentication failed: {}", error.message()))
            }
            Code::PermissionDenied => {
                SlotProviderError::RpcError(format!("Permission denied: {}", error.message()))
            }
            _ => SlotProviderError::RpcError(format!("{}: {}", error.code(), error.message())),
        }
    }

    /// Validate response format and check status
    fn validate_response(response: &BatchGetSlotStatusResponse) -> Result<(), SlotProviderError> {
        for slot in &response.slots {
            // Validate that we can parse the status
            let status = Status::try_from(slot.status).map_err(|_| {
                SlotProviderError::InvalidResponse(format!(
                    "Invalid status value {} for slot {}:{}",
                    slot.status,
                    slot.contract_address,
                    hex::encode(&slot.slot_index)
                ))
            })?;

            // Check for UNKNOWN status which indicates a problem
            if status == Status::Unknown {
                return Err(SlotProviderError::UnknownSlotStatus {
                    contract_address: slot.contract_address.clone(),
                    slot_index: slot.slot_index.clone(),
                    message: "Sentinel returned UNKNOWN status - check Bitcoin node connectivity"
                        .to_string(),
                });
            }

            // Validate contract address format
            if slot.contract_address.is_empty() {
                return Err(SlotProviderError::InvalidResponse(
                    "Empty contract address in response".to_string(),
                ));
            }

            // Validate slot index
            if slot.slot_index.is_empty() {
                return Err(SlotProviderError::InvalidResponse(format!(
                    "Empty slot index for contract {}",
                    slot.contract_address
                )));
            }
        }
        Ok(())
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
