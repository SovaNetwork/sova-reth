use crate::cache::AccessedStorage;
use crate::error::SlotLockError;
use async_trait::async_trait;
use sova_sentinel_client::SlotLockClient;
use sova_sentinel_proto::proto::{
    get_slot_status_response::Status, BatchGetSlotStatusResponse, SlotData, SlotIdentifier,
};
use tonic::Code;

#[async_trait]
pub trait SentinelClient: Send + Sync + std::fmt::Debug {
    async fn batch_get_locked_status(
        &self,
        storage: &AccessedStorage,
        block: u64,
        btc_block: u64,
    ) -> Result<BatchGetSlotStatusResponse, SlotLockError>;

    async fn batch_lock_slots(
        &self,
        storage: AccessedStorage,
        block: u64,
        btc_block: u64,
        btc_txid: Vec<u8>,
    ) -> Result<(), SlotLockError>;
}

#[derive(Debug)]
pub struct SentinelClientImpl {
    sentinel_url: String,
}

impl SentinelClientImpl {
    pub fn new(sentinel_url: String) -> Self {
        Self { sentinel_url }
    }

    /// Map client errors (Box<dyn std::error::Error>) to structured SlotLockError types
    fn map_client_error(error: Box<dyn std::error::Error>) -> SlotLockError {
        let error_str = error.to_string();

        // Check for common error patterns in the error message
        if error_str.contains("Bitcoin node") || error_str.contains("Bitcoin RPC") {
            SlotLockError::BitcoinNodeUnavailable(error_str)
        } else if error_str.contains("unavailable") || error_str.contains("connection refused") {
            SlotLockError::ServiceUnavailable(error_str)
        } else if error_str.contains("timeout") || error_str.contains("deadline") {
            SlotLockError::Timeout(error_str)
        } else if error_str.contains("invalid") || error_str.contains("argument") {
            SlotLockError::InvalidRequest(error_str)
        } else {
            SlotLockError::RpcError(error_str)
        }
    }

    /// Map tonic errors (tonic::Status) to structured SlotLockError types
    fn map_tonic_error(error: tonic::Status) -> SlotLockError {
        match error.code() {
            Code::Unavailable => {
                // Distinguish between Bitcoin node issues and sentinel service issues
                let message = error.message();
                if message.contains("Bitcoin node") || message.contains("Bitcoin RPC") {
                    SlotLockError::BitcoinNodeUnavailable(message.to_string())
                } else {
                    SlotLockError::ServiceUnavailable(message.to_string())
                }
            }
            Code::InvalidArgument => SlotLockError::InvalidRequest(error.message().to_string()),
            Code::Internal => SlotLockError::InternalError(error.message().to_string()),
            Code::DeadlineExceeded => SlotLockError::Timeout(error.message().to_string()),
            Code::Unauthenticated => {
                SlotLockError::RpcError(format!("Authentication failed: {}", error.message()))
            }
            Code::PermissionDenied => {
                SlotLockError::RpcError(format!("Permission denied: {}", error.message()))
            }
            _ => SlotLockError::RpcError(format!("{}: {}", error.code(), error.message())),
        }
    }

    /// Validate response format and check status
    fn validate_response(response: &BatchGetSlotStatusResponse) -> Result<(), SlotLockError> {
        for slot in &response.slots {
            // Validate that we can parse the status
            let status = Status::try_from(slot.status).map_err(|_| {
                SlotLockError::InvalidResponse(format!(
                    "Invalid status value {} for slot {}:{}",
                    slot.status,
                    slot.contract_address,
                    hex::encode(&slot.slot_index)
                ))
            })?;

            // Check for UNKNOWN status which indicates a problem
            if status == Status::Unknown {
                return Err(SlotLockError::UnknownSlotStatus {
                    contract_address: slot.contract_address.clone(),
                    slot_index: slot.slot_index.clone(),
                    message: "Sentinel returned UNKNOWN status - check Bitcoin node connectivity"
                        .to_string(),
                });
            }

            // Validate contract address format
            if slot.contract_address.is_empty() {
                return Err(SlotLockError::InvalidResponse(
                    "Empty contract address in response".to_string(),
                ));
            }

            // Validate slot index
            if slot.slot_index.is_empty() {
                return Err(SlotLockError::InvalidResponse(format!(
                    "Empty slot index for contract {}",
                    slot.contract_address
                )));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SentinelClient for SentinelClientImpl {
    async fn batch_get_locked_status(
        &self,
        storage: &AccessedStorage,
        block: u64,
        btc_block: u64,
    ) -> Result<BatchGetSlotStatusResponse, SlotLockError> {
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

        let mut client = SlotLockClient::connect(self.sentinel_url.clone())
            .await
            .map_err(|e| SlotLockError::ConnectionError(e.to_string()))?;

        let response = client
            .batch_get_slot_status(block, btc_block, slots_to_check)
            .await
            .map_err(Self::map_client_error)?;

        // Validate response
        Self::validate_response(&response)?;

        Ok(response)
    }

    async fn batch_lock_slots(
        &self,
        storage: AccessedStorage,
        block: u64,
        btc_block: u64,
        btc_txid_bytes: Vec<u8>,
    ) -> Result<(), SlotLockError> {
        let mut slots_to_lock: Vec<SlotData> = Vec::new();
        let btc_txid = hex::encode(&btc_txid_bytes);

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

        let mut client = SlotLockClient::connect(self.sentinel_url.clone())
            .await
            .map_err(|e| SlotLockError::ConnectionError(e.to_string()))?;

        client
            .batch_lock_slot(block, btc_block, slots_to_lock)
            .await
            .map_err(Self::map_tonic_error)?;

        Ok(())
    }
}
