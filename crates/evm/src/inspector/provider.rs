use std::fmt;

use reth_tasks::TaskExecutor;

use alloy_primitives::U256;

use bitcoin::Txid;
use tonic::transport::Error as TonicError;

use sova_sentinel_client::SlotLockClient;
use sova_sentinel_proto::proto::{GetSlotStatusResponse, LockSlotResponse};

use super::storage_cache::AccessedStorage;

#[derive(Debug)]
pub enum ProviderError {
    Transport(TonicError),
    RpcError(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProviderError::Transport(e) => write!(f, "Transport error: {}", e),
            ProviderError::RpcError(e) => write!(f, "RPC error: {}", e),
        }
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProviderError::Transport(e) => Some(e),
            ProviderError::RpcError(_) => None,
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
        btc_txid: Txid,
        vout: u32,
    ) -> Result<(), ProviderError>;
}

pub struct StorageSlotProvider {
    sentinel_client: SlotLockClient,
    task_executor: TaskExecutor,
}

impl StorageSlotProvider {
    pub fn new(sentinel_url: String, task_executor: TaskExecutor) -> Result<Self, ProviderError> {
        let sentinel_client = task_executor
            .handle()
            .block_on(SlotLockClient::connect(sentinel_url))
            .map_err(|e| ProviderError::Transport(e))?;

        Ok(Self {
            sentinel_client,
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
        for (address, slots) in storage.iter() {
            for (slot, _) in slots {
                let response: GetSlotStatusResponse = self
                    .task_executor
                    .handle()
                    .block_on(self.sentinel_client.clone().get_slot_status(
                        block.saturating_to::<u64>(),
                        String::from(address.to_string()),
                        slot,
                    ))
                    .map_err(|e| ProviderError::RpcError(e.to_string()))?
                    .into_inner();

                // check if locked
                if response.status == 1 {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// NOTE(powvt): Current stopping point and state of development:
    /// - Need to add btc block height so the sentinel service knows the start of the confirmation threshold and double spend threshold
    ///      - Reminder, Double spend protection will initially be implemented in a naive way.
    ///        Where once a btc tx is not confirmed in x amnount of blocks the slot is reverted to the previous value.
    ///        Due to this design the only thing we need to track is the btc txid of the signed payload (no need to track vout or OutPoints).
    /// - Need to coordinate slot type with the sentinel service. Currently storing as a u64 in the sentinel service will not work,
    ///   needs to be either bytes or U256. As a reminder, if this is bytes in the sentinel service, it makes querying for debugging purposes more difficult.
    ///   Using a U256 in the sentinel service is more user friendly, but proto files do not accept this.
    fn lock_slots(
        &self,
        storage: AccessedStorage,
        block: U256,
        btc_txid: Txid,
        vout: u32,
    ) -> Result<(), ProviderError> {
        for (address, slots) in storage.iter() {
            for (slot, slot_data) in slots {
                let _: LockSlotResponse = self
                    .task_executor
                    .handle()
                    //
                    .block_on(self.sentinel_client.clone().lock_slot(
                        block.saturating_to::<u64>(), 
                        String::from(address.to_string()),
                        slot,
                        slot_data.previous_value.to_be_bytes_vec(),
                        slot_data.current_value.to_be_bytes_vec(),
                        btc_txid.to_string(),
                        // vout,
                    ))
                    .map_err(|e| ProviderError::RpcError(e.to_string()))?
                    .into_inner();
            }
        }

        Ok(())
    }
}
