use thiserror::Error;

#[derive(Debug, Error)]
pub enum SlotLockError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Bitcoin error: {0}")]
    BitcoinError(String),

    #[error("Sentinel service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Bitcoin node unavailable: {0}")]
    BitcoinNodeUnavailable(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error(
        "Unknown slot status for {contract_address}:{}: {message}",
        hex::encode(slot_index)
    )]
    UnknownSlotStatus {
        contract_address: String,
        slot_index: Vec<u8>,
        message: String,
    },

    #[error("Slot is locked: {0}")]
    SlotLocked(String),

    #[error("Unauthorized caller for precompile")]
    UnauthorizedCaller,
}
