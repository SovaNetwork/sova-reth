use std::fmt;
use tonic::transport::Error as TonicError;

#[derive(Debug)]
pub enum SlotProviderError {
    /// Transport-level errors (network connectivity to sentinel)
    Transport(TonicError),
    /// Generic RPC errors that don't fit other categories  
    RpcError(String),
    /// Initial connection errors to sentinel service
    ConnectionError(String),
    /// Bitcoin RPC errors
    BitcoinError(bitcoincore_rpc::Error),
    /// Sentinel service is unavailable (not Bitcoin node)
    ServiceUnavailable(String),
    /// Bitcoin node is unreachable from sentinel
    BitcoinNodeUnavailable(String),
    /// Invalid request parameters
    InvalidRequest(String),
    /// Internal sentinel service error
    InternalError(String),
    /// Request timeout
    Timeout(String),
    /// Invalid response format from sentinel
    InvalidResponse(String),
    /// Specific slot returned UNKNOWN status
    UnknownSlotStatus {
        contract_address: String,
        slot_index: Vec<u8>,
        message: String,
    },
}

impl fmt::Display for SlotProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotProviderError::Transport(e) => write!(f, "Transport error: {e}"),
            SlotProviderError::RpcError(e) => write!(f, "RPC error: {e}"),
            SlotProviderError::ConnectionError(e) => write!(f, "Connection error: {e}"),
            SlotProviderError::BitcoinError(e) => write!(f, "Bitcoin error: {e}"),
            SlotProviderError::ServiceUnavailable(e) => {
                write!(f, "Sentinel service unavailable: {e}")
            }
            SlotProviderError::BitcoinNodeUnavailable(e) => {
                write!(f, "Bitcoin node unavailable: {e}")
            }
            SlotProviderError::InvalidRequest(e) => write!(f, "Invalid request: {e}"),
            SlotProviderError::InternalError(e) => write!(f, "Internal error: {e}"),
            SlotProviderError::Timeout(e) => write!(f, "Request timeout: {e}"),
            SlotProviderError::InvalidResponse(e) => write!(f, "Invalid response: {e}"),
            SlotProviderError::UnknownSlotStatus {
                contract_address,
                slot_index,
                message,
            } => {
                write!(
                    f,
                    "Unknown slot status for {}:{}: {}",
                    contract_address,
                    hex::encode(slot_index),
                    message
                )
            }
        }
    }
}

impl std::error::Error for SlotProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SlotProviderError::Transport(e) => Some(e),
            SlotProviderError::BitcoinError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TonicError> for SlotProviderError {
    fn from(err: TonicError) -> Self {
        Self::Transport(err)
    }
}
