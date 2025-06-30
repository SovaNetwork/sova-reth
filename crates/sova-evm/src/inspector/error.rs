use std::fmt;

use tonic::transport::Error as TonicError;

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
            SlotProviderError::Transport(e) => write!(f, "Transport error: {e}"),
            SlotProviderError::RpcError(e) => write!(f, "RPC error: {e}"),
            SlotProviderError::ConnectionError(e) => write!(f, "Connection error: {e}"),
            SlotProviderError::BitcoinError(e) => write!(f, "Bitcoin error: {e}"),
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
