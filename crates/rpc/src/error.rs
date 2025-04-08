//! RPC errors specific to OP.

use alloy_rpc_types_eth::BlockError;
use reth_rpc_eth_api::AsEthApiError;
use reth_rpc_eth_types::EthApiError;
use reth_rpc_server_types::result::internal_rpc_err;
use sova_evm::SovaBlockExecutionError;

/// Sova specific errors, that extend [`EthApiError`].
#[derive(Debug, thiserror::Error)]
pub enum SovaEthApiError {
    /// L1 ethereum error.
    #[error(transparent)]
    Eth(#[from] EthApiError),
    /// EVM error originating from invalid optimism data.
    #[error(transparent)]
    Evm(#[from] SovaBlockExecutionError),
    /// Thrown when calculating L1 gas fee.
    #[error("failed to calculate l1 gas fee")]
    L1BlockFeeError,
    /// Thrown when calculating L1 gas used
    #[error("failed to calculate l1 gas used")]
    L1BlockGasError,
}

impl AsEthApiError for SovaEthApiError {
    fn as_err(&self) -> Option<&EthApiError> {
        match self {
            Self::Eth(err) => Some(err),
            _ => None,
        }
    }
}

impl From<SovaEthApiError> for jsonrpsee_types::error::ErrorObject<'static> {
    fn from(err: SovaEthApiError) -> Self {
        match err {
            SovaEthApiError::Eth(err) => err.into(),
            SovaEthApiError::Evm(_) |
            SovaEthApiError::L1BlockFeeError |
            SovaEthApiError::L1BlockGasError => internal_rpc_err(err.to_string()),
        }
    }
}

impl From<BlockError> for SovaEthApiError {
    fn from(error: BlockError) -> Self {
        Self::Eth(error.into())
    }
}