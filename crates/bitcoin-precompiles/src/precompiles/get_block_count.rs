use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors, PrecompileResult};

use crate::BitcoinRpcPrecompile;

pub fn execute(precompile: &BitcoinRpcPrecompile) -> PrecompileResult {
    let gas_used: u64 = 2_000_u64;

    let block_count = precompile.bitcoin_client.read().get_block_count().map_err(|_| {
        PrecompileErrors::Error(PrecompileError::other("Failed to get block count"))
    })?;

    Ok(PrecompileOutput::new(
        gas_used,
        reth::primitives::Bytes::from(block_count.to_be_bytes().to_vec()),
    ))
}