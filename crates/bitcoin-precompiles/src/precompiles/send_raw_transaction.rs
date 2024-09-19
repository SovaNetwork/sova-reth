use bitcoin::consensus::encode::deserialize;
use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors, PrecompileResult};

use crate::BitcoinRpcPrecompile;

pub fn execute(precompile: &BitcoinRpcPrecompile, input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used: u64 = (10_000 + input.len() * 3) as u64;

    if gas_used > gas_limit {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }

    let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
        PrecompileErrors::Error(PrecompileError::other(
            "Failed to deserialize Bitcoin transaction",
        ))
    })?;

    let txid = precompile
        .bitcoin_client
        .read()
        .send_raw_transaction(&tx)
        .map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Send raw transaction bitcoin rpc call failed",
            ))
        })?;

    Ok(PrecompileOutput::new(
        gas_used,
        reth::primitives::Bytes::from(txid.to_string()),
    ))
}