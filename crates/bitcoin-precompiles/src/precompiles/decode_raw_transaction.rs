use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{Bytes as RethBytes, PrecompileError, PrecompileErrors, PrecompileResult};

use alloy_primitives::Bytes as AlloyBytes;

use bitcoin::consensus::encode::deserialize;

use corsa_abi_encoding::abi_encode_tx_data;

use crate::BitcoinRpcPrecompile;

pub fn execute(precompile: &BitcoinRpcPrecompile, input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used: u64 = (4_000 + input.len() * 3) as u64;

    if gas_used > gas_limit {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }

    let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
        PrecompileErrors::Error(PrecompileError::other(
            "Failed to deserialize Bitcoin transaction",
        ))
    })?;

    let data = precompile
        .bitcoin_client
        .read()
        .decode_raw_transaction(&tx)
        .map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Decode raw transaction bitcoin rpc call failed",
            ))
        })?;

    let encoded_data: AlloyBytes = abi_encode_tx_data(&data, &precompile.network).map_err(|e| {
        PrecompileErrors::Error(PrecompileError::Other(format!(
            "Failed to encode transaction data: {:?}",
            e
        )))
    })?;

    // Convert AlloyBytes to RethBytes by creating a new RethBytes from the underlying Vec<u8>
    let reth_bytes = RethBytes::from(encoded_data.to_vec());
    Ok(PrecompileOutput::new(gas_used, reth_bytes))
}