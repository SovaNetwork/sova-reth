use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors, PrecompileResult};

use bitcoin::{consensus::encode::deserialize, OutPoint, TxOut};

use crate::BitcoinRpcPrecompile;

pub fn execute(precompile: &BitcoinRpcPrecompile, input: &[u8], gas_limit: u64) -> PrecompileResult {
    let gas_used: u64 = (6_000 + input.len() * 3) as u64;

    if gas_used > gas_limit {
        return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
    }

    let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
        PrecompileErrors::Error(PrecompileError::other(
            "Failed to deserialize Bitcoin transaction",
        ))
    })?;

    // Closure to fetch previous transaction output (TxOut) for each input
    let mut spent = |outpoint: &OutPoint| -> Option<TxOut> {
        match precompile
            .bitcoin_client
            .read()
            .get_raw_transaction(&outpoint.txid, None)
        {
            Ok(prev_tx) => prev_tx
                .output
                .get(outpoint.vout as usize)
                .map(|output| TxOut {
                    value: output.value,
                    script_pubkey: output.script_pubkey.clone(),
                }),
            Err(_) => None,
        }
    };

    // Verify the transaction. For each input, check if unlocking script is valid based on the corresponding TxOut.
    tx.verify(&mut spent).map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!(
            "Transaction verification failed: {:?}",
            e
        )))
    })?;

    Ok(PrecompileOutput::new(
        gas_used,
        reth::primitives::Bytes::from(vec![1]),
    ))
}