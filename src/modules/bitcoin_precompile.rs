use std::sync::Arc;

use parking_lot::RwLock;

use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{
    Bytes as RethBytes, Env, PrecompileError, PrecompileErrors, PrecompileResult,
    StatefulPrecompileMut,
};

use alloy_primitives::Bytes as AlloyBytes;

use bitcoin::{consensus::encode::deserialize, Network, Txid};

use crate::{config::BitcoinConfig, modules::bitcoin_client::BitcoinClientWrapper};

use super::abi_encoding::{abi_encode_tx_data, EncodingError, ScriptType};

#[derive(Clone)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<RwLock<BitcoinClientWrapper>>,
    network: Network,
}

impl BitcoinRpcPrecompile {
    pub fn new(config: &BitcoinConfig) -> Result<Self, bitcoincore_rpc::Error> {
        let client = BitcoinClientWrapper::new(config)?;
        Ok(Self {
            bitcoin_client: Arc::new(RwLock::new(client)),
            network: config.network,
        })
    }

    /// helper functions
    pub fn get_output_script_type(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<ScriptType, EncodingError> {
        let prev_tx = self
            .bitcoin_client
            .read()
            .get_raw_transaction(txid, None)
            .map_err(|e| {
                EncodingError::GetPreviousOutputTypeError(format!(
                    "Failed to get previous transaction: {:?}",
                    e
                ))
            })?;

        let output = prev_tx.output.get(vout as usize).ok_or_else(|| {
            EncodingError::GetPreviousOutputTypeError("Invalid output index".to_string())
        })?;

        if output.script_pubkey.is_p2pkh() {
            Ok(ScriptType::P2PKH)
        } else if output.script_pubkey.is_p2sh() {
            Ok(ScriptType::P2SH)
        } else if output.script_pubkey.is_p2wpkh() {
            Ok(ScriptType::P2WPKH)
        } else if output.script_pubkey.is_p2wsh() {
            Ok(ScriptType::P2WSH)
        } else {
            Err(EncodingError::GetPreviousOutputTypeError(
                "Unknown script type".to_string(),
            ))
        }
    }

    /// precompile entrypoints
    fn send_raw_transaction(&self, input: &[u8], gas_price: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Failed to deserialize Bitcoin transaction",
            ))
        })?;

        let txid = self
            .bitcoin_client
            .read()
            .send_raw_transaction(&tx)
            .map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other(
                    "Send raw transaction bitcoin rpc call failed",
                ))
            })?;

        Ok(PrecompileOutput::new(
            gas_price,
            reth::primitives::Bytes::from(txid.to_string()),
        ))
    }

    fn get_block_count(&self, gas_price: u64) -> PrecompileResult {
        let block_count = self.bitcoin_client.read().get_block_count().map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other("Failed to get block count"))
        })?;

        Ok(PrecompileOutput::new(
            gas_price,
            reth::primitives::Bytes::from(block_count.to_be_bytes().to_vec()),
        ))
    }

    fn decode_raw_transaction(&self, input: &[u8], gas_price: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Failed to deserialize Bitcoin transaction",
            ))
        })?;

        let data = self
            .bitcoin_client
            .read()
            .decode_raw_transaction(&tx)
            .map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other("Decode raw transaction bitcoin rpc call failed"))
            })?;

        let encoded_data: AlloyBytes =
            abi_encode_tx_data(self, &data, &self.network).map_err(|e| {
                PrecompileErrors::Error(PrecompileError::Other(format!(
                    "Failed to encode transaction data: {:?}",
                    e
                )))
            })?;

        // Convert AlloyBytes to RethBytes by creating a new RethBytes from the underlying Vec<u8>
        let reth_bytes = RethBytes::from(encoded_data.to_vec());
        Ok(PrecompileOutput::new(gas_price, reth_bytes))
    }
}

impl StatefulPrecompileMut for BitcoinRpcPrecompile {
    fn call_mut(
        &mut self,
        input: &reth::primitives::Bytes,
        gas_price: u64,
        _env: &Env,
    ) -> PrecompileResult {
        // input[0] is the method id
        match input.first() {
            Some(0) => self.send_raw_transaction(&input[1..], gas_price),
            Some(1) => self.get_block_count(gas_price),
            Some(2) => self.decode_raw_transaction(&input[1..], gas_price),
            _ => Err(PrecompileErrors::Error(PrecompileError::other(
                "StatefulPrecompileMut::Unsupported Bitcoin RPC method",
            ))),
        }
    }
}
