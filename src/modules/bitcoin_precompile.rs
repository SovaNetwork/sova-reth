use std::sync::Arc;

use parking_lot::RwLock;

use reth::{
    primitives::revm_primitives::{Env, PrecompileResult, StatefulPrecompileMut},
    revm::precompile::PrecompileOutput,
};
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors};

use bitcoin::consensus::encode::deserialize;

use crate::{config::BitcoinConfig, modules::bitcoin_client::BitcoinClientWrapper};

use super::encoding::encode_tx_data;

#[derive(Clone)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<RwLock<BitcoinClientWrapper>>,
}

impl BitcoinRpcPrecompile {
    pub fn new(config: &BitcoinConfig) -> Result<Self, bitcoincore_rpc::Error> {
        let client = BitcoinClientWrapper::new(config)?;
        Ok(Self {
            bitcoin_client: Arc::new(RwLock::new(client)),
        })
    }

    fn send_raw_transaction(&self, input: &[u8], gas_price: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other("Failed to deserialize Bitcoin transaction"))
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
            PrecompileErrors::Error(PrecompileError::other("Failed to deserialize Bitcoin transaction"))
        })?;

        let data = self
            .bitcoin_client
            .read()
            .decode_raw_transaction(&tx)
            .map_err(|_| {
                PrecompileErrors::Error(PrecompileError::other(
                    "Decode raw transaction bitcoin rpc call failed",
                ))
            })?;
        
        let encoded_data = encode_tx_data(&data).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!("Failed to encode transaction data: {:?}", e)))
        })?;
    
        Ok(PrecompileOutput::new(gas_price, encoded_data))
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
