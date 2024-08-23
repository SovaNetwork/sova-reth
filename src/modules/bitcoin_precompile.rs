use std::sync::Arc;

use parking_lot::RwLock;

use reth::{
    primitives::revm_primitives::{Env, PrecompileResult, StatefulPrecompileMut},
    revm::precompile::PrecompileOutput
};
use reth_primitives::revm_primitives::{PrecompileError, PrecompileErrors};

use bitcoin::consensus::encode::deserialize;

use crate::modules::bitcoin_client::BitcoinClientWrapper;
use crate::settings::Settings;

#[derive(Clone)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<RwLock<BitcoinClientWrapper>>,
}

impl BitcoinRpcPrecompile {
    pub fn new(settings: &Settings) -> Result<Self, bitcoincore_rpc::Error> {
        let client = BitcoinClientWrapper::new(settings)?;
        Ok(Self {
            bitcoin_client: Arc::new(RwLock::new(client)),
        })
    }
}

impl StatefulPrecompileMut for BitcoinRpcPrecompile {
    fn call_mut(&mut self, input: &reth::primitives::Bytes, gas_price: u64, _env: &Env) -> PrecompileResult {
        match input.first() {
            Some(0) => {
                 // sendrawtransaction
                 let raw_tx = &input[1..]; // Skip the first byte

                 let tx: bitcoin::Transaction = deserialize(raw_tx)
                    .map_err(|_| PrecompileErrors::Error(PrecompileError::other("Invalid Bitcoin transaction")))?;

                let txid = self.bitcoin_client.read().send_raw_transaction(&tx)
                    .map_err(|_| PrecompileErrors::Error(PrecompileError::other("Failed to send raw transaction")))?;
                
                Ok(PrecompileOutput::new(
                    gas_price,
                    reth::primitives::Bytes::from(txid.to_string())
                ))
            }
            Some(1) => {
                // getblockcount
                let block_count = self.bitcoin_client.read().get_block_count()
                    .map_err(|_| PrecompileErrors::Error(PrecompileError::other("Failed to get block count")))?;
                
                Ok(PrecompileOutput::new(
                    gas_price,
                    reth::primitives::Bytes::from(block_count.to_be_bytes().to_vec())
                ))
            },
            _ => Err(PrecompileErrors::Error(PrecompileError::other("StatefulPrecompileMut::Unsupported Bitcoin RPC method"))),
        }
    }
}
