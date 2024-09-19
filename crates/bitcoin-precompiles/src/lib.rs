use std::sync::Arc;

use parking_lot::RwLock;

use reth_primitives::revm_primitives::{
    Bytes, Env, PrecompileError, PrecompileErrors, PrecompileResult, StatefulPrecompile,
};

use bitcoin::Network;

use corsa_bitcoin_client::BitcoinClientWrapper;
use corsa_config::BitcoinConfig;

mod precompiles;

use precompiles::{
    check_signature, decode_raw_transaction, get_block_count, send_raw_transaction
};

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
}

impl StatefulPrecompile for BitcoinRpcPrecompile {
    fn call(
        &self,
        input: &Bytes,
        _gas_price: u64,
        _env: &Env,
    ) -> PrecompileResult {
        if input.len() < 4 {
            return Err(PrecompileErrors::Error(PrecompileError::other(
                "Input too short for method selector",
            )));
        }

        // Parse the first 4 bytes as a u32 method selector
        let method_selector = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);

        match method_selector {
            0x00000000 => send_raw_transaction::execute(self, &input[4..], 100_000),
            0x00000001 => get_block_count::execute(self),
            0x00000002 => decode_raw_transaction::execute(self, &input[4..], 150_000),
            0x00000003 => check_signature::execute(self, &input[4..], 100_000),
            _ => Err(PrecompileErrors::Error(PrecompileError::other("Unsupported Bitcoin RPC method"))),
        }
    }
}
