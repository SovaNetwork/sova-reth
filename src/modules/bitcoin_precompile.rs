use std::sync::Arc;

use parking_lot::RwLock;

use reqwest::blocking::Client as ReqwestClient;

use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{
    Bytes as RethBytes, Env, PrecompileError, PrecompileErrors, PrecompileResult,
    StatefulPrecompile,
};

use alloy_primitives::Bytes as AlloyBytes;

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, OutPoint, TxOut};

use crate::config::BitcoinConfig;

use super::{
    abi_decoding::{decode_input, parse_utxos, DecodedInput},
    abi_encoding::abi_encode_tx_data,
    bitcoin_client::BitcoinClientWrapper,
};

#[derive(Clone)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<RwLock<BitcoinClientWrapper>>,
    network: Network,
    enclave_client: Arc<ReqwestClient>,
    enclave_client_url: String,
}

impl BitcoinRpcPrecompile {
    pub fn new(
        config: &BitcoinConfig,
        enclave_url: String,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        let client = BitcoinClientWrapper::new(config)?;
        let enclave_client = ReqwestClient::new();

        Ok(Self {
            bitcoin_client: Arc::new(RwLock::new(client)),
            network: config.network,
            enclave_client: Arc::new(enclave_client),
            enclave_client_url: enclave_url,
        })
    }

    fn call_enclave<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<R, PrecompileErrors> {
        let url = format!("{}/{}", self.enclave_client_url, endpoint);

        self.enclave_client
            .post(&url)
            .json(payload)
            .send()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "Enclave RPC call failed: {:?}",
                    e
                )))
            })?
            .json()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "Failed to parse enclave response: {:?}",
                    e
                )))
            })
    }

    fn send_raw_transaction(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (10_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

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

        // Convert the Txid to raw bytes and reverse the byte order
        let mut txid_bytes: [u8; 32] = txid.to_raw_hash().to_byte_array();
        txid_bytes.reverse();

        Ok(PrecompileOutput::new(
            gas_used,
            RethBytes::from(txid_bytes.to_vec()),
        ))
    }

    fn get_block_count(&self) -> PrecompileResult {
        let gas_used: u64 = 2_000_u64;

        let block_count = self.bitcoin_client.read().get_block_count().map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other("Failed to get block count"))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            reth::primitives::Bytes::from(block_count.to_be_bytes().to_vec()),
        ))
    }

    fn decode_raw_transaction(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (4_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

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
                PrecompileErrors::Error(PrecompileError::other(
                    "Decode raw transaction bitcoin rpc call failed",
                ))
            })?;

        let encoded_data: AlloyBytes = abi_encode_tx_data(&data, &self.network).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Failed to encode transaction data: {:?}",
                e
            )))
        })?;

        // Convert AlloyBytes to RethBytes by creating a new RethBytes from the underlying Vec<u8>
        let reth_bytes = RethBytes::from(encoded_data.to_vec());
        Ok(PrecompileOutput::new(gas_used, reth_bytes))
    }

    fn check_signature(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
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
            match self
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

    fn derive_btc_address(
        &self,
        ethereum_address_trimmed: &str,
    ) -> Result<String, PrecompileErrors> {
        let enclave_request = serde_json::json!({
            "ethereum_address": ethereum_address_trimmed
        });

        let response: serde_json::Value = self.call_enclave("derive_address", &enclave_request)?;

        response["address"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                PrecompileErrors::Error(PrecompileError::Other(
                    "Failed to extract Bitcoin address from response".to_string(),
                ))
            })
    }

    fn convert_address(&self, input: &[u8]) -> PrecompileResult {
        let gas_used: u64 = 3_000_u64;

        // Convert input to a hex string and remove '0x' if present
        let ethereum_address_hex = hex::encode(input);
        let ethereum_address_trimmed = ethereum_address_hex.trim_start_matches("0x");

        let bitcoin_address = self.derive_btc_address(ethereum_address_trimmed)?;

        Ok(PrecompileOutput::new(
            gas_used,
            reth::primitives::Bytes::from(bitcoin_address.as_bytes().to_vec()),
        ))
    }

    fn create_and_sign_raw_transaction(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (5_000 + input.len() * 3) as u64;
        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let decoded_input: DecodedInput = decode_input(input)?;
        let utxos = parse_utxos(&decoded_input.utxos)?;

        let total_input: u64 = utxos
            .iter()
            .map(|utxo| utxo["amount"].as_u64().unwrap())
            .sum();
        let fee = 1000000; // TODO: Add dynamic fee estimation

        let mut outputs = vec![serde_json::json!({
            "address": decoded_input.destination,
            "amount": decoded_input.amount,
        })];

        // Add change output if necessary
        if total_input > decoded_input.amount + fee {
            let change_amount = total_input - decoded_input.amount - fee;
            let bitcoin_address = self.derive_btc_address(&decoded_input.signer)?;
            outputs.push(serde_json::json!({
                "address": bitcoin_address,
                "amount": change_amount,
            }));
        }

        let sign_request = serde_json::json!({
            "ethereum_address": decoded_input.signer,
            "inputs": utxos,
            "outputs": outputs,
        });

        let sign_response: serde_json::Value =
            self.call_enclave("sign_transaction", &sign_request)?;

        let signed_tx_hex = sign_response["signed_tx"].as_str().ok_or_else(|| {
            PrecompileErrors::Error(PrecompileError::other("Missing signed_tx in response"))
        })?;

        let signed_tx_bytes = hex::decode(signed_tx_hex).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Failed to decode signed transaction into hex: {:?}",
                e
            )))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            RethBytes::from(signed_tx_bytes),
        ))
    }
}

impl StatefulPrecompile for BitcoinRpcPrecompile {
    fn call(
        &self,
        input: &reth::primitives::Bytes,
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
            0x00000000 => self.send_raw_transaction(&input[4..], 100_000),
            0x00000001 => self.get_block_count(),
            0x00000002 => self.decode_raw_transaction(&input[4..], 150_000),
            0x00000003 => self.check_signature(&input[4..], 100_000),
            0x00000004 => self.convert_address(&input[4..]),
            0x00000005 => self.create_and_sign_raw_transaction(&input, 250_000),
            _ => Err(PrecompileErrors::Error(PrecompileError::other(
                "Unsupported Bitcoin RPC method",
            ))),
        }
    }
}
