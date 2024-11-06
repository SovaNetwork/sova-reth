use std::sync::Arc;

use serde::{Deserialize, Serialize};

use reqwest::blocking::Client as ReqwestClient;

use reth::revm::precompile::PrecompileOutput;
use reth_primitives::revm_primitives::{
    Bytes as RethBytes, Env, PrecompileError, PrecompileErrors, PrecompileResult,
    StatefulPrecompile,
};
use reth_tracing::tracing::{error, info};

use alloy_primitives::Bytes as AlloyBytes;

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, OutPoint, TxOut};

use crate::config::BitcoinConfig;

use super::{
    abi_decoding::{decode_input, DecodedInput},
    abi_encoding::abi_encode_tx_data,
    bitcoin_client::BitcoinClientWrapper,
};

#[derive(Deserialize)]
struct UtxoSelectionResponse {
    block_height: i32,
    address: String,
    target_amount: i64,
    selected_utxos: Vec<UtxoUpdate>,
    total_amount: i64,
}

#[derive(Deserialize)]
struct UtxoUpdate {
    id: String,
    address: String,
    public_key: Option<String>,
    txid: String,
    vout: i32,
    amount: i64,
    script_pub_key: String,
    script_type: String,
    created_at: String,
    block_height: i32,
    spent_txid: Option<String>,
    spent_at: Option<String>,
    spent_block: Option<i32>,
}

#[derive(Serialize)]
struct SignTxInputData {
    txid: String,
    vout: u32,
    amount: u64,
}

#[derive(Clone)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<BitcoinClientWrapper>,
    network: Network,
    http_client: Arc<ReqwestClient>,
    network_signing_url: String,
    network_utxo_url: String,
    btc_tx_queue_url: String,
}

impl BitcoinRpcPrecompile {
    pub fn new(
        config: &BitcoinConfig,
        network_signing_url: String,
        network_utxo_url: String,
        btc_tx_queue_url: String,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        let client = BitcoinClientWrapper::new(config)?;
        let http_client = ReqwestClient::new();

        Ok(Self {
            bitcoin_client: Arc::new(client),
            network: config.network,
            http_client: Arc::new(http_client),
            network_signing_url,
            network_utxo_url,
            btc_tx_queue_url,
        })
    }

    fn make_http_request<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        base_url: &str,
        endpoint: &str,
        method: reqwest::Method,
        payload: Option<&T>,
    ) -> Result<R, PrecompileErrors> {
        let url = format!("{}/{}", base_url, endpoint);
        let mut request = self.http_client.request(method.clone(), &url);

        if let Some(data) = payload {
            request = match method {
                reqwest::Method::GET => request.query(data),
                _ => request.json(data),
            };
        }

        request
            .send()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "HTTP request failed: {}",
                    e
                )))
            })?
            .json()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::other(format!(
                    "Failed to parse response: {}",
                    e
                )))
            })
    }

    fn call_enclave<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<R, PrecompileErrors> {
        self.make_http_request(
            &self.network_signing_url,
            endpoint,
            reqwest::Method::POST,
            Some(payload),
        )
    }

    fn call_utxo_selection<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<R, PrecompileErrors> {
        self.make_http_request(
            &self.network_utxo_url,
            endpoint,
            reqwest::Method::GET,
            Some(payload),
        )
    }

    fn call_btc_tx_queue(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (10_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        // Deserialize to verify transaction format
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::other(
                "Failed to deserialize Bitcoin transaction",
            ))
        })?;

        // Get txid for return value
        let txid = tx.txid();

        // Queue transaction for broadcasting
        let broadcast_request = serde_json::json!({
            "raw_tx": hex::encode(input)
        });

        // Queue transaction for broadcasting
        // TODO (@powvt): handle what about when the broadcast fails in the queue?
        match self.make_http_request::<_, serde_json::Value>(
            &self.btc_tx_queue_url,
            "broadcast",
            reqwest::Method::POST,
            Some(&broadcast_request),
        ) {
            Ok(_) => {
                info!(
                    "Successfully queued transaction for broadcast, txid: {}",
                    txid
                );
            }
            Err(e) => {
                error!("Failed to broadcast transaction: {}", e);
                // Continue execution despite error
            }
        }

        // Convert txid to bytes and return
        let mut txid_bytes: [u8; 32] = txid.to_raw_hash().to_byte_array();
        txid_bytes.reverse();

        Ok(PrecompileOutput::new(
            gas_used,
            RethBytes::from(txid_bytes.to_vec()),
        ))
    }

    /// TODO (@powvt): manually decode tx data, dont use node for this
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

    fn create_and_sign_raw_transaction(&self, input: &[u8]) -> PrecompileResult {
        let gas_used: u64 = 25_000_u64;

        let decoded_input: DecodedInput = decode_input(input)?;

        // Get bitcoin address for the signer
        let bitcoin_address = self.derive_btc_address(&decoded_input.signer)?;

        let endpoint = format!(
            "select-utxos/block/{}/address/{}/amount/{}",
            decoded_input.block_height, bitcoin_address, decoded_input.amount
        );

        // Call the UTXO selection service
        let selected_utxos: UtxoSelectionResponse = self.call_utxo_selection(&endpoint, &())?;

        let inputs: Vec<SignTxInputData> = selected_utxos
            .selected_utxos
            .into_iter()
            .map(|utxo| SignTxInputData {
                txid: utxo.txid,
                vout: utxo.vout as u32,
                amount: utxo.amount as u64,
            })
            .collect();

        // Calculate total input amount
        let total_input: u64 = inputs.iter().map(|input| input.amount).sum();

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
            "inputs": inputs,
            "outputs": outputs,
        });

        let sign_response: serde_json::Value =
            self.call_enclave("sign_transaction", &sign_request)?;

        let signed_tx_hex = sign_response["signed_tx"].as_str().ok_or_else(|| {
            PrecompileErrors::Error(PrecompileError::other("Missing signed_tx in response"))
        })?;

        info!("Signed transaction: {}", signed_tx_hex);

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
            0x00000001 => self.call_btc_tx_queue(&input[4..], 100_000),
            0x00000002 => self.decode_raw_transaction(&input[4..], 150_000),
            0x00000003 => self.check_signature(&input[4..], 100_000),
            0x00000004 => self.convert_address(&input[4..]),
            0x00000005 => self.create_and_sign_raw_transaction(&input),
            _ => Err(PrecompileErrors::Error(PrecompileError::other(
                "Unsupported Bitcoin RPC method",
            ))),
        }
    }
}
