mod abi;
mod btc_client;
mod precompile_utils;

pub use precompile_utils::{BitcoinMethod, MethodError};
use reth_tracing::tracing::info;

use std::sync::Arc;

use abi::{abi_encode_tx_data, decode_input, DecodedInput};
pub use btc_client::BitcoinClient;
use reqwest::blocking::Client as ReqwestClient;
use serde::{Deserialize, Serialize};

use alloy_primitives::Bytes;

use reth_revm::primitives::{
    Env, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult, StatefulPrecompile,
};

use bitcoin::{consensus::encode::deserialize, Network, OutPoint, TxOut};

#[derive(Deserialize)]
struct BroadcastResponse {
    status: String,
    txid: Option<Vec<u8>>,
    current_block: u64,
    error: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct UtxoSelectionResponse {
    block_height: i32,
    address: String,
    target_amount: i64,
    selected_utxos: Vec<UtxoUpdate>,
    total_amount: i64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
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
    bitcoin_client: Arc<BitcoinClient>,
    network: Network,
    http_client: Arc<ReqwestClient>,
    network_signing_url: String,
    network_utxo_url: String,
    btc_tx_queue_url: String,
}

impl BitcoinRpcPrecompile {
    pub fn new(
        bitcoin_client: Arc<BitcoinClient>,
        network: Network,
        network_signing_url: String,
        network_utxo_url: String,
        btc_tx_queue_url: String,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        Ok(Self {
            bitcoin_client,
            network,
            http_client: Arc::new(ReqwestClient::new()),
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
                PrecompileErrors::Error(PrecompileError::Other(format!(
                    "HTTP request failed: {}",
                    e
                )))
            })?
            .json()
            .map_err(|e| {
                PrecompileErrors::Error(PrecompileError::Other(format!(
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

        let broadcast_request = serde_json::json!({
            "raw_tx": hex::encode(input)
        });

        let broadcast_response: BroadcastResponse = self
            .make_http_request(
                &self.btc_tx_queue_url,
                "broadcast",
                reqwest::Method::POST,
                Some(&broadcast_request),
            )
            .map_err(|e| {
                info!("HTTP request to broadcast service failed: {}", e);
                PrecompileErrors::Error(PrecompileError::Other(format!(
                    "HTTP request to broadcast service failed: {}",
                    e
                )))
            })?;

        if broadcast_response.status != "success" {
            info!(
                "Broadcast btc tx precompile error: {:?}",
                broadcast_response.error
            );
            return Err(PrecompileErrors::Error(PrecompileError::Other(
                broadcast_response
                    .error
                    .unwrap_or_else(|| "Broadcast service error".into()),
            )));
        } else {
            let txid_str = hex::encode(broadcast_response.txid.clone().unwrap());
            info!("Broadcast bitcoin txid: {}", txid_str);
        }

        // Encode the response: txid (32 bytes) followed by current block height (8 bytes)
        let mut response = Vec::with_capacity(40);

        // Get txid bytes directly from the response
        let txid_bytes = broadcast_response.txid.ok_or_else(|| {
            info!("No txid in broadcast response");
            PrecompileErrors::Error(PrecompileError::Other(
                "No txid in broadcast response".into(),
            ))
        })?;

        response.extend_from_slice(&txid_bytes);
        response.extend_from_slice(&broadcast_response.current_block.to_be_bytes());

        Ok(PrecompileOutput::new(gas_used, Bytes::from(response)))
    }

    fn decode_raw_transaction(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (4_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::Other(
                "Failed to deserialize Bitcoin transaction".into(),
            ))
        })?;

        let data = self
            .bitcoin_client
            .decode_raw_transaction(&tx)
            .map_err(|_| {
                PrecompileErrors::Error(PrecompileError::Other(
                    "Decode raw transaction bitcoin rpc call failed".into(),
                ))
            })?;

        let encoded_data = abi_encode_tx_data(&data, &self.network).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Failed to encode transaction data: {:?}",
                e
            )))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            Bytes::from(encoded_data.to_vec()),
        ))
    }

    fn check_signature(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = (6_000 + input.len() * 3) as u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileErrors::Error(PrecompileError::Other(
                "Failed to deserialize Bitcoin transaction".into(),
            ))
        })?;

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

        tx.verify(&mut spent).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Transaction verification failed: {:?}",
                e
            )))
        })?;

        Ok(PrecompileOutput::new(gas_used, Bytes::from(vec![1])))
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
                    "Failed to extract Bitcoin address from response".into(),
                ))
            })
    }

    fn convert_address(&self, input: &[u8]) -> PrecompileResult {
        let gas_used: u64 = 3_000_u64;

        let ethereum_address_hex = hex::encode(input);
        let ethereum_address_trimmed = ethereum_address_hex.trim_start_matches("0x");

        let bitcoin_address = self.derive_btc_address(ethereum_address_trimmed)?;

        Ok(PrecompileOutput::new(
            gas_used,
            Bytes::from(bitcoin_address.as_bytes().to_vec()),
        ))
    }

    fn create_and_sign_raw_transaction(&self, input: &[u8]) -> PrecompileResult {
        let gas_used: u64 = 25_000_u64;

        let decoded_input: DecodedInput = decode_input(input)?;
        let bitcoin_address = self.derive_btc_address(&decoded_input.signer)?;

        let endpoint = format!(
            "select-utxos/block/{}/address/{}/amount/{}",
            decoded_input.block_height, bitcoin_address, decoded_input.amount
        );

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

        let total_input: u64 = inputs.iter().map(|input| input.amount).sum();
        let fee = 1000000; // TODO: Add dynamic fee estimation

        let mut outputs = vec![serde_json::json!({
            "address": decoded_input.destination,
            "amount": decoded_input.amount,
        })];

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
            PrecompileErrors::Error(PrecompileError::Other(
                "Missing signed_tx in response".into(),
            ))
        })?;

        let signed_tx_bytes = hex::decode(signed_tx_hex).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::Other(format!(
                "Failed to decode signed transaction into hex: {:?}",
                e
            )))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            Bytes::from(signed_tx_bytes),
        ))
    }
}

impl StatefulPrecompile for BitcoinRpcPrecompile {
    fn call(&self, input: &Bytes, _gas_price: u64, _env: &Env) -> PrecompileResult {
        let method = BitcoinMethod::try_from(input)
            .map_err(|e| PrecompileErrors::Error(PrecompileError::Other(e.to_string())))?;

        // Skip the selector bytes and get the method's input data
        let input_data = &input[4..];

        match method {
            BitcoinMethod::BroadcastTransaction => {
                self.call_btc_tx_queue(input_data, method.gas_limit())
            }
            BitcoinMethod::DecodeTransaction => {
                self.decode_raw_transaction(input_data, method.gas_limit())
            }
            BitcoinMethod::CheckSignature => self.check_signature(input_data, method.gas_limit()),
            BitcoinMethod::ConvertAddress => self.convert_address(input_data),
            BitcoinMethod::CreateAndSignTransaction => self.create_and_sign_raw_transaction(input),
        }
    }
}
