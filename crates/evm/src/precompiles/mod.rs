mod abi;
mod btc_client;
mod precompile_utils;

pub use precompile_utils::BitcoinMethod;
use reth_tracing::tracing::{debug, info, warn};

use std::sync::Arc;

use abi::{abi_encode_tx_data, decode_input, DecodedInput};
pub use btc_client::BitcoinClient;
use reqwest::blocking::Client as ReqwestClient;
use serde::{Deserialize, Serialize};

use alloy_primitives::Bytes;

use reth_revm::primitives::{
    Env, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult, StatefulPrecompile,
};

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, OutPoint, TxOut};

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
}

impl BitcoinRpcPrecompile {
    pub fn new(
        bitcoin_client: Arc<BitcoinClient>,
        network: Network,
        network_signing_url: String,
        network_utxo_url: String,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        Ok(Self {
            bitcoin_client,
            network,
            http_client: Arc::new(ReqwestClient::new()),
            network_signing_url,
            network_utxo_url,
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

    fn send_btc_tx(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let gas_used: u64 = 21_000_u64;

        if gas_used > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        // Deserialize the Bitcoin transaction
        let tx: bitcoin::Transaction = match deserialize(input) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("Failed to deserialize Bitcoin transaction: {}", e);
                return Err(PrecompileErrors::Error(PrecompileError::Other(
                    "Failed to deserialize Bitcoin transaction".into(),
                )));
            }
        };

        // Get current block height for inclusion in the response
        let current_block = match self.bitcoin_client.get_block_height() {
            Ok(height) => height,
            Err(e) => {
                warn!("WARNING: Failed to get block height: {}", e);
                0 // Default to 0 if we can't get the height
            }
        };

        // Attempt to broadcast the transaction
        let txid: bitcoincore_rpc::bitcoin::Txid =
            match self.bitcoin_client.send_raw_transaction(&tx) {
                Ok(txid) => {
                    // Successfully broadcast
                    info!("Broadcast bitcoin txid: {}", txid);
                    txid
                }
                Err(e) => {
                    // Filter error codes from the node and return. The filter make transaction broadcasting idempotent.
                    // Meaning braodcasting a tx multiple times has the same effect as performing it once. In the context of
                    // block building this means when nodes are syncing and verifying transactions, they will get the same
                    // result as the entity that broadcast the tx.
                    //
                    // Filters include:
                    // - RPC_VERIFY_ALREADY_IN_CHAIN or RPC_TRANSACTION_ALREADY_IN_CHAIN (-27)
                    // - RPC_VERIFY_REJECTED or RPC_TRANSACTION_REJECTED (-26)
                    debug!("Failed to broadcast transaction: {}", e);
                    match &e {
                        // Handle JsonRpc errors
                        bitcoincore_rpc::Error::JsonRpc(jsonrpc_err) => {
                            match jsonrpc_err {
                                bitcoincore_rpc::jsonrpc::error::Error::Rpc(rpc_error) => {
                                    match rpc_error.code {
                                        // RPC_VERIFY_ALREADY_IN_CHAIN or RPC_TRANSACTION_ALREADY_IN_CHAIN (-27)
                                        -27 => {
                                            debug!(
                                                "Json rpc error -27. Txid: {} msg: {}",
                                                tx.txid(),
                                                rpc_error.message
                                            );
                                            tx.txid()
                                        }
                                        // RPC_VERIFY_REJECTED or RPC_TRANSACTION_REJECTED (-26)
                                        // TODO: Verify that all of these actually needed in a multi-node environment
                                        -26 => {
                                            let err_msg = &rpc_error.message;
                                            if err_msg.contains("already in mempool")
                                                || err_msg.contains("already known")
                                                || err_msg.contains("duplicate transaction")
                                            {
                                                debug!(
                                                    "Json rpc error -26. Txid: {} msg: {}",
                                                    tx.txid(),
                                                    rpc_error.message
                                                );
                                                tx.txid()
                                            } else {
                                                // Other type of rejection
                                                warn!(
                                                    "WARNING: Transaction rejected: {} (code: {})",
                                                    rpc_error.message, rpc_error.code
                                                );
                                                return Err(PrecompileErrors::Error(
                                                    PrecompileError::Other(format!(
                                                        "Transaction rejected: {}",
                                                        rpc_error.message
                                                    )),
                                                ));
                                            }
                                        }
                                        // Other RPC error
                                        _ => {
                                            warn!(
                                                "WARNING: Bitcoin RPC error: {} (code: {})",
                                                rpc_error.message, rpc_error.code
                                            );
                                            return Err(PrecompileErrors::Error(
                                                PrecompileError::Other(format!(
                                                    "Bitcoin RPC error: {} (code: {})",
                                                    rpc_error.message, rpc_error.code
                                                )),
                                            ));
                                        }
                                    }
                                }
                                // Other JSON-RPC errors
                                _ => {
                                    warn!("WARNING: JSON-RPC error: {:?}", jsonrpc_err);
                                    return Err(PrecompileErrors::Error(PrecompileError::Other(
                                        format!("JSON-RPC error: {:?}", jsonrpc_err),
                                    )));
                                }
                            }
                        }
                        // Handle ReturnedError
                        bitcoincore_rpc::Error::ReturnedError(err_msg) => {
                            if err_msg.contains("already in block chain")
                                || err_msg.contains("already in the mempool")
                                || err_msg.contains("already known")
                                || err_msg.contains("duplicate transaction")
                            {
                                info!("Transaction already known: {} ({})", tx.txid(), err_msg);
                                tx.txid()
                            } else {
                                warn!("WARNING: Bitcoin returned error: {}", err_msg);
                                return Err(PrecompileErrors::Error(PrecompileError::Other(
                                    format!("Bitcoin returned error: {}", err_msg),
                                )));
                            }
                        }
                        // All other error types
                        _ => {
                            warn!("WARNING: Bitcoin client error: {:?}", e);
                            return Err(PrecompileErrors::Error(PrecompileError::Other(format!(
                                "Bitcoin client error: {:?}",
                                e
                            ))));
                        }
                    }
                }
            };

        // format to match slot locking service
        let mut bytes = txid.to_raw_hash().to_byte_array().to_vec();
        bytes.reverse();

        // Encode the response: txid (32 bytes) followed by current block height (8 bytes)
        let mut response = Vec::with_capacity(40);
        response.extend_from_slice(&bytes);
        response.extend_from_slice(&current_block.to_be_bytes());

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
            BitcoinMethod::BroadcastTransaction => self.send_btc_tx(input_data, method.gas_limit()),
            BitcoinMethod::DecodeTransaction => {
                self.decode_raw_transaction(input_data, method.gas_limit())
            }
            BitcoinMethod::CheckSignature => self.check_signature(input_data, method.gas_limit()),
            BitcoinMethod::ConvertAddress => self.convert_address(input_data),
            BitcoinMethod::CreateAndSignTransaction => self.create_and_sign_raw_transaction(input),
        }
    }
}
