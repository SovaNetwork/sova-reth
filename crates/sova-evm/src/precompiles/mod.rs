mod abi;
mod btc_client;
mod precompile_utils;

use abi::{abi_encode_tx_data, decode_input, DecodedInput};
pub use btc_client::{BitcoinClient, SovaL1BlockInfo};
pub use precompile_utils::BitcoinMethod;

use std::{str::FromStr, sync::Arc};

use reqwest::blocking::Client as ReqwestClient;
use serde::{Deserialize, Serialize};

use alloy_primitives::{Address, Bytes};

use reth_revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use reth_tracing::tracing::{debug, info, warn};

use bitcoin::{
    consensus::encode::deserialize, hashes::Hash, Address as BtcAddress, Amount, Network, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use sova_chainspec::UBTC_CONTRACT_ADDRESS;

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

#[derive(Clone, Debug)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<BitcoinClient>,
    network: Network,
    http_client: Arc<ReqwestClient>,
    network_utxos_url: String,
    sequencer_mode: bool,
}

impl Default for BitcoinRpcPrecompile {
    fn default() -> Self {
        Self {
            bitcoin_client: Arc::new(BitcoinClient::default()),
            network: Network::Regtest,
            http_client: Arc::new(ReqwestClient::new()),
            network_utxos_url: String::new(),
            sequencer_mode: false,
        }
    }
}

impl BitcoinRpcPrecompile {
    pub fn new(
        bitcoin_client: Arc<BitcoinClient>,
        network: Network,
        network_utxos_url: String,
        sequencer_mode: bool,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        // Check for API key at initialization
        let api_key = std::env::var("NETWORK_UTXOS_API_KEY").unwrap_or_default();
        if api_key.is_empty() && sequencer_mode {
            warn!("WARNING: NETWORK_UTXOS_API_KEY env var not set for sequencer mode. Auth to signing service will fail.");
        }

        Ok(Self {
            bitcoin_client,
            network,
            http_client: Arc::new(ReqwestClient::new()),
            network_utxos_url,
            sequencer_mode,
        })
    }

    pub fn sequencer_mode(&mut self) {
        self.sequencer_mode = true;
    }

    pub fn run(&self, input: &Bytes, caller: &Address) -> PrecompileResult {
        let method = BitcoinMethod::try_from(input).map_err(|e| {
            PrecompileError::Other(
                "Invalid precompile method selector".to_string() + &e.to_string(),
            )
        })?;

        // Skip the selector bytes and get the method's input data
        let input_data = &input[BitcoinMethod::SELECTOR_SIZE..];

        // Calculate gas used based on input length
        let gas_used = method.calculate_gas_used(input_data.len());

        // Check if gas exceeds method's limit using the new helper method
        if method.is_gas_limit_exceeded(input_data.len()) {
            return Err(PrecompileError::OutOfGas);
        }

        let res = match method {
            BitcoinMethod::BroadcastTransaction => self.broadcast_btc_tx(input_data, gas_used),
            BitcoinMethod::DecodeTransaction => self.decode_raw_transaction(input_data, gas_used),
            BitcoinMethod::CheckSignature => self.check_signature(input_data, gas_used),
            BitcoinMethod::ConvertAddress => self.convert_address(input_data, gas_used),
            BitcoinMethod::VaultSpend => self.network_spend(input, caller, gas_used),
        };

        if res.is_err() {
            warn!("Precompile error: {:?}", res);
        }

        res
    }

    fn call_network_utxos<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        payload: &T,
    ) -> Result<R, PrecompileError> {
        let url = format!("{}/{}", self.network_utxos_url, endpoint);

        // Get API key from environment
        let api_key = std::env::var("NETWORK_UTXOS_API_KEY").unwrap_or_default();

        // Log warning if API key is missing
        if api_key.is_empty() {
            warn!("WARNING: NETWORK_UTXOS_API_KEY environment variable is not set or empty");
        }

        let mut request = self.http_client.post(&url);

        // Add API key header if it exists
        if !api_key.is_empty() {
            request = request.header("x-api-key", api_key);
        }

        // Add request payload
        request = request.json(payload);

        debug!("request: {:?}", request);

        // Send request
        let response = match request.send() {
            Ok(resp) => resp,
            Err(e) => {
                warn!("WARNING: HTTP request to enclave failed: {}", e);
                return Err(PrecompileError::Other(format!(
                    "HTTP request failed: {}",
                    e
                )));
            }
        };

        debug!("indexer response status: {}", response.status().is_success());

        // Parse response
        match response.json() {
            Ok(res) => Ok(res),
            Err(e) => {
                warn!("WARNING: Failed to parse enclave response: {}", e);

                Err(PrecompileError::Other(format!(
                    "Failed to parse response: {}",
                    e
                )))
            }
        }
    }

    fn format_txid_to_bytes32(&self, txid: bitcoin::Txid) -> Vec<u8> {
        // format to match slot locking service
        // Reverse the byte order (Bitcoin hashes are reversed compared to Ethereum)
        let mut bytes = txid.to_raw_hash().to_byte_array().to_vec();
        bytes.reverse();

        // Encode the response: txid (32 bytes)
        let mut response = Vec::with_capacity(32);
        response.extend_from_slice(&bytes);
        response
    }

    fn broadcast_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Txid, PrecompileError> {
        // Attempt to broadcast the transaction
        match self.bitcoin_client.send_raw_transaction(tx) {
            Ok(txid) => {
                // Successfully broadcast
                info!("Broadcast bitcoin txid: {}", txid);
                Ok(txid)
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
                                        Ok(tx.txid())
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
                                            Ok(tx.txid())
                                        } else {
                                            // Other type of rejection
                                            warn!(
                                                "WARNING: Transaction rejected: {} (code: {})",
                                                rpc_error.message, rpc_error.code
                                            );
                                            Err(PrecompileError::Other(format!(
                                                "Transaction rejected: {}",
                                                rpc_error.message
                                            )))
                                        }
                                    }
                                    // Other RPC error
                                    _ => {
                                        warn!(
                                            "WARNING: Bitcoin RPC error: {} (code: {})",
                                            rpc_error.message, rpc_error.code
                                        );
                                        Err(PrecompileError::Other(format!(
                                            "Bitcoin RPC error: {} (code: {})",
                                            rpc_error.message, rpc_error.code
                                        )))
                                    }
                                }
                            }
                            // Other JSON-RPC errors
                            _ => {
                                warn!("WARNING: JSON-RPC error: {:?}", jsonrpc_err);
                                Err(PrecompileError::Other(format!(
                                    "JSON-RPC error: {:?}",
                                    jsonrpc_err
                                )))
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
                            debug!("Transaction already known: {} ({})", tx.txid(), err_msg);
                            Ok(tx.txid())
                        } else {
                            warn!("WARNING: Bitcoin returned error: {}", err_msg);
                            Err(PrecompileError::Other(format!(
                                "Bitcoin returned error: {}",
                                err_msg
                            )))
                        }
                    }
                    // All other error types
                    _ => {
                        warn!("WARNING: Bitcoin client error: {:?}", e);
                        Err(PrecompileError::Other(format!(
                            "Bitcoin client error: {:?}",
                            e
                        )))
                    }
                }
            }
        }
    }

    fn broadcast_btc_tx(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        // Deserialize the Bitcoin transaction
        let tx: bitcoin::Transaction = match deserialize(input) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("Failed to deserialize Bitcoin transaction: {}", e);
                return Err(PrecompileError::Other(
                    "Failed to deserialize Bitcoin transaction".into(),
                ));
            }
        };

        let txid = self.broadcast_transaction(&tx)?;

        let response = self.format_txid_to_bytes32(txid);
        Ok(PrecompileOutput::new(gas_used, Bytes::from(response)))
    }

    fn decode_raw_transaction(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileError::Other("Failed to deserialize Bitcoin transaction".into())
        })?;

        let data = self
            .bitcoin_client
            .decode_raw_transaction(&tx)
            .map_err(|_| {
                PrecompileError::Other("Decode raw transaction bitcoin rpc call failed".into())
            })?;

        let encoded_data = abi_encode_tx_data(&data, &self.network).map_err(|e| {
            PrecompileError::Other(format!("Failed to encode transaction data: {:?}", e))
        })?;

        Ok(PrecompileOutput::new(
            gas_used,
            Bytes::from(encoded_data.to_vec()),
        ))
    }

    fn check_signature(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileError::Other("Failed to deserialize Bitcoin transaction".into())
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
            PrecompileError::Other(format!("Transaction verification failed: {:?}", e))
        })?;

        Ok(PrecompileOutput::new(gas_used, Bytes::from(vec![1])))
    }

    fn derive_btc_address(&self, ethereum_address: &str) -> Result<String, PrecompileError> {
        // TODO(powvt): can this call fail and the tx execution still succeed?
        let request = serde_json::json!({ "evm_address": ethereum_address });
        let response: serde_json::Value = self.call_network_utxos("derive-address", &request)?;

        debug!("derive-address response: {:?}", response);

        response["btc_address"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                PrecompileError::Other("Failed to extract Bitcoin address from response".into())
            })
    }

    fn convert_address(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let encoded = hex::encode(input);
        let ethereum_address_hex = encoded.as_str();
        let bitcoin_address = self.derive_btc_address(ethereum_address_hex)?;

        Ok(PrecompileOutput::new(
            gas_used,
            Bytes::from(bitcoin_address.as_bytes().to_vec()),
        ))
    }

    fn network_spend(&self, input: &[u8], caller: &Address, gas_used: u64) -> PrecompileResult {
        // only the native bitcoin wrapper contract can call this method
        if caller != &UBTC_CONTRACT_ADDRESS {
            return Err(
                PrecompileError::Other("Unauthorized caller for vaultSpend. Only the enshrined uBTC contract may call this precompile.".to_string())
            );
        }

        let decoded_input: DecodedInput = decode_input(input)?;

        // get network spendable UTXOs
        // TODO(powvt): use the block height from 6 blocks ago to ensure the spendables are confirmed.
        // TODO(powvt): validate gas and amount params are correct here. Is this accounted for in UTXO selection service? I dont think so..
        let utxo_request = serde_json::json!({
            "block_height": decoded_input.block_height,
            "target_amount": decoded_input.amount
        });

        let selected_utxos_resp: serde_json::Value =
            self.call_network_utxos("select-utxos", &utxo_request)?;

        let selected_utxos: Vec<UtxoUpdate> =
            serde_json::from_value(selected_utxos_resp["selected_utxos"].clone())
                .map_err(|e| PrecompileError::Other(format!("UTXO parse error: {}", e)))?;

        let inputs: Vec<SignTxInputData> = selected_utxos
            .iter()
            .map(|utxo| SignTxInputData {
                txid: utxo.txid.clone(),
                vout: utxo.vout as u32,
                amount: utxo.amount as u64,
            })
            .collect();

        let total_input: u64 = inputs.iter().map(|input| input.amount).sum();

        // TODO(powvt): Add dynamic fee estimation
        let fee = decoded_input.btc_gas_limit;
        let total_withdrawn = decoded_input.amount + fee;

        if total_input < total_withdrawn {
            warn!("Insufficient funds for vault spend. Signer {}, total_input {}, requested amount {}", &decoded_input.signer, total_input, total_withdrawn);

            return Err(PrecompileError::Other(
                "Insufficient funds for vault spend".to_string(),
            ));
        }

        let mut outputs = vec![serde_json::json!({
            "address": decoded_input.destination,
            "amount": decoded_input.amount,
        })];

        if total_input > total_withdrawn {
            let change_amount = total_input - decoded_input.amount - fee;
            let bitcoin_address = self.derive_btc_address(&decoded_input.signer)?;
            outputs.push(serde_json::json!({
                "address": bitcoin_address,
                "amount": change_amount,
            }));
        }

        let response: Vec<u8> = if self.sequencer_mode {
            // sign using network pk
            // TODO(powvt): add Auth/API key for this call to the signing endpoint on the sequencer.

            let sign_request = serde_json::json!({
                "inputs": inputs,
                "outputs": outputs,
            });

            let sign_response: serde_json::Value =
                self.call_network_utxos("sign-transaction", &sign_request)?;

            let signed_tx_hex = sign_response["signed_tx"]
                .as_str()
                .ok_or_else(|| PrecompileError::Other("Missing signed_tx in response".into()))?;

            let signed_tx_bytes = hex::decode(signed_tx_hex).map_err(|e| {
                PrecompileError::Other(format!(
                    "Vault Spend Precompile: Failed to decode signed transaction into hex: {:?}",
                    e
                ))
            })?;

            // Deserialize the signed Bitcoin transaction
            let signed_tx: bitcoin::Transaction = deserialize(&signed_tx_bytes).map_err(|e| {
                PrecompileError::Other(format!(
                    "Vault Spend Precompile: Failed to deserialize signed Bitcoin transaction: {:?}",
                    e
                ))
            })?;

            // Broadcast the transaction
            let txid = self.broadcast_transaction(&signed_tx)?;

            self.format_txid_to_bytes32(txid)
        } else {
            // validator does not have access to network pk requests

            // NOTE(powvt): This conversion logic is duplicated in the signing service.
            // When the signing service receives a payload to be signed this same type conversion happens.
            // If the spent transaction type is ever modified it needs to be updated in both places.

            // Convert inputs to TxIn objects
            let tx_inputs: Vec<TxIn> = inputs
                .iter()
                .map(|input| {
                    let txid = Txid::from_str(&input.txid)
                        .map_err(|e| PrecompileError::Other(format!("Invalid txid: {:?}", e)))?;
                    let outpoint = OutPoint {
                        txid,
                        vout: input.vout,
                    };

                    Ok(TxIn {
                        previous_output: outpoint,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence(u32::MAX),
                        witness: Witness::default(),
                    })
                })
                .collect::<Result<Vec<TxIn>, PrecompileError>>()?;

            // Convert outputs to TxOut objects
            let tx_outputs: Vec<TxOut> = outputs
                .iter()
                .map(|output| {
                    let address_str = output["address"].as_str().ok_or_else(|| {
                        PrecompileError::Other("Missing address in output".into())
                    })?;
                    let amount = output["amount"]
                        .as_u64()
                        .ok_or_else(|| PrecompileError::Other("Missing amount in output".into()))?;

                    let address = BtcAddress::from_str(address_str)
                        .map_err(|e| PrecompileError::Other(format!("Invalid address: {:?}", e)))?
                        .require_network(self.network)
                        .map_err(|e| {
                            PrecompileError::Other(format!("Network mismatch: {:?}", e))
                        })?;

                    Ok(TxOut {
                        value: Amount::from_sat(amount),
                        script_pubkey: address.script_pubkey(),
                    })
                })
                .collect::<Result<Vec<TxOut>, PrecompileError>>()?;

            // Construct the transaction with the prepared inputs and outputs
            let tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: tx_inputs,
                output: tx_outputs,
            };

            self.format_txid_to_bytes32(tx.txid())
        };

        Ok(PrecompileOutput::new(gas_used, Bytes::from(response)))
    }
}
