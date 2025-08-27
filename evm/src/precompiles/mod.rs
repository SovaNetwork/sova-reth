mod abi;
mod address_deriver;
mod btc_client;
mod precompile_utils;

use abi::{abi_encode_tx_data, decode_input, DecodedInput};
pub use btc_client::{BitcoinClient, BitcoinClientError};
use once_cell::race::OnceBox;
use revm_precompile::interface::{PrecompileError, PrecompileResult};
use tracing::{debug, info, warn};

use std::{env, str::FromStr, sync::Arc};

use reqwest::blocking::Client as BlockingRequestClient;
use serde::Deserialize;

use alloy_primitives::Bytes;

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, Txid};

use sova_chainspec::{
    BitcoinPrecompileMethod, BITCOIN_BROADCAST_BASE_GAS, BITCOIN_CONVERT_BASE_GAS,
    BITCOIN_DECODE_BASE_GAS, BITCOIN_VAULT_SPEND_BASE_GAS, BROADCAST_TRANSACTION_ADDRESS,
    BROADCAST_TRANSACTION_PRECOMPILE_ID, CONVERT_ADDRESS_PRECOMPILE_ID,
    DECODE_TRANSACTION_PRECOMPILE_ID, SOVA_BTC_CONTRACT_ADDRESS, VAULT_SPEND_ADDRESS,
    VAULT_SPEND_PRECOMPILE_ID,
};

use crate::precompiles::address_deriver::SovaAddressDeriver;
pub use crate::precompiles::precompile_utils::BitcoinMethodHelper;
use eyre::Result;

#[derive(Debug, Clone)]
pub struct SovaBitcoinConfig {
    pub network: Network,
    pub network_url: String,
    pub rpc_username: String,
    pub rpc_password: String,
    pub rpc_connection_type: String,
}

impl SovaBitcoinConfig {
    pub fn new(
        network: Network,
        network_url: &str,
        rpc_username: &str,
        rpc_password: &str,
        rpc_connection_type: &str,
    ) -> Self {
        Self {
            network,
            network_url: network_url.to_string(),
            rpc_username: rpc_username.to_string(),
            rpc_password: rpc_password.to_string(),
            rpc_connection_type: rpc_connection_type.to_string(),
        }
    }

    pub fn with_connection_type(mut self, connection_type: &str) -> Self {
        self.rpc_connection_type = connection_type.to_string();
        self
    }
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

#[derive(Clone, Debug)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<BitcoinClient>,
    network: Network,
    http_client: Arc<BlockingRequestClient>,
    network_utxos_url: String,
    sequencer_mode: bool,
    address_deriver: Arc<SovaAddressDeriver>,
}

impl Default for BitcoinRpcPrecompile {
    fn default() -> Self {
        // Dummy address deriver for default (will panic if used without proper initialization)
        let dummy_xpub = "xpub123Ab".parse().expect("Invalid dummy xpub");

        let address_deriver = Arc::new(SovaAddressDeriver::new(dummy_xpub, Network::Regtest));

        Self {
            bitcoin_client: Arc::new(BitcoinClient::default()),
            network: Network::Regtest,
            http_client: Arc::new(BlockingRequestClient::new()),
            network_utxos_url: String::new(),
            sequencer_mode: false,
            address_deriver,
        }
    }
}

impl BitcoinRpcPrecompile {
    pub fn new(
        bitcoin_client: Arc<BitcoinClient>,
        network: Network,
        network_utxos_url: String,
        sequencer_mode: bool,
        address_deriver: Arc<SovaAddressDeriver>,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        // Check for env vars at initialization
        let api_key = std::env::var("NETWORK_UTXOS_API_KEY").unwrap_or_default();
        if api_key.is_empty() && sequencer_mode {
            warn!("WARNING: NETWORK_UTXOS_API_KEY env var not set. Required for sequencer mode.");
        }

        Ok(Self {
            bitcoin_client,
            network,
            http_client: Arc::new(BlockingRequestClient::new()),
            network_utxos_url,
            sequencer_mode,
            address_deriver,
        })
    }

    pub fn config_from_env() -> SovaBitcoinConfig {
        let network = Network::from_str(&env::var("SOVA_BTC_NETWORK").unwrap()).unwrap();
        SovaBitcoinConfig::new(
            network,
            &env::var("SOVA_BTC_NETWORK_URL").unwrap(),
            &env::var("SOVA_BTC_RPC_USERNAME").unwrap(),
            &env::var("SOVA_BTC_RPC_PASSWORD").unwrap(),
            &env::var("SOVA_RPC_CONNECTION_TYPE").unwrap(),
        )
    }

    pub fn client_from_env() -> Arc<BitcoinClient> {
        // we call .unwrap() instead of .unwrap_or_else to cause a panic in case of missing environment variables
        // to do this, we call this function once (for sanity check) after the env vars are set just before node start

        let bitcoin_config = BitcoinRpcPrecompile::config_from_env();

        // Convert SovaBitcoinConfig to BitcoinConfig
        let btc_config = btc_client::BitcoinConfig {
            network: bitcoin_config.network,
            network_url: bitcoin_config.network_url.clone(),
            rpc_username: bitcoin_config.rpc_username.clone(),
            rpc_password: bitcoin_config.rpc_password.clone(),
            rpc_connection_type: bitcoin_config.rpc_connection_type.clone(),
        };

        Arc::new(
            BitcoinClient::new(
                &btc_config,
                env::var("SOVA_SENTINEL_CONFIRMATION_THRESHOLD")
                    .unwrap()
                    .parse::<u8>()
                    .unwrap(),
                &btc_config.rpc_connection_type,
            )
            .unwrap(),
        )
    }

    fn address_deriver_from_env(network: Network) -> Arc<SovaAddressDeriver> {
        let derivation_xpub_str = env::var("SOVA_DERIVATION_XPUB")
            .expect("SOVA_DERIVATION_XPUB environment variable must be set");

        if derivation_xpub_str.trim().is_empty() {
            panic!("SOVA_DERIVATION_XPUB environment variable cannot be empty");
        }

        let derivation_xpub = bitcoin::bip32::Xpub::from_str(&derivation_xpub_str)
            .expect("Invalid SOVA_DERIVATION_XPUB format");

        Arc::new(SovaAddressDeriver::new(derivation_xpub, network))
    }

    pub fn from_env() -> Self {
        // we call .unwrap() instead of .unwrap_or_else to cause a panic in case of missing environment variables
        // to do this, we call this function once (for sanity check) after the env vars are set just before node start

        let network = Network::from_str(&env::var("SOVA_BTC_NETWORK").unwrap()).unwrap();

        let bitcoin_client = BitcoinRpcPrecompile::client_from_env();

        let network_utxos_url = env::var("SOVA_NETWORK_UTXOS_URL").unwrap_or_default();

        let sequencer_mode = env::var("SOVA_SEQUENCER_MODE").is_ok_and(|v| v == "true");

        let address_deriver = Self::address_deriver_from_env(network);

        BitcoinRpcPrecompile::new(
            bitcoin_client,
            network,
            network_utxos_url,
            sequencer_mode,
            address_deriver,
        )
        .expect("Failed to create BitcoinRpcPrecompile from environment")
    }

    pub fn run_broadcast_transaction(input: &[u8], _gas_limit: u64) -> PrecompileResult {
        let btc_precompile = BitcoinRpcPrecompile::from_env();

        // Calculate gas used based on input length
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::BroadcastTransaction,
            input.len(),
        );

        // Check if gas exceeds method's limit using the new helper method
        if BitcoinMethodHelper::is_gas_limit_exceeded(
            &BitcoinPrecompileMethod::BroadcastTransaction,
            input.len(),
        ) {
            return Err(PrecompileError::OutOfGas);
        }

        let input_bytes = Bytes::copy_from_slice(input);
        let res = btc_precompile.broadcast_btc_tx(&input_bytes, gas_used);

        if res.is_err() {
            warn!("Precompile error: {:?}", res);
        }

        res
    }

    pub fn run_decode_transaction(input: &[u8], _gas_limit: u64) -> PrecompileResult {
        let btc_precompile = BitcoinRpcPrecompile::from_env();

        // Calculate gas used based on input length
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::DecodeTransaction,
            input.len(),
        );

        // Check if gas exceeds method's limit using the new helper method
        if BitcoinMethodHelper::is_gas_limit_exceeded(
            &BitcoinPrecompileMethod::DecodeTransaction,
            input.len(),
        ) {
            return Err(PrecompileError::OutOfGas);
        }

        let input_bytes = Bytes::copy_from_slice(input);
        let res = btc_precompile.decode_raw_transaction(&input_bytes, gas_used);

        if res.is_err() {
            warn!("Precompile error: {:?}", res);
        }

        res
    }

    pub fn run_convert_address(input: &[u8], _gas_limit: u64) -> PrecompileResult {
        let btc_precompile = BitcoinRpcPrecompile::from_env();

        // Calculate gas used based on input length
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::ConvertAddress,
            input.len(),
        );

        // Check if gas exceeds method's limit using the new helper method
        if BitcoinMethodHelper::is_gas_limit_exceeded(
            &BitcoinPrecompileMethod::ConvertAddress,
            input.len(),
        ) {
            return Err(PrecompileError::OutOfGas);
        }

        let input_bytes = Bytes::copy_from_slice(input);
        let res = btc_precompile.convert_address(&input_bytes, gas_used);

        if res.is_err() {
            warn!("Precompile error: {:?}", res);
        }

        res
    }

    pub fn run_vault_spend(input: &[u8], _gas_limit: u64) -> PrecompileResult {
        let btc_precompile = BitcoinRpcPrecompile::from_env();

        // Calculate gas used based on input length
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::VaultSpend,
            input.len(),
        );

        // Check if gas exceeds method's limit using the new helper method
        if BitcoinMethodHelper::is_gas_limit_exceeded(
            &BitcoinPrecompileMethod::VaultSpend,
            input.len(),
        ) {
            return Err(PrecompileError::OutOfGas);
        }

        let res = btc_precompile.network_spend(input, gas_used);

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
                warn!("WARNING: HTTP request to enclave failed: {e}");
                return Err(PrecompileError::Other(format!("HTTP request failed: {e}",)));
            }
        };

        // Parse response
        match response.json() {
            Ok(res) => Ok(res),
            Err(e) => {
                warn!("WARNING: Failed to parse enclave response: {}", e);

                Err(PrecompileError::Other(format!(
                    "Failed to parse response: {e}",
                )))
            }
        }
    }

    fn format_txid_to_bytes32(&self, txid: bitcoin::Txid) -> Vec<u8> {
        // format to match slot locking service
        // Reverse the byte order (Bitcoin hashes are reversed compared to EVM)
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
                    // Handle BitcoinCoreRpc errors
                    BitcoinClientError::BitcoinCoreRpc(bitcoincore_rpc::Error::JsonRpc(
                        jsonrpc_err,
                    )) => {
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
                                    // TX_MISSING_INPUTS (bad-txns-inputs-missingorspent) (-25)
                                    -25 => {
                                        debug!(
                                            "Json rpc error -25 (inputs missing/spent). Txid: {} msg: {}",
                                            tx.txid(),
                                            rpc_error.message
                                        );
                                        // Return success since the transaction was likely already processed
                                        // The sentinel service will verify actual finality on Bitcoin
                                        Ok(tx.txid())
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
                                warn!("WARNING: JSON-RPC error: {jsonrpc_err:?}");
                                Err(PrecompileError::Other(format!(
                                    "JSON-RPC error: {jsonrpc_err:?}",
                                )))
                            }
                        }
                    }
                    // Handle ReturnedError
                    BitcoinClientError::BitcoinCoreRpc(bitcoincore_rpc::Error::ReturnedError(
                        err_msg,
                    )) => {
                        if err_msg.contains("already in block chain")
                            || err_msg.contains("already in the mempool")
                            || err_msg.contains("already known")
                            || err_msg.contains("duplicate transaction")
                        {
                            debug!("Transaction already known: {} ({err_msg})", tx.txid());
                            Ok(tx.txid())
                        } else {
                            warn!("WARNING: Bitcoin returned error: {err_msg}");
                            Err(PrecompileError::Other(format!(
                                "Bitcoin returned error: {err_msg}",
                            )))
                        }
                    }
                    // Handle other BitcoinClientError types
                    BitcoinClientError::Reqwest(reqwest_err) => {
                        // For external RPC client, check for common broadcast error patterns
                        let err_msg = reqwest_err.to_string();
                        if err_msg.contains("already in block chain")
                            || err_msg.contains("already in the mempool")
                            || err_msg.contains("already known")
                            || err_msg.contains("duplicate transaction")
                        {
                            debug!(
                                "Transaction already known via external client: {} ({err_msg})",
                                tx.txid()
                            );
                            Ok(tx.txid())
                        } else {
                            warn!("WARNING: External RPC client error: {reqwest_err}");
                            Err(PrecompileError::Other(format!(
                                "External RPC client error: {reqwest_err}",
                            )))
                        }
                    }
                    BitcoinClientError::RpcError(err_msg) => {
                        // Handle custom RPC errors from external client
                        if err_msg.contains("already in block chain")
                            || err_msg.contains("already in the mempool")
                            || err_msg.contains("already known")
                            || err_msg.contains("duplicate transaction")
                        {
                            debug!("Transaction already known: {} ({err_msg})", tx.txid());
                            Ok(tx.txid())
                        } else {
                            warn!("WARNING: RPC error: {err_msg}");
                            Err(PrecompileError::Other(format!("RPC error: {err_msg}",)))
                        }
                    }
                    // All other error types
                    _ => {
                        warn!("WARNING: Bitcoin client error: {e:?}");
                        Err(PrecompileError::Other(format!(
                            "Bitcoin client error: {e:?}",
                        )))
                    }
                }
            }
        }
    }

    pub fn broadcast_btc_tx(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        // Deserialize the Bitcoin transaction
        let tx: bitcoin::Transaction = match deserialize(input) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("Failed to deserialize Bitcoin transaction: {e}");
                return Err(PrecompileError::Other(
                    "Failed to deserialize Bitcoin transaction".into(),
                ));
            }
        };

        let txid = self.broadcast_transaction(&tx)?;

        let response = self.format_txid_to_bytes32(txid);
        Ok(revm_precompile::interface::PrecompileOutput::new(
            gas_used,
            Bytes::from(response),
        ))
    }

    pub fn decode_raw_transaction(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = deserialize(input).map_err(|_| {
            PrecompileError::Other("Failed to deserialize Bitcoin transaction".into())
        })?;

        let data = self
            .bitcoin_client
            .decode_raw_transaction(&tx)
            .map_err(|e| {
                PrecompileError::Other(format!(
                    "Decode raw transaction bitcoin rpc call failed: {e}"
                ))
            })?;

        let encoded_data = abi_encode_tx_data(&data, &self.network).map_err(|e| {
            PrecompileError::Other(format!("Failed to encode transaction data: {e:?}"))
        })?;

        Ok(revm_precompile::interface::PrecompileOutput::new(
            gas_used,
            Bytes::from(encoded_data.to_vec()),
        ))
    }

    fn parse_eth_address_bytes(&self, input: &[u8]) -> Result<[u8; 20], PrecompileError> {
        if input.len() != 20 {
            warn!("EVM address must be 20 bytes, got {}", input.len());
            return Err(PrecompileError::Other(format!(
                "EVM address must be 20 bytes, got {}",
                input.len()
            )));
        }

        let mut array = [0u8; 20];
        array.copy_from_slice(input);
        Ok(array)
    }

    /// Call indexer to derive Bitcoin address (sequencer mode only)
    /// This ensures the indexer caches the derivation AND adds address to watched set
    fn derive_btc_address_with_caching(
        &self,
        ethereum_address_bytes: &[u8; 20],
    ) -> Result<String, PrecompileError> {
        // Convert bytes to hex with 0x prefix for indexer API call
        let evm_address_hex = format!("0x{}", hex::encode(ethereum_address_bytes));

        let request = serde_json::json!({
            "evm_address": evm_address_hex
        });

        debug!("Calling indexer derive-address with: {}", evm_address_hex);

        let response: serde_json::Value = self.call_network_utxos("derive-address", &request)?;

        debug!("derive-address response: {:?}", response);

        // Extract the Bitcoin address from indexer response
        response["btc_address"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                PrecompileError::Other(
                    "Failed to extract Bitcoin address from indexer response".into(),
                )
            })
    }

    pub fn convert_address(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let ethereum_address_bytes = self.parse_eth_address_bytes(input)?;

        let bitcoin_address = if self.sequencer_mode {
            self.derive_btc_address_with_caching(&ethereum_address_bytes)?
        } else {
            self.address_deriver
                .derive_bitcoin_address(&ethereum_address_bytes)?
                .to_string()
        };

        Ok(revm_precompile::interface::PrecompileOutput::new(
            gas_used,
            Bytes::from(bitcoin_address.as_bytes().to_vec()),
        ))
    }

    pub fn network_spend(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let decoded_input: DecodedInput = decode_input(input)?;

        let mut request = serde_json::json!({
            "block_height": decoded_input.block_height,
            "amount": decoded_input.amount,
            "destination": decoded_input.destination,
            "fee": decoded_input.btc_gas_limit,
            "caller": decoded_input.caller, // msg.sender, data comes from contract
        });

        let response: Vec<u8> = if self.sequencer_mode {
            info!("Processing Bitcoin withdrawal as sequencer");

            let sign_response: serde_json::Value =
                self.call_network_utxos("sign-transaction", &request)?;

            let signed_tx_hex = sign_response["signed_tx"]
                .as_str()
                .ok_or_else(|| PrecompileError::Other("Missing signed_tx in response".into()))?;

            let txid_str = sign_response["txid"]
                .as_str()
                .ok_or_else(|| PrecompileError::Other("Missing txid in response".into()))?;
            info!("Signed txid {txid_str}");

            let signed_tx_bytes = hex::decode(signed_tx_hex).map_err(|e| {
                PrecompileError::Other(format!("Failed to decode signed transaction: {e:?}"))
            })?;

            let signed_tx: bitcoin::Transaction = deserialize(&signed_tx_bytes).map_err(|e| {
                PrecompileError::Other(format!(
                    "Failed to deserialize signed Bitcoin transaction: {e:?}"
                ))
            })?;

            let broadcast_txid = self.broadcast_transaction(&signed_tx)?;

            let expected_txid = Txid::from_str(txid_str).map_err(|e| {
                PrecompileError::Other(format!("Invalid txid from signing service: {e:?}"))
            })?;

            if broadcast_txid != expected_txid {
                warn!(
                    "Broadcast txid {broadcast_txid} does not match indexer txid {expected_txid}",
                );
            }

            self.format_txid_to_bytes32(expected_txid)
        } else {
            // remove caller field for prepare-transaction calls to indexer
            if let Some(obj) = request.as_object_mut() {
                obj.remove("caller");
            }

            let prepare_response: serde_json::Value =
                self.call_network_utxos("prepare-transaction", &request)?;

            let txid_str = prepare_response["txid"]
                .as_str()
                .ok_or_else(|| PrecompileError::Other("Missing txid in response".into()))?;

            debug!(
                "Network spend: Non-sequencer mode: received txid {}",
                txid_str
            );

            let txid = Txid::from_str(txid_str)
                .map_err(|e| PrecompileError::Other(format!("Invalid txid: {e:?}")))?;

            self.format_txid_to_bytes32(txid)
        };

        Ok(revm_precompile::interface::PrecompileOutput::new(
            gas_used,
            Bytes::from(response),
        ))
    }
}

//
// SovaPrecompiles - Following op-revm pattern to extend OpPrecompiles with Bitcoin functionality
//

use op_revm::{precompiles::OpPrecompiles, OpSpecId};
use revm_precompile::{u64_to_address, PrecompileOutput, PrecompileWithAddress, Precompiles};

// Import for PrecompileProvider trait
use revm::{
    context::{Cfg, ContextTr},
    handler::PrecompileProvider,
    interpreter::{InputsImpl, InterpreterResult},
};

/// Bitcoin transaction broadcast precompile
pub fn bitcoin_broadcast_transaction(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if BITCOIN_BROADCAST_BASE_GAS > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    // Caller validation is handled by SovaInspector before this function is called
    match BitcoinRpcPrecompile::run_broadcast_transaction(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(
            BITCOIN_BROADCAST_BASE_GAS,
            output.bytes,
        )),
        Err(e) => Err(e),
    }
}

/// Bitcoin transaction decode precompile
pub fn bitcoin_decode_transaction(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if BITCOIN_DECODE_BASE_GAS > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    match BitcoinRpcPrecompile::run_decode_transaction(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(BITCOIN_DECODE_BASE_GAS, output.bytes)),
        Err(e) => Err(e),
    }
}

/// Bitcoin address conversion precompile
pub fn bitcoin_convert_address(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if BITCOIN_CONVERT_BASE_GAS > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    match BitcoinRpcPrecompile::run_convert_address(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(
            BITCOIN_CONVERT_BASE_GAS,
            output.bytes,
        )),
        Err(e) => Err(e),
    }
}

/// Bitcoin vault spend precompile
pub fn bitcoin_vault_spend(input: &[u8], gas_limit: u64) -> PrecompileResult {
    if BITCOIN_VAULT_SPEND_BASE_GAS > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    // Caller validation is handled by SovaInspector before this function is called
    match BitcoinRpcPrecompile::run_vault_spend(input, gas_limit) {
        Ok(output) => Ok(PrecompileOutput::new(
            BITCOIN_VAULT_SPEND_BASE_GAS,
            output.bytes,
        )),
        Err(e) => Err(e),
    }
}

/// PrecompileWithAddress constants for Bitcoin precompiles
pub const BITCOIN_BROADCAST: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(BROADCAST_TRANSACTION_PRECOMPILE_ID),
    bitcoin_broadcast_transaction,
);

pub const BITCOIN_DECODE: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(DECODE_TRANSACTION_PRECOMPILE_ID),
    bitcoin_decode_transaction,
);

pub const BITCOIN_CONVERT: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(CONVERT_ADDRESS_PRECOMPILE_ID),
    bitcoin_convert_address,
);

pub const BITCOIN_VAULT_SPEND: PrecompileWithAddress = PrecompileWithAddress(
    u64_to_address(VAULT_SPEND_PRECOMPILE_ID),
    bitcoin_vault_spend,
);

/// SovaPrecompiles - extends OpPrecompiles with Bitcoin functionality
#[derive(Debug, Clone)]
pub struct SovaPrecompiles {
    /// Inner precompile provider based on OpPrecompiles.
    inner: OpPrecompiles,
    /// Spec id of the precompile provider.
    spec: OpSpecId,
}

impl SovaPrecompiles {
    /// Create a new precompile provider with the given OpSpec.
    #[inline]
    pub fn new_with_spec(spec: OpSpecId) -> Self {
        Self {
            inner: OpPrecompiles::new_with_spec(spec),
            spec,
        }
    }

    /// Precompiles getter.
    #[inline]
    pub fn precompiles(&self) -> &'static Precompiles {
        self.inner.precompiles()
    }

    /// Returns precompiles for Satoshi hardfork (static version)
    pub fn satoshi(spec: OpSpecId) -> &'static Precompiles {
        static INSTANCE: OnceBox<Precompiles> = OnceBox::new();
        INSTANCE.get_or_init(|| {
            let mut all_precompiles = OpPrecompiles::new_with_spec(spec).precompiles().clone();

            // Extend with Bitcoin precompiles for Satoshi fork
            all_precompiles.extend([
                BITCOIN_BROADCAST,
                BITCOIN_CONVERT,
                BITCOIN_DECODE,
                BITCOIN_VAULT_SPEND,
            ]);

            Box::new(all_precompiles)
        })
    }
}

impl Default for SovaPrecompiles {
    fn default() -> Self {
        Self::new_with_spec(OpSpecId::default())
    }
}

// Implementation of PrecompileProvider trait for SovaPrecompiles
impl<CTX> PrecompileProvider<CTX> for SovaPrecompiles
where
    CTX: ContextTr<Cfg: Cfg<Spec = OpSpecId>>,
{
    type Output = InterpreterResult;

    #[inline]
    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        if spec == self.spec {
            return false;
        }
        *self = Self::new_with_spec(spec);
        true
    }

    #[inline]
    fn run(
        &mut self,
        context: &mut CTX,
        address: &alloy_primitives::Address,
        inputs: &InputsImpl,
        is_static: bool,
        gas_limit: u64,
    ) -> Result<Option<Self::Output>, String> {
        // Extract caller address from inputs
        let caller = inputs.caller_address;

        // Handle Bitcoin precompiles with caller validation
        match *address {
            BROADCAST_TRANSACTION_ADDRESS => {
                // Only the native bitcoin wrapper contract can call this method
                if caller != SOVA_BTC_CONTRACT_ADDRESS {
                    return Err("Unauthorized precompile caller. Only the enshrined SovaBTC contract may broadcast transactions.".to_string());
                } else {
                    self.inner
                        .run(context, address, inputs, is_static, gas_limit)
                }
            }
            VAULT_SPEND_ADDRESS => {
                // Only the native bitcoin wrapper contract can call this method
                if caller != SOVA_BTC_CONTRACT_ADDRESS {
                    return Err("Unauthorized precompile caller. Only the enshrined SovaBTC contract may use network signing.".to_string());
                } else {
                    self.inner
                        .run(context, address, inputs, is_static, gas_limit)
                }
            }
            _ => {
                // Not a whitelisted Bitcoin precompile address
                self.inner
                    .run(context, address, inputs, is_static, gas_limit)
            }
        }
    }

    #[inline]
    fn warm_addresses(&self) -> Box<impl Iterator<Item = alloy_primitives::Address>> {
        <OpPrecompiles as PrecompileProvider<CTX>>::warm_addresses(&self.inner)
    }

    #[inline]
    fn contains(&self, address: &alloy_primitives::Address) -> bool {
        <OpPrecompiles as PrecompileProvider<CTX>>::contains(&self.inner, address)
    }
}
