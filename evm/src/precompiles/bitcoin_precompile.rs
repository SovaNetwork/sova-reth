use abi::{abi_encode_tx_data, decode_input, DecodedInput};
pub use btc_client::{BitcoinClient, BitcoinClientError};
use revm_precompile::interface::{PrecompileError, PrecompileResult};
use revm_precompile::PrecompileOutput;
use sova_chainspec::BitcoinPrecompileMethod;
use tracing::{debug, error, info, warn};

use std::{env, str::FromStr, sync::Arc};

use eyre::Result;
use reqwest::blocking::Client as BlockingRequestClient;
use serde::Deserialize;

use alloy_primitives::Bytes;

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, Txid};

use super::abi;
use super::address_deriver::SovaAddressDeriver;
use super::btc_client;

pub use super::precompile_utils::BitcoinMethodHelper;

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

        // Calculate gas used
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::BroadcastTransaction,
            input.len(),
        );

        // Enforce limit if the precompile accounts for dynamic input lengths
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

        // Calculate gas used
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::DecodeTransaction,
            input.len(),
        );

        // Enforce limit if the precompile accounts for dynamic input lengths
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

        // Calculate gas used
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::ConvertAddress,
            input.len(),
        );

        // Enforce limit if the precompile accounts for dynamic input lengths
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

        // Calculate gas used
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::VaultSpend,
            input.len(),
        );

        // Enforce limit if the precompile accounts for dynamic input lengths
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

    fn is_already_in_chain_msg(s: &str) -> bool {
        let m = s.to_ascii_lowercase();
        m.contains("outputs already in utxo set")
            || m.contains("already in block chain")
            || m.contains("code: -27")
            || m.contains("(-27)")
    }

    fn is_already_known_msg(s: &str) -> bool {
        let m = s.to_ascii_lowercase();
        m.contains("already in the mempool")
            || m.contains("already known")
            || m.contains("duplicate transaction")
    }

    fn is_inputs_missing_or_spent_msg(s: &str) -> bool {
        let m = s.to_ascii_lowercase();
        m.contains("missingorspent") || m.contains("code: -25") || m.contains("(-25)")
    }

    fn broadcast_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Txid, PrecompileError> {
        match self.bitcoin_client.send_raw_transaction(tx) {
            Ok(txid) => {
                info!("Broadcast bitcoin txid: {}", txid);
                Ok(txid)
            }
            Err(e) => {
                let txid = tx.txid();
                debug!("Failed to broadcast transaction: {}", e);

                // 1) Structured JSON-RPC with numeric codes
                if let BitcoinClientError::BitcoinCoreRpc(bitcoincore_rpc::Error::JsonRpc(j)) = &e {
                    if let bitcoincore_rpc::jsonrpc::error::Error::Rpc(rpc) = j {
                        match rpc.code {
                            -27 => {
                                debug!(
                                    "Idempotent: already in chain (-27). txid={} msg={}",
                                    txid, rpc.message
                                );
                                return Ok(txid);
                            }
                            -26 => {
                                if Self::is_already_known_msg(&rpc.message) {
                                    debug!(
                                        "Idempotent: already known (-26). txid={} msg={}",
                                        txid, rpc.message
                                    );
                                    return Ok(txid);
                                }
                                warn!("WARNING: Transaction rejected: {} (code: -26)", rpc.message);
                                return Err(PrecompileError::Other(format!(
                                    "Transaction rejected: {}",
                                    rpc.message
                                )));
                            }
                            -25 => {
                                debug!(
                                    "Soft-success: inputs missing/spent (-25). txid={} msg={}",
                                    txid, rpc.message
                                );
                                return Ok(txid);
                            }
                            _ => {
                                warn!(
                                    "WARNING: Bitcoin RPC error: {} (code: {})",
                                    rpc.message, rpc.code
                                );
                                return Err(PrecompileError::Other(format!(
                                    "Bitcoin RPC error: {} (code: {})",
                                    rpc.message, rpc.code
                                )));
                            }
                        }
                    }
                    warn!("WARNING: JSON-RPC error: {j:?}");
                    return Err(PrecompileError::Other(format!("JSON-RPC error: {j:?}")));
                }

                // 2) String-like paths. Normalize by substring.
                let msg_norm = match &e {
                    BitcoinClientError::BitcoinCoreRpc(bitcoincore_rpc::Error::ReturnedError(
                        m,
                    )) => m.to_string(),
                    BitcoinClientError::Reqwest(err) => err.to_string(),
                    BitcoinClientError::RpcError(m) => m.clone(),
                    other => format!("{other:?}"),
                };

                if Self::is_already_in_chain_msg(&msg_norm) {
                    debug!(
                        "Idempotent: already in chain (string). txid={} msg={}",
                        txid, msg_norm
                    );
                    return Ok(txid);
                }
                if Self::is_already_known_msg(&msg_norm) {
                    debug!(
                        "Idempotent: already known (string). txid={} msg={}",
                        txid, msg_norm
                    );
                    return Ok(txid);
                }
                if Self::is_inputs_missing_or_spent_msg(&msg_norm) {
                    debug!(
                        "Soft-success: inputs missing/spent (string). txid={} msg={}",
                        txid, msg_norm
                    );
                    return Ok(txid);
                }

                // 3) Anything else is a real error
                warn!("WARNING: Bitcoin client error: {e:?}");
                Err(PrecompileError::Other(format!(
                    "Bitcoin client error: {e:?}"
                )))
            }
        }
    }

    fn broadcast_btc_tx(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
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
        Ok(PrecompileOutput::new(gas_used, Bytes::from(response)))
    }

    fn decode_raw_transaction(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
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

        Ok(PrecompileOutput::new(
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

        let derived_bitcoin_address = self
            .address_deriver
            .derive_bitcoin_address(&ethereum_address_bytes)?
            .to_string();

        let bitcoin_address = if self.sequencer_mode {
            // derive address with network deposit pk and cache in indexer
            let cached_address = self.derive_btc_address_with_caching(&ethereum_address_bytes)?;

            // the cached_address is derived from the network-enclave and considered the
            // 'canonical' implementation that is why this invariant must hold true
            if cached_address != derived_bitcoin_address {
                error!("Derivation is not the same, this results in state mismatches");
            }

            cached_address
        } else {
            derived_bitcoin_address
        };

        Ok(PrecompileOutput::new(
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

        Ok(PrecompileOutput::new(gas_used, Bytes::from(response)))
    }
}
