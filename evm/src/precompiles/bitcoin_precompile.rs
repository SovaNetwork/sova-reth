use std::{env, str::FromStr, sync::Arc};

use eyre::Result;
use reqwest::blocking::Client as BlockingRequestClient;

use alloy_primitives::Bytes;

use reth_tracing::tracing::{debug, error, warn};
use revm_precompile::interface::{PrecompileError, PrecompileResult};
use revm_precompile::PrecompileOutput;

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network};

use abi::abi_encode_tx_data;
pub use btc_client::BitcoinClient;
use sova_chainspec::BitcoinPrecompileMethod;

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

#[derive(Clone, Debug)]
pub struct BitcoinRpcPrecompile {
    bitcoin_client: Arc<BitcoinClient>,
    network: Network,
    http_client: Arc<BlockingRequestClient>,
    network_utxos_url: String,
    add_to_address_derivation_cache: bool,
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
            add_to_address_derivation_cache: false,
            address_deriver,
        }
    }
}

impl BitcoinRpcPrecompile {
    pub fn new(
        bitcoin_client: Arc<BitcoinClient>,
        network: Network,
        network_utxos_url: String,
        add_to_address_derivation_cache: bool,
        address_deriver: Arc<SovaAddressDeriver>,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        // Check for env vars at initialization
        let api_key = std::env::var("NETWORK_UTXOS_API_KEY").unwrap_or_default();
        if api_key.is_empty() && add_to_address_derivation_cache {
            warn!("WARNING: NETWORK_UTXOS_API_KEY env var not set. Required for sequencer mode.");
        }

        Ok(Self {
            bitcoin_client,
            network,
            http_client: Arc::new(BlockingRequestClient::new()),
            network_utxos_url,
            add_to_address_derivation_cache,
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
        // Use hardcoded chainspec xpub based on network
        let derivation_xpub_str = match network {
            Network::Bitcoin => sova_chainspec::SOVA_MAINNET_DERIVATION_XPUB,
            Network::Testnet | Network::Signet => sova_chainspec::SOVA_TESTNET_DERIVATION_XPUB,
            Network::Regtest => sova_chainspec::SOVA_DEVNET_DERIVATION_XPUB,
            _ => panic!("Unsupported Bitcoin network: {network:?}"),
        };

        let derivation_xpub = bitcoin::bip32::Xpub::from_str(derivation_xpub_str)
            .expect("Invalid derivation xpub format");

        Arc::new(SovaAddressDeriver::new(derivation_xpub, network))
    }

    pub fn from_env() -> Self {
        // we call .unwrap() instead of .unwrap_or_else to cause a panic in case of missing environment variables
        // to do this, we call this function once (for sanity check) after the env vars are set just before node start

        let network = Network::from_str(&env::var("SOVA_BTC_NETWORK").unwrap()).unwrap();

        let bitcoin_client = BitcoinRpcPrecompile::client_from_env();

        let network_utxos_url = env::var("SOVA_NETWORK_UTXOS_URL").unwrap_or_default();

        let add_to_address_derivation_cache =
            env::var("ADD_TO_ADDRESS_DERIVATION_CACHE").is_ok_and(|v| v == "true");

        let address_deriver = Self::address_deriver_from_env(network);

        BitcoinRpcPrecompile::new(
            bitcoin_client,
            network,
            network_utxos_url,
            add_to_address_derivation_cache,
            address_deriver,
        )
        .expect("Failed to create BitcoinRpcPrecompile from environment")
    }

    pub fn run_broadcast_transaction(input: &[u8], gas_limit: u64) -> PrecompileResult {
        let btc_precompile = BitcoinRpcPrecompile::from_env();

        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::BroadcastTransaction,
            input.len(),
        );

        if gas_used > gas_limit {
            return Err(PrecompileError::OutOfGas);
        }

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

    pub fn run_decode_transaction(input: &[u8], gas_limit: u64) -> PrecompileResult {
        let btc_precompile = BitcoinRpcPrecompile::from_env();

        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::DecodeTransaction,
            input.len(),
        );

        if gas_used > gas_limit {
            return Err(PrecompileError::OutOfGas);
        }

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

    pub fn run_convert_address(input: &[u8], gas_limit: u64) -> PrecompileResult {
        let btc_precompile = BitcoinRpcPrecompile::from_env();

        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::ConvertAddress,
            input.len(),
        );

        if gas_used > gas_limit {
            return Err(PrecompileError::OutOfGas);
        }

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
        match self.bitcoin_client.send_raw_transaction(tx) {
            Ok(txid) => {
                debug!("Broadcasted Bitcoin tx: {}", txid);
                Ok(txid)
            }
            Err(e) => {
                let txid = tx.txid();

                // it is the sentinels job to rectify Bitcoin txs which do not get included in Bitcoin blocks
                debug!(
                    "Idempotent broadcast transaction, broadcast error ignored: {}",
                    e
                );
                Ok(txid)
            }
        }
    }

    fn broadcast_btc_tx(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = match deserialize(input) {
            Ok(tx) => tx,
            Err(e) => {
                debug!("Broadcast Precompile: Failed to deserialize Bitcoin tx: {e}");
                return Err(PrecompileError::Other(
                    "Broadcast Precompile: Failed to deserialize Bitcoin tx".into(),
                ));
            }
        };

        let txid = self.broadcast_transaction(&tx)?;

        Ok(PrecompileOutput::new(
            gas_used,
            Bytes::from(self.format_txid_to_bytes32(txid)),
        ))
    }

    fn decode_raw_transaction(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let tx: bitcoin::Transaction = deserialize(input).map_err(|e| {
            debug!("Decode Tx Precompile: Failed to deserialize Bitcoin tx: {e}");
            PrecompileError::Other("Decode Tx Precompile: Failed to deserialize Bitcoin tx".into())
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

    /// Call indexer to derive Bitcoin address instead of deriving locally
    /// This ensures the indexer caches the derivation and adds address to watched set
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

        let bitcoin_address = if self.add_to_address_derivation_cache {
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
}
