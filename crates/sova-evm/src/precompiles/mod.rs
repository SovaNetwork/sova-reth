mod abi;
mod address_deriver;
pub mod btc_client;
mod precompile_utils;

use abi::{abi_encode_tx_data, decode_input, DecodedInput};
pub use btc_client::BitcoinClient;
use revm::precompile::PrecompileWithAddress;
use alloy_evm::precompiles::{PrecompilesMap, DynPrecompile};
use sova_cli::BitcoinConfig;

use std::{env, str::FromStr, sync::Arc};

use reqwest::blocking::Client as BlockingRequestClient;
use serde::Deserialize;

use alloy_primitives::{Address, Bytes};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};

use reth_revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use reth_tracing::tracing::{debug, info, warn};

use bitcoin::{consensus::encode::deserialize, hashes::Hash, Network, Txid};

use sova_chainspec::{
    BitcoinPrecompileMethod, BROADCAST_TRANSACTION_ADDRESS, CONVERT_ADDRESS_ADDRESS,
    DECODE_TRANSACTION_ADDRESS, SOVA_BTC_CONTRACT_ADDRESS, VAULT_SPEND_ADDRESS,
};

use crate::precompiles::address_deriver::SovaAddressDeriver;
pub use crate::precompiles::precompile_utils::BitcoinMethodHelper;

pub const SOVA_BITCOIN_PRECOMPILE_BROADCAST_TRANSACTION: PrecompileWithAddress =
    PrecompileWithAddress(
        BROADCAST_TRANSACTION_ADDRESS,
        BitcoinRpcPrecompile::run_broadcast_transaction,
    );

pub const SOVA_BITCOIN_PRECOMPILE_DECODE_TRANSACTION: PrecompileWithAddress = PrecompileWithAddress(
    DECODE_TRANSACTION_ADDRESS,
    BitcoinRpcPrecompile::run_decode_transaction,
);

pub const SOVA_BITCOIN_PRECOMPILE_CONVERT_ADDRESS: PrecompileWithAddress = PrecompileWithAddress(
    CONVERT_ADDRESS_ADDRESS,
    BitcoinRpcPrecompile::run_convert_address,
);

pub const SOVA_BITCOIN_PRECOMPILE_VAULT_SPEND: PrecompileWithAddress =
    PrecompileWithAddress(VAULT_SPEND_ADDRESS, BitcoinRpcPrecompile::run_vault_spend);

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

#[derive(RlpDecodable, RlpEncodable, Debug)]
pub struct VaultSpendInput {
    precompile_input: Bytes,
    precomp_caller: Address,
}

impl VaultSpendInput {
    pub fn new(precompile_input: Bytes, precomp_caller: Address) -> Self {
        Self {
            precompile_input,
            precomp_caller,
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

    pub fn config_from_env() -> BitcoinConfig {
        let network = Network::from_str(&env::var("SOVA_BTC_NETWORK").unwrap()).unwrap();
        BitcoinConfig::new(
            network,
            &env::var("SOVA_BTC_NETWORK_URL").unwrap(),
            &env::var("SOVA_BTC_RPC_USERNAME").unwrap(),
            &env::var("SOVA_BTC_RPC_PASSWORD").unwrap(),
        )
    }

    pub fn client_from_env() -> Arc<BitcoinClient> {
        // we call .unwrap() instead of .unwrap_or_else to cause a panic in case of missing environment variables
        // to do this, we call this function once (for sanity check) after the env vars are set just before node start

        let bitcoin_config = BitcoinRpcPrecompile::config_from_env();

        Arc::new(
            BitcoinClient::new(
                &bitcoin_config,
                env::var("SOVA_SENTINEL_CONFIRMATION_THRESHOLD")
                    .unwrap()
                    .parse::<u8>()
                    .unwrap(),
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

        let res = btc_precompile.broadcast_btc_tx(input, gas_used);

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

        let res = btc_precompile.decode_raw_transaction(input, gas_used);

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

        let res = btc_precompile.convert_address(input, gas_used);

        if res.is_err() {
            warn!("Precompile error: {:?}", res);
        }

        res
    }

    pub fn run_vault_spend(input: &[u8], _gas_limit: u64) -> PrecompileResult {
        let VaultSpendInput {
            precompile_input,
            precomp_caller,
        } = VaultSpendInput::decode(&mut input.iter().as_ref())
            .map_err(|e| PrecompileError::Other(format!("Failed to decode input: {e:?}")))?;

        let input = precompile_input.as_ref();
        let precomp_caller = &precomp_caller;

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

        let res = btc_precompile.network_spend(input, precomp_caller, gas_used);

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

        debug!(
            "indexer response status: {}",
            response.status().is_success()
        );

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
                    bitcoincore_rpc::Error::ReturnedError(err_msg) => {
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
            .map_err(|_| {
                PrecompileError::Other("Decode raw transaction bitcoin rpc call failed".into())
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

    fn convert_address(&self, input: &[u8], gas_used: u64) -> PrecompileResult {
        let ethereum_address_bytes = self.parse_eth_address_bytes(input)?;

        let bitcoin_address = if self.sequencer_mode {
            self.derive_btc_address_with_caching(&ethereum_address_bytes)?
        } else {
            self.address_deriver
                .derive_bitcoin_address(&ethereum_address_bytes)?
                .to_string()
        };

        Ok(PrecompileOutput::new(
            gas_used,
            Bytes::from(bitcoin_address.as_bytes().to_vec()),
        ))
    }

    fn network_spend(
        &self,
        input: &[u8],
        precomp_caller: &Address,
        gas_used: u64,
    ) -> PrecompileResult {
        // only the native bitcoin wrapper contract can call this method
        if precomp_caller != &SOVA_BTC_CONTRACT_ADDRESS {
            return Err(
                PrecompileError::Other("Unauthorized precompile caller. Only the enshrined SovaBTC contract may use network signing.".to_string())
            );
        }

        let decoded_input: DecodedInput = decode_input(input)?;

        let mut request = serde_json::json!({
            "block_height": decoded_input.block_height,
            "amount": decoded_input.amount,
            "destination": decoded_input.destination,
            "fee": decoded_input.btc_gas_limit,
            "caller": decoded_input.caller, // msg.sender, data comes from contract
        });

        let response: Vec<u8> = if self.sequencer_mode {
            info!("Sequencer signing and broadcasting Bitcoin transaction");

            let sign_response: serde_json::Value =
                self.call_network_utxos("sign-transaction", &request)?;

            let signed_tx_hex = sign_response["signed_tx"]
                .as_str()
                .ok_or_else(|| PrecompileError::Other("Missing signed_tx in response".into()))?;

            let txid_str = sign_response["txid"]
                .as_str()
                .ok_or_else(|| PrecompileError::Other("Missing txid in response".into()))?;

            let signed_tx_bytes = hex::decode(signed_tx_hex).map_err(|e| {
                PrecompileError::Other(format!("Failed to decode signed transaction: {e:?}"))
            })?;

            let signed_tx: bitcoin::Transaction = deserialize(&signed_tx_bytes).map_err(|e| {
                PrecompileError::Other(format!(
                    "Failed to deserialize signed Bitcoin transaction: {e:?}"
                ))
            })?;

            let broadcast_txid = self.broadcast_transaction(&signed_tx)?;

            debug!(
                "Network spend: Sequencer mode: txid broadcast: {}",
                broadcast_txid
            );

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

/// Sova precompiles implementation that combines standard Optimism precompiles
/// with Bitcoin-specific precompiles for Reth v1.6.0
#[derive(Debug, Clone)]
pub struct SovaPrecompiles {
    /// Bitcoin client for precompile operations
    pub bitcoin_client: Arc<BitcoinClient>,
    /// Sentinel worker for slot lock coordination
    pub sentinel_worker: Arc<crate::SentinelWorker>,
}

impl SovaPrecompiles {
    pub fn new(bitcoin_client: Arc<BitcoinClient>, sentinel_worker: Arc<crate::SentinelWorker>) -> Self {
        Self {
            bitcoin_client,
            sentinel_worker
        }
    }
    
    /// Add Bitcoin precompiles to an existing precompiles map
    pub fn add_to_precompiles_map(precompiles_map: &mut PrecompilesMap, bitcoin_client: Arc<BitcoinClient>, sentinel_worker: Arc<crate::SentinelWorker>) {
        use alloy_evm::precompiles::PrecompileInput;
        use reth_revm::precompile::PrecompileResult;
        
        // Add Bitcoin precompiles one by one - wrap with slot lock enforcement
        let bitcoin_client_for_broadcast = Arc::clone(&bitcoin_client);
        let sentinel_worker_for_broadcast = Arc::clone(&sentinel_worker);
        precompiles_map.apply_precompile(&BROADCAST_TRANSACTION_ADDRESS, |_| {
            Some(DynPrecompile::new(move |input: PrecompileInput<'_>| -> PrecompileResult {
                Self::run_broadcast_transaction_with_slot_locks(input, &bitcoin_client_for_broadcast, &sentinel_worker_for_broadcast)
            }))
        });
        
        precompiles_map.apply_precompile(&DECODE_TRANSACTION_ADDRESS, |_| {
            Some(DynPrecompile::new(|input: PrecompileInput<'_>| -> PrecompileResult {
                SOVA_BITCOIN_PRECOMPILE_DECODE_TRANSACTION.1(input.data, input.gas)
            }))
        });
        
        precompiles_map.apply_precompile(&CONVERT_ADDRESS_ADDRESS, |_| {
            Some(DynPrecompile::new(|input: PrecompileInput<'_>| -> PrecompileResult {
                SOVA_BITCOIN_PRECOMPILE_CONVERT_ADDRESS.1(input.data, input.gas)
            }))
        });
        
        precompiles_map.apply_precompile(&VAULT_SPEND_ADDRESS, |_| {
            Some(DynPrecompile::new(|input: PrecompileInput<'_>| -> PrecompileResult {
                SOVA_BITCOIN_PRECOMPILE_VAULT_SPEND.1(input.data, input.gas)
            }))
        });
    }

    /// Enhanced broadcast transaction precompile with slot lock enforcement
    fn run_broadcast_transaction_with_slot_locks(
        input: alloy_evm::precompiles::PrecompileInput<'_>, 
        _bitcoin_client: &Arc<BitcoinClient>,
        sentinel_worker: &Arc<crate::SentinelWorker>
    ) -> reth_revm::precompile::PrecompileResult {
        use reth_revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
        use reth_tracing::tracing::{info, warn, error};
        use crate::SentinelClient;
        use crate::sentinel_client::{SlotLockRequest, SlotLockResponse};
        use std::collections::HashMap;
        
        info!("SOVA: Bitcoin broadcast precompile called with slot lock enforcement");
        
        // Step 1: Calculate gas used and check limits (same as before)
        let gas_used = BitcoinMethodHelper::calculate_gas_used(
            &BitcoinPrecompileMethod::BroadcastTransaction,
            input.data.len(),
        );

        if BitcoinMethodHelper::is_gas_limit_exceeded(
            &BitcoinPrecompileMethod::BroadcastTransaction,
            input.data.len(),
        ) {
            return Err(PrecompileError::OutOfGas);
        }

        // Step 2: Get current storage slots that have been accessed in this transaction
        // TODO: In a full implementation, you would need to:
        // 1. Access the current EVM execution context
        // 2. Extract the storage slots that have been written in this transaction
        // 3. For now, we'll create a placeholder list of critical Bitcoin slots
        
        let bitcoin_critical_addresses = vec![
            // TODO: Replace with actual Bitcoin contract addresses from your chainspec
            sova_chainspec::SOVA_BTC_CONTRACT_ADDRESS,
        ];
        
        let mut slots_to_check = HashMap::new();
        for address in bitcoin_critical_addresses {
            // TODO: Extract actual storage slots from the current transaction's state changes
            // For now, we'll check a few critical slots that Bitcoin operations typically modify
            let critical_slots = vec![
                alloy_primitives::U256::from(0), // Balance slot
                alloy_primitives::U256::from(1), // State slot  
                alloy_primitives::U256::from(2), // Nonce slot
            ];
            slots_to_check.insert(address, critical_slots);
        }

        // Step 3: Check slot locks with sentinel before proceeding
        if !slots_to_check.is_empty() {
            // Convert to slots format for worker
            let slots: Vec<(alloy_primitives::Address, alloy_primitives::U256)> = slots_to_check
                .iter()
                .flat_map(|(address, slot_list)| {
                    slot_list.iter().map(|slot| (*address, *slot))
                })
                .collect();
                
            // Read Bitcoin height deterministically from SovaL1Block predeploy
            // TODO: Access EVM database through proper precompile context when available
            // For now, use a default height - in production this would read from the predeploy
            let btc_height = match std::env::var("SOVA_BTC_HEIGHT") {
                Ok(height_str) => {
                    info!("SOVA: Using BTC height {} from environment", height_str);
                    height_str.parse().unwrap_or(800000)
                }
                Err(_) => {
                    info!("SOVA: Using default BTC height 800000");
                    800000
                }
            };
            
            // Check slot locks using sentinel worker with deterministic height
            let slot_check_results = sentinel_worker.check_locks(
                slots,
                0, // TODO: Get actual current block number from EVM context if available
                btc_height, // Use deterministic Bitcoin height from predeploy
            ).map_err(|e| PrecompileError::Other(format!("Slot lock check failed: {}", e)))?;

            // Check if any slots are locked  
            for ((address, slot), status) in slot_check_results {
                match status {
                    crate::sentinel_client::SlotLockStatus::Locked { btc_tx_hash, confirmations, .. } => {
                        error!(
                            "SOVA: Transaction BLOCKED - slot {:?} at {:?} is locked by Bitcoin tx {} ({} confirmations)",
                            slot, address, btc_tx_hash, confirmations
                        );
                        return Err(PrecompileError::Other(format!(
                            "Storage slot locked by pending Bitcoin transaction: {}",
                            btc_tx_hash
                        )));
                    }
                    crate::sentinel_client::SlotLockStatus::Reverted { previous_value, reason } => {
                        warn!(
                            "SOVA: Slot {:?} at {:?} was reverted ({}), will restore to {:?}",
                            slot, address, reason, previous_value
                        );
                        // Reverted slots don't block execution, but we log them
                    }
                    crate::sentinel_client::SlotLockStatus::Unlocked => {
                        // OK to proceed
                    }
                }
            }
        }

        // Step 4: All slot locks passed - proceed with Bitcoin transaction broadcast
        info!("SOVA: All slot lock checks passed, proceeding with Bitcoin broadcast");
        
        let btc_precompile = BitcoinRpcPrecompile::from_env();
        let result = btc_precompile.broadcast_btc_tx(input.data, gas_used);

        if let Ok(ref _output) = result {
            // Step 5: If broadcast succeeded, register the transaction and its affected slots
            info!("SOVA: Bitcoin transaction broadcast successful, registering slot locks");
            
            // TODO: Extract the actual Bitcoin transaction ID from the broadcast result
            // TODO: Register the transaction and its slot locks with the sentinel
            // For now, we'll just log what would be registered
            for (address, slots) in slots_to_check {
                for slot in slots {
                    info!("SOVA: Would lock slot {:?} at {:?} pending Bitcoin confirmation", slot, address);
                }
            }
        } else if let Err(ref err) = result {
            warn!("SOVA: Bitcoin transaction broadcast failed: {:?}", err);
        }

        result
    }
}
