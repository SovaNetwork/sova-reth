use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::B256;
use bitcoin::{BlockHash, Network, Transaction};
use bitcoincore_rpc::{bitcoin::Txid, json::DecodeRawTransactionResult, Auth, Client, RpcApi};
use reqwest::blocking::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct BitcoinConfig {
    pub network: Network,
    pub network_url: String,
    pub rpc_username: String,
    pub rpc_password: String,
    pub rpc_connection_type: String,
}

#[derive(Clone, Default)]
pub struct SovaL1BlockInfo {
    pub current_block_height: u64,
    pub block_hash_six_blocks_back: B256,
}

#[derive(Debug)]
pub enum BitcoinClientError {
    BitcoinCoreRpc(bitcoincore_rpc::Error),
    Reqwest(reqwest::Error),
    JsonParse(serde_json::Error),
    RpcError(String),
}

impl fmt::Display for BitcoinClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitcoinClientError::BitcoinCoreRpc(e) => write!(f, "Bitcoin Core RPC error: {e}"),
            BitcoinClientError::Reqwest(e) => write!(f, "HTTP request error: {e}"),
            BitcoinClientError::JsonParse(e) => write!(f, "JSON parsing error: {e}"),
            BitcoinClientError::RpcError(e) => write!(f, "RPC error: {e}"),
        }
    }
}

impl Error for BitcoinClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            BitcoinClientError::BitcoinCoreRpc(e) => Some(e),
            BitcoinClientError::Reqwest(e) => Some(e),
            BitcoinClientError::JsonParse(e) => Some(e),
            BitcoinClientError::RpcError(_) => None,
        }
    }
}

impl From<bitcoincore_rpc::Error> for BitcoinClientError {
    fn from(error: bitcoincore_rpc::Error) -> Self {
        BitcoinClientError::BitcoinCoreRpc(error)
    }
}

impl From<reqwest::Error> for BitcoinClientError {
    fn from(error: reqwest::Error) -> Self {
        BitcoinClientError::Reqwest(error)
    }
}

impl From<serde_json::Error> for BitcoinClientError {
    fn from(error: serde_json::Error) -> Self {
        BitcoinClientError::JsonParse(error)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    jsonrpc: Option<String>,
    id: Value,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

pub trait BitcoinRpcClient: Send + Sync {
    fn get_block_count(&self) -> Result<u64, BitcoinClientError>;
    fn get_block_hash(&self, height: u64) -> Result<String, BitcoinClientError>;
    fn send_raw_transaction(&self, tx_hex: String) -> Result<String, BitcoinClientError>;
    fn decode_raw_transaction(
        &self,
        tx_hex: String,
    ) -> Result<DecodeRawTransactionResult, BitcoinClientError>;
}

pub struct BitcoinCoreRpcClient {
    client: Client,
}

impl BitcoinCoreRpcClient {
    pub fn new(config: &BitcoinConfig) -> Result<Self, BitcoinClientError> {
        let auth = Auth::UserPass(config.rpc_username.clone(), config.rpc_password.clone());
        let url = config.network_url.to_string();
        let client = Client::new(&url, auth)?;
        Ok(Self { client })
    }
}

impl BitcoinRpcClient for BitcoinCoreRpcClient {
    fn get_block_count(&self) -> Result<u64, BitcoinClientError> {
        self.client
            .get_block_count()
            .map_err(BitcoinClientError::from)
    }

    fn get_block_hash(&self, height: u64) -> Result<String, BitcoinClientError> {
        let hash = self.client.get_block_hash(height)?;
        Ok(hash.to_string())
    }

    fn send_raw_transaction(&self, tx_hex: String) -> Result<String, BitcoinClientError> {
        let tx: Transaction = bitcoin::consensus::encode::deserialize(
            &hex::decode(&tx_hex)
                .map_err(|e| BitcoinClientError::RpcError(format!("Invalid hex: {e}")))?,
        )
        .map_err(|e| BitcoinClientError::RpcError(format!("Invalid transaction: {e}")))?;
        let txid = self.client.send_raw_transaction(&tx)?;
        Ok(txid.to_string())
    }

    fn decode_raw_transaction(
        &self,
        tx_hex: String,
    ) -> Result<DecodeRawTransactionResult, BitcoinClientError> {
        let tx: Transaction = bitcoin::consensus::encode::deserialize(
            &hex::decode(&tx_hex)
                .map_err(|e| BitcoinClientError::RpcError(format!("Invalid hex: {e}")))?,
        )
        .map_err(|e| BitcoinClientError::RpcError(format!("Invalid transaction: {e}")))?;
        self.client
            .decode_raw_transaction(&tx, None)
            .map_err(BitcoinClientError::from)
    }
}

pub struct ExternalRpcClient {
    client: ReqwestClient,
    url: String,
    user: Option<String>,
    password: Option<String>,
    id_counter: std::sync::atomic::AtomicU64,
}

impl ExternalRpcClient {
    pub fn new(config: &BitcoinConfig) -> Result<Self, BitcoinClientError> {
        let client = ReqwestClient::new();

        // Handle optional authentication
        let (user, password) = if config.rpc_username.is_empty() {
            (None, None)
        } else {
            (
                Some(config.rpc_username.clone()),
                if config.rpc_password.is_empty() {
                    None
                } else {
                    Some(config.rpc_password.clone())
                },
            )
        };

        Ok(Self {
            client,
            url: config.network_url.clone(),
            user,
            password,
            id_counter: std::sync::atomic::AtomicU64::new(1),
        })
    }

    fn call_rpc(&self, method: &str, params: Vec<Value>) -> Result<Value, BitcoinClientError> {
        let id = self
            .id_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let mut req = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "1.0",
                "id": id.to_string(),
                "method": method,
                "params": params
            }))
            .timeout(Duration::from_secs(60));

        if let Some(ref user) = self.user {
            req = req.basic_auth(user, self.password.as_deref());
        }

        let response = req.send()?;
        let rpc_response: JsonRpcResponse = response.json()?;

        if let Some(error) = rpc_response.error {
            return Err(BitcoinClientError::RpcError(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        rpc_response
            .result
            .ok_or_else(|| BitcoinClientError::RpcError("No result in response".to_string()))
    }
}

impl BitcoinRpcClient for ExternalRpcClient {
    fn get_block_count(&self) -> Result<u64, BitcoinClientError> {
        let result = self.call_rpc("getblockcount", vec![])?;
        result
            .as_u64()
            .ok_or_else(|| BitcoinClientError::RpcError("Invalid block count response".to_string()))
    }

    fn get_block_hash(&self, height: u64) -> Result<String, BitcoinClientError> {
        let result = self.call_rpc("getblockhash", vec![json!(height)])?;
        result
            .as_str()
            .ok_or_else(|| BitcoinClientError::RpcError("Invalid block hash response".to_string()))
            .map(|s| s.to_string())
    }

    fn send_raw_transaction(&self, tx_hex: String) -> Result<String, BitcoinClientError> {
        let result = self.call_rpc("sendrawtransaction", vec![json!(tx_hex)])?;
        result
            .as_str()
            .ok_or_else(|| {
                BitcoinClientError::RpcError("Invalid transaction ID response".to_string())
            })
            .map(|s| s.to_string())
    }

    fn decode_raw_transaction(
        &self,
        tx_hex: String,
    ) -> Result<DecodeRawTransactionResult, BitcoinClientError> {
        let result = self.call_rpc("decoderawtransaction", vec![json!(tx_hex)])?;
        serde_json::from_value(result).map_err(BitcoinClientError::from)
    }
}

pub struct BitcoinClient {
    rpc_client: Arc<dyn BitcoinRpcClient>,
    sentinel_confirmation_threshold: u8,
}

impl Default for BitcoinClient {
    /// Defaults to a Bitcoin confirmation threshold of 6
    fn default() -> Self {
        // Create default configuration for local regtest node
        let config = BitcoinConfig {
            network: Network::Regtest,
            network_url: "http://127.0.0.1:18443".to_string(),
            rpc_username: "user".to_string(),
            rpc_password: "password".to_string(),
            rpc_connection_type: "bitcoincore".to_string(),
        };

        Self::new(&config, 6, &config.rpc_connection_type)
            .expect("Failed to create default Bitcoin client")
    }
}

impl fmt::Debug for BitcoinClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinClient").finish()
    }
}

impl BitcoinClient {
    pub fn new(
        config: &BitcoinConfig,
        sentinel_confirmation_threshold: u8,
        connection_type: &str,
    ) -> Result<Self, BitcoinClientError> {
        let rpc_client: Arc<dyn BitcoinRpcClient> = match connection_type {
            "bitcoincore" => Arc::new(BitcoinCoreRpcClient::new(config)?),
            "external" => Arc::new(ExternalRpcClient::new(config)?),
            _ => {
                return Err(BitcoinClientError::RpcError(format!(
                "Unsupported connection type: {connection_type}. Use 'bitcoincore' or 'external'"
            )))
            }
        };

        Ok(Self {
            rpc_client,
            sentinel_confirmation_threshold,
        })
    }

    pub fn decode_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<DecodeRawTransactionResult, BitcoinClientError> {
        let tx_hex = hex::encode(bitcoin::consensus::encode::serialize(tx));
        self.rpc_client.decode_raw_transaction(tx_hex)
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinClientError> {
        let tx_hex = hex::encode(bitcoin::consensus::encode::serialize(tx));
        let txid_str = self.rpc_client.send_raw_transaction(tx_hex)?;
        txid_str
            .parse()
            .map_err(|e| BitcoinClientError::RpcError(format!("Invalid txid: {e}")))
    }

    /// Used by the PayloadBuilder flow to record the Bitcoin context
    /// at the time of block building. This function returns:
    /// - current BTC block height
    /// - The blockhash in the block that is considered "confirmed" by the sentinel.
    ///     - For example, if the confirmation threshold on the sentinel is 6,
    ///       the blockhash is queried from 6 blocks behind the current one.
    pub fn get_current_block_info(&self) -> Result<SovaL1BlockInfo, BitcoinClientError> {
        // Get the current block height
        let current_block_height = self.rpc_client.get_block_count()?;

        // Get the previous block hash based on the set confirmation threshold
        let height_six_blocks_back =
            current_block_height.saturating_sub(self.sentinel_confirmation_threshold.into());
        let block_hash_str = self.rpc_client.get_block_hash(height_six_blocks_back)?;

        // Parse the block hash string
        let block_hash: BlockHash = block_hash_str
            .parse()
            .map_err(|e| BitcoinClientError::RpcError(format!("Invalid block hash: {e}")))?;

        // Reverse the byte order (Bitcoin hashes are reversed compared to EVM)
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&block_hash[..]);
        block_hash_bytes.reverse();

        let block_hash_six_blocks_back = B256::new(block_hash_bytes);

        Ok(SovaL1BlockInfo {
            current_block_height,
            block_hash_six_blocks_back,
        })
    }

    /// Validates that the provided hash matches the actual hash of the Bitcoin block
    /// that is self.sentinel_confirmation_threshold blocks back from the given height.
    ///
    /// Returns Ok(true) if the hash matches, Ok(false) if it doesn't, or an Error
    /// if there was an issue fetching the block information.
    pub fn validate_block_hash(
        &self,
        block_height: u64,
        expected_hash: B256,
    ) -> Result<bool, BitcoinClientError> {
        // Get the previous block hash based on the set confirmation threshold
        let height_six_blocks_back =
            block_height.saturating_sub(self.sentinel_confirmation_threshold.into());
        let block_hash_str = self.rpc_client.get_block_hash(height_six_blocks_back)?;

        // Parse the block hash string
        let block_hash: BlockHash = block_hash_str
            .parse()
            .map_err(|e| BitcoinClientError::RpcError(format!("Invalid block hash: {e}")))?;

        // Reverse the byte order (Bitcoin hashes are reversed compared to EVM)
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&block_hash[..]);
        block_hash_bytes.reverse();

        let actual_hash = B256::new(block_hash_bytes);

        // Compare the actual hash with the expected hash
        Ok(actual_hash == expected_hash)
    }
}
