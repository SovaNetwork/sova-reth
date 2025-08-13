use std::{fmt, future::Future, str::FromStr, sync::Arc, time::Duration};

use alloy_primitives::B256;
use bitcoin::{consensus::encode, Transaction};
use bitcoincore_rpc::{bitcoin::Txid, json::DecodeRawTransactionResult, Auth, Client, RpcApi};
use reqwest::blocking::Client as HttpClient;
use serde_json::json;
use thiserror::Error;

use sova_cli::BitcoinConfig;

/// Common error type for all Bitcoin RPC clients.
#[derive(Error, Debug)]
pub enum BitcoinRpcError {
    #[error("Bitcoin Core RPC error: {0}")]
    BitcoinCore(#[from] bitcoincore_rpc::Error),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Serde json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("{0}")]
    Other(String),
}

/// Trait abstracting over different Bitcoin RPC clients.
#[async_trait::async_trait]
pub trait BitcoinRpcClient: Send + Sync {
    async fn get_block_count(&self) -> Result<u64, BitcoinRpcError>;
    async fn get_block_hash(&self, height: u64) -> Result<String, BitcoinRpcError>;
    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, BitcoinRpcError>;
    async fn decode_raw_transaction(
        &self,
        tx_hex: String,
    ) -> Result<DecodeRawTransactionResult, BitcoinRpcError>;
}

/// Implementation using `bitcoincore_rpc` crate.
pub struct BitcoinCoreRpcClient {
    inner: Client,
}

impl BitcoinCoreRpcClient {
    pub fn new(config: &BitcoinConfig) -> Result<Self, bitcoincore_rpc::Error> {
        let auth = Auth::UserPass(config.rpc_username.clone(), config.rpc_password.clone());
        let client = Client::new(&config.network_url, auth)?;
        Ok(Self { inner: client })
    }
}

#[async_trait::async_trait]
impl BitcoinRpcClient for BitcoinCoreRpcClient {
    async fn get_block_count(&self) -> Result<u64, BitcoinRpcError> {
        let client = self.inner.clone();
        tokio::task::spawn_blocking(move || client.get_block_count())
            .await?
            .map_err(Into::into)
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, BitcoinRpcError> {
        let client = self.inner.clone();
        let hash = tokio::task::spawn_blocking(move || client.get_block_hash(height)).await??;
        Ok(hash.to_string())
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, BitcoinRpcError> {
        let client = self.inner.clone();
        let bytes = hex::decode(&tx_hex).map_err(|e| BitcoinRpcError::Other(e.to_string()))?;
        let tx: Transaction =
            encode::deserialize(&bytes).map_err(|e| BitcoinRpcError::Other(e.to_string()))?;
        let txid = tokio::task::spawn_blocking(move || client.send_raw_transaction(&tx)).await??;
        Ok(txid.to_string())
    }

    async fn decode_raw_transaction(
        &self,
        tx_hex: String,
    ) -> Result<DecodeRawTransactionResult, BitcoinRpcError> {
        let client = self.inner.clone();
        let bytes = hex::decode(&tx_hex).map_err(|e| BitcoinRpcError::Other(e.to_string()))?;
        let tx: Transaction =
            encode::deserialize(&bytes).map_err(|e| BitcoinRpcError::Other(e.to_string()))?;
        tokio::task::spawn_blocking(move || client.decode_raw_transaction(&tx, None))
            .await??
            .map_err(Into::into)
    }
}

/// External RPC client that performs raw JSON-RPC calls via HTTP.
#[derive(Clone)]
pub struct ExternalRpcClient {
    url: String,
    client: HttpClient,
    user: Option<String>,
    password: Option<String>,
}

impl ExternalRpcClient {
    pub fn new(config: &BitcoinConfig) -> Result<Self, reqwest::Error> {
        Ok(Self {
            url: config.network_url.clone(),
            client: HttpClient::new(),
            user: if config.rpc_username.is_empty() {
                None
            } else {
                Some(config.rpc_username.clone())
            },
            password: if config.rpc_password.is_empty() {
                None
            } else {
                Some(config.rpc_password.clone())
            },
        })
    }

    fn call_rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, BitcoinRpcError> {
        let mut req = self
            .client
            .post(&self.url)
            .json(&json!({
                "jsonrpc": "1.0",
                "id": "1",
                "method": method,
                "params": params
            }))
            .timeout(Duration::from_secs(60));

        if let Some(ref user) = self.user {
            req = req.basic_auth(user, self.password.as_deref());
        }

        let resp = req.send()?;

        let value: serde_json::Value = resp.json()?;
        if !value["error"].is_null() {
            return Err(BitcoinRpcError::Other(value["error"].to_string()));
        }

        Ok(value["result"].clone())
    }
}

#[async_trait::async_trait]
impl BitcoinRpcClient for ExternalRpcClient {
    async fn get_block_count(&self) -> Result<u64, BitcoinRpcError> {
        let this = self.clone();
        let res = tokio::task::spawn_blocking(move || this.call_rpc("getblockcount", json!([])))
            .await??;
        res.as_u64()
            .ok_or_else(|| BitcoinRpcError::Other("invalid result".to_string()))
    }

    async fn get_block_hash(&self, height: u64) -> Result<String, BitcoinRpcError> {
        let this = self.clone();
        let res =
            tokio::task::spawn_blocking(move || this.call_rpc("getblockhash", json!([height])))
                .await??;
        res.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| BitcoinRpcError::Other("invalid result".to_string()))
    }

    async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, BitcoinRpcError> {
        let this = self.clone();
        let res = tokio::task::spawn_blocking(move || {
            this.call_rpc("sendrawtransaction", json!([tx_hex]))
        })
        .await??;
        res.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| BitcoinRpcError::Other("invalid result".to_string()))
    }

    async fn decode_raw_transaction(
        &self,
        tx_hex: String,
    ) -> Result<DecodeRawTransactionResult, BitcoinRpcError> {
        let this = self.clone();
        let res = tokio::task::spawn_blocking(move || {
            this.call_rpc("decoderawtransaction", json!([tx_hex]))
        })
        .await??;
        serde_json::from_value(res).map_err(BitcoinRpcError::SerdeJson)
    }
}

#[derive(Clone, Default)]
pub struct SovaL1BlockInfo {
    pub current_block_height: u64,
    pub block_hash_six_blocks_back: B256,
}

pub struct BitcoinClient {
    client: Arc<dyn BitcoinRpcClient>,
    sentinel_confirmation_threshold: u8,
}

impl Default for BitcoinClient {
    /// Defaults to a Bitcoin confirmation threshold of 6
    fn default() -> Self {
        // Create default configuration for local regtest node
        let config = BitcoinConfig {
            network: bitcoin::Network::Regtest,
            network_url: "http://127.0.0.1:18443".to_string(),
            rpc_username: "user".to_string(),
            rpc_password: "password".to_string(),
        };

        Self::new(&config, 6, "bitcoincore").expect("Failed to create default Bitcoin client")
    }
}

impl fmt::Debug for BitcoinClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinClient").finish()
    }
}

impl BitcoinClient {
    /// Helper to run futures in both async and sync contexts.
    fn block_on<F: Future>(fut: F) -> F::Output {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.block_on(fut)
        } else {
            tokio::runtime::Runtime::new()
                .expect("runtime")
                .block_on(fut)
        }
    }

    pub fn new(
        config: &BitcoinConfig,
        sentinel_confirmation_threshold: u8,
        connection_type: &str,
    ) -> Result<Self, BitcoinRpcError> {
        let client: Arc<dyn BitcoinRpcClient> = match connection_type {
            "external" => Arc::new(ExternalRpcClient::new(config)?),
            "bitcoincore" | _ => Arc::new(BitcoinCoreRpcClient::new(config)?),
        };

        reth_tracing::tracing::info!("Using Bitcoin RPC connection type: {}", connection_type);

        Ok(Self {
            client,
            sentinel_confirmation_threshold,
        })
    }

    pub fn decode_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<DecodeRawTransactionResult, BitcoinRpcError> {
        let tx_hex = encode::serialize_hex(tx);
        Self::block_on(self.client.decode_raw_transaction(tx_hex))
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinRpcError> {
        let tx_hex = encode::serialize_hex(tx);
        let txid_hex = Self::block_on(self.client.send_raw_transaction(tx_hex))?;
        Txid::from_str(&txid_hex).map_err(|e| BitcoinRpcError::Other(e.to_string()))
    }

    /// Used by the PayloadBuilder flow to record the Bitcoin context
    /// at the time of block building. This function returns:
    /// - current BTC block height
    /// - The blockhash in the block that is considered "confirmed" by the sentinel.
    ///     - For example, if the confirmation threshold on the sentinel is 6,
    ///       the blockhash is queried from 6 blocks behind the current one.
    pub fn get_current_block_info(&self) -> Result<SovaL1BlockInfo, BitcoinRpcError> {
        // Get the current block height
        let current_block_height = Self::block_on(self.client.get_block_count())?;

        // Get the previous block hash based on the set confirmation threshold
        let height_six_blocks_back =
            current_block_height.saturating_sub(self.sentinel_confirmation_threshold.into());
        let block_hash_hex = Self::block_on(self.client.get_block_hash(height_six_blocks_back))?;
        let block_hash = bitcoin::BlockHash::from_str(&block_hash_hex)
            .map_err(|e| BitcoinRpcError::Other(e.to_string()))?;

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
    ) -> Result<bool, BitcoinRpcError> {
        // Get the previous block hash based on the set confirmation threshold
        let height_six_blocks_back =
            block_height.saturating_sub(self.sentinel_confirmation_threshold.into());
        let block_hash_hex = Self::block_on(self.client.get_block_hash(height_six_blocks_back))?;
        let block_hash = bitcoin::BlockHash::from_str(&block_hash_hex)
            .map_err(|e| BitcoinRpcError::Other(e.to_string()))?;

        // Reverse the byte order (Bitcoin hashes are reversed compared to EVM)
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&block_hash[..]);
        block_hash_bytes.reverse();

        let actual_hash = B256::new(block_hash_bytes);

        // Compare the actual hash with the expected hash
        Ok(actual_hash == expected_hash)
    }
}
