use std::fmt;

use alloy_primitives::B256;
use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::{bitcoin::Txid, json::DecodeRawTransactionResult, Auth, Client, RpcApi};

use crate::precompiles::SovaBitcoinConfig;

#[derive(Clone, Default)]
pub struct SovaL1BlockInfo {
    pub current_block_height: u64,
    pub block_hash_six_blocks_back: B256,
}

pub struct BitcoinClient {
    client: Client,
    sentinel_confirmation_threshold: u8,
}

impl Default for BitcoinClient {
    /// Defaults to a Bitcoin confirmation threshold of 6
    fn default() -> Self {
        // Create default configuration for local regtest node
        let config = SovaBitcoinConfig {
            network: bitcoin::Network::Regtest,
            network_url: "http://127.0.0.1:18443".to_string(),
            rpc_username: "user".to_string(),
            rpc_password: "password".to_string(),
        };

        Self::new(&config, 6).expect("Failed to create default Bitcoin client")
    }
}

impl fmt::Debug for BitcoinClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinClient").finish()
    }
}

impl BitcoinClient {
    pub fn new(
        config: &SovaBitcoinConfig,
        sentinel_confirmation_threshold: u8,
    ) -> Result<Self, bitcoincore_rpc::Error> {
        let auth = Auth::UserPass(config.rpc_username.clone(), config.rpc_password.clone());
        let url = config.network_url.to_string();

        let client = Client::new(&url, auth)?;
        Ok(Self {
            client,
            sentinel_confirmation_threshold,
        })
    }

    pub fn decode_raw_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<DecodeRawTransactionResult, bitcoincore_rpc::Error> {
        self.client.decode_raw_transaction(tx, None)
    }

    pub fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<Transaction, bitcoincore_rpc::Error> {
        self.client.get_raw_transaction(txid, block_hash)
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, bitcoincore_rpc::Error> {
        self.client.send_raw_transaction(tx)
    }

    /// Used by the PayloadBuilder flow to record the Bitcoin context
    /// at the time of block building. This function returns:
    /// - current BTC block height
    /// - The blockhash in the block that is considered "confirmed" by the sentinel.
    ///     - For example, if the confirmation threshold on the sentinel is 6,
    ///       the blockhash is queried from 6 blocks behind the current one.
    pub fn get_current_block_info(&self) -> Result<SovaL1BlockInfo, bitcoincore_rpc::Error> {
        // Get the current block height
        let current_block_height = self.client.get_block_count()?;

        // Get the previous block hash based on the set confirmation threshold
        let height_six_blocks_back =
            current_block_height.saturating_sub(self.sentinel_confirmation_threshold.into());
        let block_hash = self.client.get_block_hash(height_six_blocks_back)?;

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
    ) -> Result<bool, bitcoincore_rpc::Error> {
        // Get the previous block hash based on the set confirmation threshold
        let height_six_blocks_back =
            block_height.saturating_sub(self.sentinel_confirmation_threshold.into());
        let block_hash = self.client.get_block_hash(height_six_blocks_back)?;

        // Reverse the byte order (Bitcoin hashes are reversed compared to EVM)
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&block_hash[..]);
        block_hash_bytes.reverse();

        let actual_hash = B256::new(block_hash_bytes);

        // Compare the actual hash with the expected hash
        Ok(actual_hash == expected_hash)
    }
}
