use std::fmt;

use alloy_primitives::B256;
use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::{bitcoin::Txid, json::DecodeRawTransactionResult, Auth, Client, RpcApi};

use sova_cli::BitcoinConfig;

#[derive(Clone)]
pub struct L1BlockInfo {
    pub current_block_height: u64,
    pub block_hash_six_blocks_back: B256,
}

pub struct BitcoinClient {
    client: Client,
}

impl Default for BitcoinClient {
    fn default() -> Self {
        // Create default configuration for local regtest node
        let config = BitcoinConfig {
            network: bitcoin::Network::Regtest,
            network_url: "http://127.0.0.1".to_string(),
            rpc_username: "user".to_string(),
            rpc_password: "password".to_string(),
        };

        Self::new(&config).expect("Failed to create default Bitcoin client")
    }
}

impl fmt::Debug for BitcoinClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitcoinClient").finish()
    }
}

impl BitcoinClient {
    pub fn new(config: &BitcoinConfig) -> Result<Self, bitcoincore_rpc::Error> {
        let port = match config.network {
            bitcoin::Network::Bitcoin => 8332,
            bitcoin::Network::Testnet => 18332,
            bitcoin::Network::Regtest => 18443,
            bitcoin::Network::Signet => 38332,
            _ => unreachable!("unsupported network id"),
        };

        let auth = Auth::UserPass(config.rpc_username.clone(), config.rpc_password.clone());

        let url = format!("{}:{}", config.network_url, port);
        let client = Client::new(&url, auth)?;
        Ok(Self { client })
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

    pub fn get_current_block_info(&self) -> Result<L1BlockInfo, bitcoincore_rpc::Error> {
        // Get the current block height
        let current_block_height = self.client.get_block_count()?;

        // Calculate the height 6 blocks back
        // TODO(powvt): make this deterministic based on the sentinel confirmation threshold
        let height_six_blocks_back = current_block_height.saturating_sub(6);

        // Get the block hash for the block 6 confirmations back
        let block_hash = self.client.get_block_hash(height_six_blocks_back)?;

        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&block_hash[..]);

        // Reverse the byte order (Bitcoin hashes are reversed compared to Ethereum)
        block_hash_bytes.reverse();
        // Convert from Bitcoin's BlockHash to Alloy's B256
        let block_hash_six_blocks_back = B256::new(block_hash_bytes);

        Ok(L1BlockInfo {
            current_block_height,
            block_hash_six_blocks_back,
        })
    }

    /// Validates that the provided hash matches the actual hash of the Bitcoin block
    /// that is 6 blocks back from the given height.
    ///
    /// Returns Ok(true) if the hash matches, Ok(false) if it doesn't, or an Error
    /// if there was an issue fetching the block information.
    pub fn validate_block_hash(
        &self,
        block_height: u64,
        expected_hash: B256,
    ) -> Result<bool, bitcoincore_rpc::Error> {
        // Calculate the height 6 blocks back
        let height_six_blocks_back = block_height.saturating_sub(6);

        // Get the block hash for the block 6 confirmations back
        let block_hash = self.client.get_block_hash(height_six_blocks_back)?;

        // Convert from Bitcoin's BlockHash to Alloy's B256
        let mut block_hash_bytes = [0u8; 32];
        block_hash_bytes.copy_from_slice(&block_hash[..]);

        // Reverse the byte order (Bitcoin hashes are reversed compared to Ethereum)
        block_hash_bytes.reverse();
        let actual_hash = B256::new(block_hash_bytes);

        // Compare the actual hash with the expected hash
        Ok(actual_hash == expected_hash)
    }
}
