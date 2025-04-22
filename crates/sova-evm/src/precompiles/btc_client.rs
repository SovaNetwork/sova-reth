use std::fmt;

use bitcoin::{BlockHash, Transaction};
use bitcoincore_rpc::{bitcoin::Txid, json::DecodeRawTransactionResult, Auth, Client, RpcApi};

use sova_cli::BitcoinConfig;

#[derive(Clone)]
pub struct L1BlockInfo {
    pub current_block_height: u64,
    pub block_hash_six_blocks_back: BlockHash,
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

    pub fn get_block_height(&self) -> Result<u64, bitcoincore_rpc::Error> {
        self.client.get_block_count()
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, bitcoincore_rpc::Error> {
        self.client.send_raw_transaction(tx)
    }

    pub fn get_current_block_info(&self) -> Result<L1BlockInfo, bitcoincore_rpc::Error> {
        // Get the current block height
        let current_block_height = self.get_block_height()?;
        
        // Calculate the height 6 blocks back
        // TODO(powvt): make this deterministic based on the sentinel confirmation threshold
        let height_six_blocks_back = current_block_height.saturating_sub(6);
        
        // Get the block hash for the block 6 confirmations back
        let block_hash_six_blocks_back = self.client.get_block_hash(height_six_blocks_back)?;
        
        Ok(L1BlockInfo {
            current_block_height,
            block_hash_six_blocks_back,
        })
    }
}
