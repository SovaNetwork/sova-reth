use std::fmt;

use bitcoin::{BlockHash, Transaction, Txid};
use bitcoincore_rpc::{json::DecodeRawTransactionResult, Auth, Client, RpcApi};

use sova_cli::BitcoinConfig;

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
}
