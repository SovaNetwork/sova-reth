use bitcoin::{Transaction, Txid};
use bitcoincore_rpc::{json::DecodeRawTransactionResult, Auth, Client, RpcApi};

use crate::config::BitcoinConfig;

pub struct BitcoinClientWrapper {
    client: Client,
}

impl BitcoinClientWrapper {
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

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, bitcoincore_rpc::Error> {
        self.client.send_raw_transaction(tx)
    }

    pub fn get_block_count(&self) -> Result<u64, bitcoincore_rpc::Error> {
        self.client.get_block_count()
    }

    pub fn decode_raw_transaction(&self, tx: &Transaction) -> Result<DecodeRawTransactionResult, bitcoincore_rpc::Error> {
        self.client.decode_raw_transaction(tx, None)
    }

    // Add more methods as needed...
}
