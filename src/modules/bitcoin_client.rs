use bitcoincore_rpc::{Auth, Client, RpcApi};
use bitcoin::{Transaction, Txid};

use crate::settings::Settings;

pub struct BitcoinClientWrapper {
    client: Client,
}

impl BitcoinClientWrapper {
    pub fn new(settings: &Settings) -> Result<Self, bitcoincore_rpc::Error> {
        let port = match settings.network {
            bitcoin::Network::Bitcoin => 8332,
            bitcoin::Network::Testnet => 18332,
            bitcoin::Network::Regtest => 18443,
            bitcoin::Network::Signet => 38332,
            _ => unreachable!("unsupported network id"),
        };

        let auth = Auth::UserPass(
            settings.bitcoin_rpc_username.clone(),
            settings.bitcoin_rpc_password.clone(),
        );

        let url = format!("{}:{}", settings.network_url, port);
        let client = Client::new(&url, auth)?;
        Ok(Self { client })
    }

    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, bitcoincore_rpc::Error> {
        self.client.send_raw_transaction(tx)
    }

    pub fn get_block_count(&self) -> Result<u64, bitcoincore_rpc::Error> {
        self.client.get_block_count()
    }

    // Add more methods as needed...
}