mod chainspec;

pub use chainspec::SovaChainSpecParser;

use std::sync::Arc;

use bitcoin::Network;

#[derive(Clone, Debug)]
pub struct BitcoinConfig {
    pub network: Network,
    pub network_url: String,
    pub rpc_username: String,
    pub rpc_password: String,
}

impl BitcoinConfig {
    pub fn new(
        network: Network,
        network_url: &str,
        rpc_username: &str,
        rpc_password: &str,
    ) -> Self {
        BitcoinConfig {
            network,
            network_url: network_url.to_owned(),
            rpc_username: rpc_username.to_owned(),
            rpc_password: rpc_password.to_owned(),
        }
    }
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        BitcoinConfig {
            network: Network::Regtest,
            network_url: String::new(),
            rpc_username: String::new(),
            rpc_password: String::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SovaConfig {
    pub bitcoin_config: Arc<BitcoinConfig>,
    pub network_signing_url: String,
    pub network_utxo_url: String,
    pub btc_tx_queue_url: String,
    pub sentinel_url: String,
}

impl SovaConfig {
    pub fn new(
        bitcoin_config: BitcoinConfig,
        network_signing_url: &str,
        network_utxo_url: &str,
        btc_tx_queue_url: &str,
        sentinel_url: &str,
    ) -> Self {
        SovaConfig {
            bitcoin_config: Arc::new(bitcoin_config),
            network_signing_url: network_signing_url.to_owned(),
            network_utxo_url: network_utxo_url.to_owned(),
            btc_tx_queue_url: btc_tx_queue_url.to_owned(),
            sentinel_url: sentinel_url.to_owned(),
        }
    }
}

impl Default for SovaConfig {
    fn default() -> Self {
        SovaConfig {
            bitcoin_config: Arc::new(BitcoinConfig::default()),
            network_signing_url: String::new(),
            network_utxo_url: String::new(),
            btc_tx_queue_url: String::new(),
            sentinel_url: String::new(),
        }
    }
}
