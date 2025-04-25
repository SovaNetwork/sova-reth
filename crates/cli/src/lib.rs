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
    pub sentinel_url: String,
    pub sentinel_confirmation_threshold: u8,
}

impl SovaConfig {
    pub fn new(
        bitcoin_config: BitcoinConfig,
        network_signing_url: &str,
        network_utxo_url: &str,
        sentinel_url: &str,
        sentinel_confirmation_threshold: u8,
    ) -> Self {
        SovaConfig {
            bitcoin_config: Arc::new(bitcoin_config),
            network_signing_url: network_signing_url.to_owned(),
            network_utxo_url: network_utxo_url.to_owned(),
            sentinel_url: sentinel_url.to_owned(),
            sentinel_confirmation_threshold
        }
    }
}

impl Default for SovaConfig {
    fn default() -> Self {
        SovaConfig {
            bitcoin_config: Arc::new(BitcoinConfig::default()),
            network_signing_url: String::new(),
            network_utxo_url: String::new(),
            sentinel_url: String::new(),
            sentinel_confirmation_threshold: 6,
        }
    }
}
