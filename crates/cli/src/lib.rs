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

#[derive(Clone, Debug)]
pub struct SovaConfig {
    pub bitcoin: Arc<BitcoinConfig>,
    pub network_signing_url: String,
    pub network_utxo_url: String,
    pub btc_tx_queue_url: String,
    pub storage_slot_provider_url: String,
}

impl SovaConfig {
    pub fn new(
        btc_network: &Network,
        network_url: &str,
        btc_rpc_username: &str,
        btc_rpc_password: &str,
        network_signing_url: &str,
        network_utxo_url: &str,
        btc_tx_queue_url: &str,
        storage_slot_provider_url: &str,
    ) -> Self {
        let bitcoin_config = BitcoinConfig {
            network: *btc_network,
            network_url: network_url.to_owned(),
            rpc_username: btc_rpc_username.to_owned(),
            rpc_password: btc_rpc_password.to_owned(),
        };

        SovaConfig {
            bitcoin: Arc::new(bitcoin_config),
            network_signing_url: network_signing_url.to_owned(),
            network_utxo_url: network_utxo_url.to_owned(),
            btc_tx_queue_url: btc_tx_queue_url.to_owned(),
            storage_slot_provider_url: storage_slot_provider_url.to_owned(),
        }
    }
}

impl Default for SovaConfig {
    fn default() -> Self {
        SovaConfig {
            bitcoin: Arc::new(BitcoinConfig {
                network: Network::Bitcoin,
                network_url: String::new(),
                rpc_username: String::new(),
                rpc_password: String::new(),
            }),
            network_signing_url: String::new(),
            network_utxo_url: String::new(),
            btc_tx_queue_url: String::new(),
            storage_slot_provider_url: String::new(),
        }
    }
}
