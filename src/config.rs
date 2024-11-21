use std::sync::Arc;

use bitcoin::Network;

#[derive(Clone)]
pub struct BitcoinConfig {
    pub network: Network,
    pub network_url: String,
    pub rpc_username: String,
    pub rpc_password: String,
}

#[derive(Clone)]
pub struct CorsaConfig {
    pub bitcoin: Arc<BitcoinConfig>,
    pub network_signing_url: String,
    pub network_utxo_url: String,
    pub btc_tx_queue_url: String,
}

impl CorsaConfig {
    pub fn new(args: &crate::cli::Args) -> Self {
        let bitcoin_config = BitcoinConfig {
            network: args.btc_network,
            network_url: args.network_url.clone(),
            rpc_username: args.btc_rpc_username.clone(),
            rpc_password: args.btc_rpc_password.clone(),
        };

        CorsaConfig {
            bitcoin: Arc::new(bitcoin_config),
            network_signing_url: args.network_signing_url.clone(),
            network_utxo_url: args.network_utxo_url.clone(),
            btc_tx_queue_url: args.btc_tx_queue_url.clone(),
        }
    }
}
