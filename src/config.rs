use bitcoin::Network;
use std::sync::Arc;

use crate::cli::CorsaRollupArgs;

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
}

impl CorsaConfig {
    pub fn new(args: &CorsaRollupArgs) -> Self {
        let btc_network = match args.bitcoin.network.as_str() {
            "regtest" => Ok(Network::Regtest),
            "testnet" => Ok(Network::Testnet),
            "signet" => Ok(Network::Signet),
            "mainnet" => Ok(Network::Bitcoin),
            _ => Err("Invalid network. Use 'regtest', 'testnet', 'signet' or 'mainnet'"),
        }
        .unwrap();

        let bitcoin_config = BitcoinConfig {
            network: btc_network,
            network_url: args.bitcoin.url.clone(),
            rpc_username: args.bitcoin.rpc_username.clone(),
            rpc_password: args.bitcoin.rpc_password.clone(),
        };

        CorsaConfig {
            bitcoin: Arc::new(bitcoin_config),
        }
    }
}
