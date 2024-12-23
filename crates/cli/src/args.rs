use bitcoin::Network;

/// Our custom cli args extension that adds flags to configure the bitcoin rpc client
#[derive(Debug, Clone, PartialEq, Eq, clap::Args)]
pub struct CorsaArgs {
    /// CLI flag to indicate the bitcoin network the bitcoin rpc client will connect to
    #[arg(long, value_parser = parse_network, default_value = "regtest")]
    pub btc_network: Network,

    // CLI flag to indicate the bitcoin rpc url
    #[arg(long, default_value = "http://127.0.0.1")]
    pub network_url: String,

    /// CLI flag to indicate the bitcoin rpc username
    #[arg(long, default_value = "user")]
    pub btc_rpc_username: String,

    /// CLI flag to indicate the bitcoin rpc password
    #[arg(long, default_value = "password")]
    pub btc_rpc_password: String,

    /// CLI flag to indicate the network signing service url
    #[arg(long, default_value = "http://127.0.0.1:5555")]
    pub network_signing_url: String,

    /// CLI flag to indicate the network UTXO database url
    #[arg(long, default_value = "http://127.0.0.1:5557")]
    pub network_utxo_url: String,

    /// CLI flag to indicate the bitcoin transaction queue url
    #[arg(long, default_value = "http://127.0.0.1:5558")]
    pub btc_tx_queue_url: String,
}

impl Default for CorsaArgs {
    fn default() -> Self {
        Self {
            btc_network: Network::Regtest,
            network_url: "http://127.0.0.1".to_string(),
            btc_rpc_username: "user".to_string(),
            btc_rpc_password: "password".to_string(),
            network_signing_url: "http://127.0.0.1:5555".to_string(),
            network_utxo_url: "http://127.0.0.1:5557".to_string(),
            btc_tx_queue_url: "http://127.0.0.1:5558".to_string(),
        }
    }
}

fn parse_network(s: &str) -> Result<Network, &'static str> {
    match s {
        "regtest" => Ok(Network::Regtest),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "mainnet" => Ok(Network::Bitcoin),
        _ => Err("Invalid network. Use 'regtest', 'testnet', 'signet' or 'mainnet'"),
    }
}
