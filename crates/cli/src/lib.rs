use clap::Parser;

use bitcoin::Network;

/// corsa-reth CLI arguments
#[derive(Debug, Parser)]
pub struct Args {
    /// The bitcoin network that the rpc client will connect to
    #[arg(long, value_parser = parse_network, default_value = "regtest")]
    pub btc_network: Network,

    // The bitcoin rpc url
    #[arg(long, default_value = "http://127.0.0.1")]
    pub network_url: String,

    /// The bitcoin rpc username
    #[arg(long, default_value = "user")]
    pub btc_rpc_username: String,

    /// The bitcoin rpc password
    #[arg(long, default_value = "password")]
    pub btc_rpc_password: String,
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
