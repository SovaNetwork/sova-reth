use clap::Parser;

use bitcoin::Network;

/// Our custom cli args extension that adds flags to configure the bitcoin rpc client
#[derive(Clone, Debug, Default, Parser)]
pub struct SovaArgs {
    /// CLI flag to indicate the bitcoin network the bitcoin rpc client will connect to
    #[arg(long, value_parser = parse_network_to_wrapper, default_value = "regtest")]
    pub btc_network: BitcoinNetwork,

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

fn parse_network_to_wrapper(s: &str) -> Result<BitcoinNetwork, &'static str> {
    parse_network(s).map(BitcoinNetwork::from)
}

fn parse_network(s: &str) -> Result<Network, &'static str> {
    match s.to_lowercase().as_str() {
        "regtest" => Ok(Network::Regtest),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "mainnet" => Ok(Network::Bitcoin),
        _ => Err("Invalid network. Use 'regtest', 'testnet', 'signet' or 'mainnet'"),
    }
}

/// Wrapper Bitcoin Network enum to allow for default derivation
#[derive(Clone, Debug)]
pub struct BitcoinNetwork {
    network: Network,
}

impl Default for BitcoinNetwork {
    fn default() -> Self {
        BitcoinNetwork {
            network: Network::Regtest,
        }
    }
}

impl From<Network> for BitcoinNetwork {
    fn from(network: Network) -> Self {
        BitcoinNetwork { network }
    }
}

impl From<BitcoinNetwork> for Network {
    fn from(network: BitcoinNetwork) -> Self {
        network.network
    }
}
