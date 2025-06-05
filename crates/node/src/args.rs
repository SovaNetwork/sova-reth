use clap::Parser;

use bitcoin::Network;

use op_alloy_consensus::interop::SafetyLevel;

use reth_optimism_txpool::supervisor::DEFAULT_SUPERVISOR_URL;

/// Custom cli args extension that adds flags to configure Bitcoin functionality
#[derive(Clone, Debug, Parser)]
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

    /// CLI flag to indicate the network signing url
    #[arg(long, default_value = "http://127.0.0.1:3031")]
    pub network_utxos_url: String,

    /// CLI flag to indicate the storage slot provider url
    #[arg(long, default_value = "http://[::1]:50051")]
    pub sentinel_url: String,

    /// CLI flag to set the confirmation threshold being
    /// used by the accompanying sentinel service.
    ///
    /// NOTE: It is crucial this is the same value used in
    ///       the sentinel and should be a global variable
    ///       in the orchestration of running a validator.
    #[arg(long, default_value = "6")]
    pub sentinel_confirmation_threshold: u8,

    /// enable sequencer mode, this is for validators who are able to process network signed transactions
    #[arg(long, default_value = "false")]
    pub sequencer_mode: bool,

    /// Endpoint for the sequencer mempool (can be both HTTP and WS)
    #[arg(long = "rollup.sequencer", visible_aliases = ["rollup.sequencer-http", "rollup.sequencer-ws"])]
    pub sequencer: Option<String>,

    /// Disable transaction pool gossip
    #[arg(long = "rollup.disable-tx-pool-gossip")]
    pub disable_txpool_gossip: bool,

    /// Enable walkback to genesis on startup. This is useful for re-validating the existing DB
    /// prior to beginning normal syncing.
    #[arg(long = "rollup.enable-genesis-walkback")]
    pub enable_genesis_walkback: bool,

    /// By default the pending block equals the latest block
    /// to save resources and not leak txs from the tx-pool,
    /// this flag enables computing of the pending block
    /// from the tx-pool instead.
    ///
    /// If `compute_pending_block` is not enabled, the payload builder
    /// will use the payload attributes from the latest block. Note
    /// that this flag is not yet functional.
    #[arg(long = "rollup.compute-pending-block")]
    pub compute_pending_block: bool,

    /// enables discovery v4 if provided
    #[arg(long = "rollup.discovery.v4", default_value = "false")]
    pub discovery_v4: bool,

    /// Enable transaction conditional support on sequencer
    #[arg(long = "rollup.enable-tx-conditional", default_value = "false")]
    pub enable_tx_conditional: bool,

    /// HTTP endpoint for the supervisor
    #[arg(
        long = "rollup.supervisor-http",
        value_name = "SUPERVISOR_HTTP_URL",
        default_value = DEFAULT_SUPERVISOR_URL
    )]
    pub supervisor_http: String,

    /// Safety level for the supervisor
    #[arg(
        long = "rollup.supervisor-safety-level",
        default_value_t = SafetyLevel::CrossUnsafe,
    )]
    pub supervisor_safety_level: SafetyLevel,
}

impl Default for SovaArgs {
    fn default() -> Self {
        Self {
            btc_network: BitcoinNetwork::default(),
            network_url: "http://127.0.0.1".to_string(),
            btc_rpc_username: "user".to_string(),
            btc_rpc_password: "password".to_string(),
            network_utxos_url: "http://127.0.0.1:3031".to_string(),
            sentinel_url: "http://[::1]:50051".to_string(),
            sentinel_confirmation_threshold: 6,
            sequencer_mode: false,
            sequencer: None,
            disable_txpool_gossip: false,
            enable_genesis_walkback: false,
            compute_pending_block: false,
            discovery_v4: false,
            enable_tx_conditional: false,
            supervisor_http: DEFAULT_SUPERVISOR_URL.to_string(),
            supervisor_safety_level: SafetyLevel::CrossUnsafe,
        }
    }
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
    pub network: Network,
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

impl ToString for BitcoinNetwork {
    fn to_string(&self) -> String {
        match self.network {
            Network::Regtest => "regtest".to_string(),
            Network::Testnet => "testnet".to_string(),
            Network::Signet => "signet".to_string(),
            Network::Bitcoin => "mainnet".to_string(),
            _ => "regtest".to_string(),
        }
    }
}

impl From<&str> for BitcoinNetwork {
    fn from(s: &str) -> Self {
        match parse_network(&s) {
            Ok(network) => BitcoinNetwork::from(network),
            Err(err) => {
                eprintln!("Error parsing network: {}", err);
                BitcoinNetwork::default()
            }
        }
    }
}
