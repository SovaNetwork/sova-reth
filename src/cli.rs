use clap::Args;
use reth_node_optimism::args::RollupArgs;

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
#[command(next_help_heading = "Rollup")]
pub struct CorsaRollupArgs {
    /// HTTP endpoint for the sequencer mempool
    #[arg(long = "rollup.sequencer-http", value_name = "HTTP_URL")]
    pub sequencer_http: Option<String>,

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

    /// Enable the engine2 experimental features on op-reth binary POOP
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,

    // bitcoin rpc args
    #[command(flatten)]
    pub bitcoin: BitcoinArgs,
}

/// Our custom cli args extension that adds flags to configure the bitcoin rpc client
#[derive(Debug, Clone, Default, PartialEq, Eq, Args)]
pub struct BitcoinArgs {
    /// bitcoin network the bitcoin rpc client will connect to
    #[arg(long = "bitcoin.network", default_value = "regtest")]
    pub network: String,

    // bitcoin rpc url
    #[arg(long = "bitcoin.url", default_value = "http://127.0.0.1")]
    pub url: String,

    /// bitcoin rpc username
    #[arg(long = "bitcoin.rpc-username", default_value = "user")]
    pub rpc_username: String,

    /// bitcoin rpc password
    #[arg(long = "bitcoin.rpc-password", default_value = "password")]
    pub rpc_password: String,
}

impl From<CorsaRollupArgs> for RollupArgs {
    fn from(args: CorsaRollupArgs) -> Self {
        RollupArgs {
            sequencer_http: args.sequencer_http,
            disable_txpool_gossip: args.disable_txpool_gossip,
            enable_genesis_walkback: args.enable_genesis_walkback,
            compute_pending_block: args.compute_pending_block,
            discovery_v4: args.discovery_v4,
            experimental: args.experimental,
        }
    }
}
