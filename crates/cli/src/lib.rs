use std::{ffi::OsString, fmt, future::Future, sync::Arc};

use clap::{command, value_parser, Parser};

use chainspec::CorsaChainSpecParser;
use commands::Commands;
use corsa_reth_chainspec::CorsaChainSpec;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::node::NoArgs;
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use reth_node_core::args::LogArgs;
use reth_tracing::FileWorkerGuard;
use tracing::info;

// This allows us to manually enable node metrics features, required for proper jemalloc metric
// reporting
use reth_node_metrics as _;
use reth_node_metrics::recorder::install_prometheus_recorder;

pub mod args;
pub mod chainspec;
pub mod cli;
pub mod commands;

/// The main corsa-reth cli interface.
///
/// This is the entrypoint to the executable.
#[derive(Debug, clap::Parser)]
#[command(long_version = "v0.0.2", about = "Corsa Reth", long_about = None)]
pub struct Cli<Spec: ChainSpecParser = CorsaChainSpecParser, Ext: clap::Args + fmt::Debug = NoArgs>
{
    /// The command to run
    #[command(subcommand)]
    command: Commands<Spec, Ext>,

    /// The chain this node is running.
    ///
    /// Possible values are either a built-in chain or the path to a chain specification file.
    #[arg(
        long,
        value_name = "CHAIN_OR_PATH",
        long_help = Spec::help_message(),
        default_value = Spec::SUPPORTED_CHAINS[0],
        value_parser = Spec::parser(),
        global = true,
    )]
    chain: Arc<Spec::ChainSpec>,

    /// Add a new instance of a node.
    ///
    /// Configures the ports of the node to avoid conflicts with the defaults.
    /// This is useful for running multiple nodes on the same machine.
    ///
    /// Max number of instances is 200. It is chosen in a way so that it's not possible to have
    /// port numbers that conflict with each other.
    ///
    /// Changes to the following port numbers:
    /// - `DISCOVERY_PORT`: default + `instance` - 1
    /// - `AUTH_PORT`: default + `instance` * 100 - 100
    /// - `HTTP_RPC_PORT`: default - `instance` + 1
    /// - `WS_RPC_PORT`: default + `instance` * 2 - 2
    #[arg(long, value_name = "INSTANCE", global = true, default_value_t = 1, value_parser = value_parser!(u16).range(..=200))]
    instance: u16,

    #[command(flatten)]
    logs: LogArgs,
}

impl Cli {
    /// Parsers only the default CLI arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Parsers only the default CLI arguments from the given iterator
    pub fn try_parse_args_from<I, T>(itr: I) -> Result<Self, clap::error::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        Self::try_parse_from(itr)
    }
}

// impl<C, Ext> Cli<C, Ext>
// where
//     C: ChainSpecParser<ChainSpec = CorsaChainSpec>,
//     Ext: clap::Args + fmt::Debug,
// {
//     /// Execute the configured cli command.
//     ///
//     /// This accepts a closure that is used to launch the node via the
//     /// [`NodeCommand`](reth_cli_commands::node::NodeCommand).
//     pub fn run<L, Fut>(mut self, launcher: L) -> eyre::Result<()>
//     where
//         L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, C::ChainSpec>>, Ext) -> Fut,
//         Fut: Future<Output = eyre::Result<()>>,
//     {
//         // add network name to logs dir
//         self.logs.log_file_directory = self
//             .logs
//             .log_file_directory
//             .join(self.chain.chain().to_string());

//         let _guard = self.init_tracing()?;
//         info!(target: "reth::cli", "Initialized tracing, debug log directory: {}", self.logs.log_file_directory);

//         // Install the prometheus recorder to be sure to record all metrics
//         let _ = install_prometheus_recorder();

//         let runner = CliRunner::default();
//         match self.command {
//             Commands::Node(command) => {
//                 runner.run_command_until_exit(|ctx| command.execute(ctx, launcher))
//             }
//             Commands::Init(command) => {
//                 runner.run_blocking_until_ctrl_c(command.execute::<OpNode>())
//             }
//             Commands::InitState(command) => {
//                 runner.run_blocking_until_ctrl_c(command.execute::<OpNode>())
//             }
//             Commands::ImportOp(command) => {
//                 runner.run_blocking_until_ctrl_c(command.execute::<OpNode>())
//             }
//             Commands::DumpGenesis(command) => runner.run_blocking_until_ctrl_c(command.execute()),
//             Commands::Db(command) => runner.run_blocking_until_ctrl_c(command.execute::<OpNode>()),
//             Commands::Stage(command) => runner.run_command_until_exit(|ctx| {
//                 command
//                     .execute::<OpNode, _, _, OpNetworkPrimitives>(ctx, OpExecutorProvider::optimism)
//             }),
//             Commands::P2P(command) => {
//                 runner.run_until_ctrl_c(command.execute::<OpNetworkPrimitives>())
//             }
//             Commands::Config(command) => runner.run_until_ctrl_c(command.execute()),
//             Commands::Recover(command) => {
//                 runner.run_command_until_exit(|ctx| command.execute::<OpNode>(ctx))
//             }
//             Commands::Prune(command) => runner.run_until_ctrl_c(command.execute::<OpNode>()),
//         }
//     }
//
//     /// Initializes tracing with the configured options.
//     ///
//     /// If file logging is enabled, this function returns a guard that must be kept alive to ensure
//     /// that all logs are flushed to disk.
//     pub fn init_tracing(&self) -> eyre::Result<Option<FileWorkerGuard>> {
//         let guard = self.logs.init_tracing()?;
//         Ok(guard)
//     }
// }
