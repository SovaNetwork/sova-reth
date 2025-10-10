use std::{ffi::OsString, fmt, future::Future, marker::PhantomData, sync::Arc};

use clap::Parser;
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::launcher::FnLauncher;
use reth_cli_runner::CliRunner;
use reth_db::DatabaseEnv;
use reth_node_builder::{NodeBuilder, WithLaunchContext};
use reth_node_core::{args::LogArgs, version::version_metadata};
use reth_optimism_cli::commands::Commands;
use reth_optimism_node::args::RollupArgs;
use reth_rpc_server_types::{DefaultRpcModuleValidator, RpcModuleValidator};

use sova_chainspec::{SovaChainSpec, SovaChainSpecParser};

mod app;
pub use app::CliApp;

/// The main sova-reth cli interface.
///
/// This is the entrypoint to the executable.
#[derive(Debug, Parser)]
#[command(author, version = version_metadata().short_version.as_ref(), long_version = version_metadata().long_version.as_ref(), about = "Reth", long_about = None)]
pub struct Cli<
    Spec: ChainSpecParser = SovaChainSpecParser,
    Ext: clap::Args + fmt::Debug = RollupArgs,
    Rpc: RpcModuleValidator = DefaultRpcModuleValidator,
> {
    /// The command to run
    #[command(subcommand)]
    pub command: Commands<Spec, Ext>,

    /// The logging configuration for the CLI.
    #[command(flatten)]
    pub logs: LogArgs,

    /// Type marker for the RPC module validator
    #[arg(skip)]
    _phantom: PhantomData<Rpc>,
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

impl<C, Ext, Rpc> Cli<C, Ext, Rpc>
where
    C: ChainSpecParser<ChainSpec = SovaChainSpec>,
    Ext: clap::Args + fmt::Debug,
    Rpc: RpcModuleValidator,
{
    /// Configures the CLI and returns a [`CliApp`] instance.
    ///
    /// This method is used to prepare the CLI for execution by wrapping it in a
    /// [`CliApp`] that can be further configured before running.
    pub fn configure(self) -> CliApp<C, Ext, Rpc> {
        CliApp::new(self)
    }

    /// Execute the configured cli command.
    ///
    /// This accepts a closure that is used to launch the node via the
    /// [`NodeCommand`](reth_cli_commands::node::NodeCommand).
    pub fn run<L, Fut>(self, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, C::ChainSpec>>, Ext) -> Fut,
        Fut: Future<Output = eyre::Result<()>>,
    {
        self.with_runner(CliRunner::try_default_runtime()?, launcher)
    }

    /// Execute the configured cli command with the provided [`CliRunner`].
    pub fn with_runner<L, Fut>(self, runner: CliRunner, launcher: L) -> eyre::Result<()>
    where
        L: FnOnce(WithLaunchContext<NodeBuilder<Arc<DatabaseEnv>, C::ChainSpec>>, Ext) -> Fut,
        Fut: Future<Output = eyre::Result<()>>,
    {
        let mut this = self.configure();
        this.set_runner(runner);
        this.run(FnLauncher::new::<C, Ext>(async move |builder, chain_spec| {
            launcher(builder, chain_spec).await
        }))
    }
}
