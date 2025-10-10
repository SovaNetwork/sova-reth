use crate::{cli::Cli, SovaNode};
use eyre::{eyre, Result};
use reth_cli::chainspec::ChainSpecParser;
use reth_cli_commands::launcher::Launcher;
use reth_cli_runner::CliRunner;
use reth_node_metrics::recorder::install_prometheus_recorder;
use reth_optimism_cli::commands::Commands;
use reth_rpc_server_types::RpcModuleValidator;
use reth_tracing::{tracing::info, FileWorkerGuard, Layers};
use sova_chainspec::SovaChainSpec;
use std::fmt;

/// A wrapper around a parsed CLI that handles command execution.
#[derive(Debug)]
pub struct CliApp<Spec: ChainSpecParser, Ext: clap::Args + fmt::Debug, Rpc: RpcModuleValidator> {
    cli: Cli<Spec, Ext, Rpc>,
    runner: Option<CliRunner>,
    layers: Option<Layers>,
    guard: Option<FileWorkerGuard>,
}

impl<C, Ext, Rpc> CliApp<C, Ext, Rpc>
where
    C: ChainSpecParser<ChainSpec = SovaChainSpec>,
    Ext: clap::Args + fmt::Debug,
    Rpc: RpcModuleValidator,
{
    pub(crate) fn new(cli: Cli<C, Ext, Rpc>) -> Self {
        Self { cli, runner: None, layers: Some(Layers::new()), guard: None }
    }

    /// Sets the runner for the CLI commander.
    ///
    /// This replaces any existing runner with the provided one.
    pub fn set_runner(&mut self, runner: CliRunner) {
        self.runner = Some(runner);
    }

    /// Access to tracing layers.
    ///
    /// Returns a mutable reference to the tracing layers, or error
    /// if tracing initialized and layers have detached already.
    pub fn access_tracing_layers(&mut self) -> Result<&mut Layers> {
        self.layers.as_mut().ok_or_else(|| eyre!("Tracing already initialized"))
    }

    /// Execute the configured cli command.
    ///
    /// This accepts a closure that is used to launch the node via the
    /// [`NodeCommand`](reth_cli_commands::node::NodeCommand).
    pub fn run(mut self, launcher: impl Launcher<C, Ext>) -> Result<()> {
        let runner = match self.runner.take() {
            Some(runner) => runner,
            None => CliRunner::try_default_runtime()?,
        };

        // add network name to logs dir
        // Add network name if available to the logs dir
        if let Some(chain_spec) = self.cli.command.chain_spec() {
            self.cli.logs.log_file_directory = self
                .cli
                .logs
                .log_file_directory
                .join(chain_spec.inner().chain().to_string());
        }

        self.init_tracing()?;
        // Install the prometheus recorder to be sure to record all metrics
        let _ = install_prometheus_recorder();

        match self.cli.command {
            Commands::Node(command) => {
                // Validate RPC modules using the configured validator
                if let Some(http_api) = &command.rpc.http_api {
                    Rpc::validate_selection(http_api, "http.api").map_err(|e| eyre!("{e}"))?;
                }
                if let Some(ws_api) = &command.rpc.ws_api {
                    Rpc::validate_selection(ws_api, "ws.api").map_err(|e| eyre!("{e}"))?;
                }

                runner.run_command_until_exit(|ctx| command.execute(ctx, launcher))
            }
            Commands::Init(command) => {
                runner.run_blocking_until_ctrl_c(command.execute::<SovaNode>())
            }
            Commands::InitState(_command) => unimplemented!("InitState command is not supported for Sova"),
            Commands::ImportOp(_command) => unimplemented!("ImportOp command is not supported for Sova"),
            Commands::ImportReceiptsOp(_command) => unimplemented!("ImportReceiptsOp command is not supported for Sova"),
            Commands::DumpGenesis(command) => runner.run_blocking_until_ctrl_c(command.execute()),
            Commands::Db(command) => {
                runner.run_blocking_until_ctrl_c(command.execute::<SovaNode>())
            }
            Commands::Stage(_command) => unimplemented!("Stage command is not supported for Sova"),
            Commands::P2P(command) => runner.run_until_ctrl_c(command.execute::<SovaNode>()),
            Commands::Config(command) => runner.run_until_ctrl_c(command.execute()),
            Commands::Prune(command) => runner.run_until_ctrl_c(command.execute::<SovaNode>()),
            Commands::ReExecute(_command) => unimplemented!("ReExecute command is not supported for Sova"),
        }
    }

    /// Initializes tracing with the configured options.
    ///
    /// If file logging is enabled, this function stores guard to the struct.
    pub fn init_tracing(&mut self) -> Result<()> {
        if self.guard.is_none() {
            let layers = self.layers.take().unwrap_or_default();
            self.guard = self.cli.logs.init_tracing_with_layers(layers)?;
            info!(target: "reth::cli", "Initialized tracing, debug log directory: {}", self.cli.logs.log_file_directory);
        }
        Ok(())
    }
}
