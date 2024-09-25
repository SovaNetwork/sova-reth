use std::sync::Arc;

use clap::Parser;
use parking_lot::RwLock;

use reth::{
    builder::{components::ExecutorBuilder, BuilderContext, EngineNodeLauncher},
    cli::Cli,
    primitives::{address, revm_primitives::Env, Bytes},
    providers::providers::BlockchainProvider2,
    revm::{
        handler::register::EvmHandler,
        inspector_handle_register,
        precompile::{Precompile, PrecompileSpecId},
        ContextPrecompile, ContextPrecompiles, Database, Evm, EvmBuilder, GetInspector,
    },
};
use reth_chainspec::ChainSpec;
use reth_node_api::{ConfigureEvm, ConfigureEvmEnv, FullNodeTypes};
use reth_node_optimism::{
    args::RollupArgs, node::OptimismAddOns, rpc::SequencerClient, OptimismNode,
};
use reth_node_optimism::{OpExecutorProvider, OptimismEvmConfig};
use reth_primitives::{
    revm_primitives::{CfgEnvWithHandlerCfg, TxEnv},
    Address, Header, TransactionSigned, U256,
};

mod cli;
mod config;
mod modules;

use cli::CorsaRollupArgs;
use config::CorsaConfig;
use modules::bitcoin_precompile::BitcoinRpcPrecompile;

#[derive(Clone)]
pub struct MyEvmConfig {
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl MyEvmConfig {
    pub fn new(config: &CorsaConfig) -> Self {
        let bitcoin_precompile = BitcoinRpcPrecompile::new(config.bitcoin.as_ref())
            .expect("Failed to create Bitcoin RPC precompile");
        Self {
            bitcoin_rpc_precompile: Arc::new(RwLock::new(bitcoin_precompile)),
        }
    }

    pub fn set_precompiles<EXT, DB>(
        handler: &mut EvmHandler<EXT, DB>,
        bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
    ) where
        DB: Database,
    {
        let spec_id = handler.cfg.spec_id;
        let mut loaded_precompiles: ContextPrecompiles<DB> =
            ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id));

        loaded_precompiles.to_mut().insert(
            address!("0000000000000000000000000000000000000999"),
            ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                BitcoinRpcPrecompile::clone(&bitcoin_rpc_precompile.read()),
            ))),
        );

        handler.pre_execution.load_precompiles = Arc::new(move || loaded_precompiles.clone());
    }
}

impl ConfigureEvmEnv for MyEvmConfig {
    fn fill_cfg_env(
        &self,
        cfg_env: &mut CfgEnvWithHandlerCfg,
        chain_spec: &ChainSpec,
        header: &Header,
        total_difficulty: U256,
    ) {
        OptimismEvmConfig::default().fill_cfg_env(cfg_env, chain_spec, header, total_difficulty)
    }

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        OptimismEvmConfig::default().fill_tx_env(tx_env, transaction, sender)
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        OptimismEvmConfig::default().fill_tx_env_system_contract_call(env, caller, contract, data)
    }
}

impl ConfigureEvm for MyEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        EvmBuilder::default()
            .with_db(db)
            .optimism()
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .build()
    }

    fn evm_with_inspector<DB, I>(&self, db: DB, inspector: I) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            .optimism()
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {}
}

#[derive(Clone)]
pub struct MyExecutorBuilder {
    config: CorsaConfig,
}

impl MyExecutorBuilder {
    pub fn new(config: CorsaConfig) -> Self {
        Self { config }
    }
}

impl<Node> ExecutorBuilder<Node> for MyExecutorBuilder
where
    Node: FullNodeTypes,
{
    type EVM = MyEvmConfig;
    type Executor = OpExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = MyEvmConfig::new(&self.config);
        Ok((
            evm_config.clone(),
            OpExecutorProvider::new(ctx.chain_spec(), evm_config),
        ))
    }
}

fn main() -> eyre::Result<()> {
    Cli::<CorsaRollupArgs>::parse().run(|builder, rollup_args| async move {
        let sequencer_http_arg = rollup_args.sequencer_http.clone();
        let app_config = CorsaConfig::new(&rollup_args);
        let rollup_args: RollupArgs = rollup_args.into();
        let handle = builder
            .with_types_and_provider::<OptimismNode, BlockchainProvider2<_>>()
            .with_components(
                OptimismNode::components(rollup_args)
                    .executor(MyExecutorBuilder::new(app_config.clone())),
            )
            .with_add_ons::<OptimismAddOns>()
            .extend_rpc_modules(move |ctx| {
                // register sequencer tx forwarder
                if let Some(sequencer_http) = sequencer_http_arg {
                    ctx.registry
                        .set_eth_raw_transaction_forwarder(Arc::new(SequencerClient::new(
                            sequencer_http,
                        )));
                }

                Ok(())
            })
            .launch_with_fn(|builder| {
                let launcher = EngineNodeLauncher::new(
                    builder.task_executor().clone(),
                    builder.config().datadir(),
                );
                builder.launch_with(launcher)
            })
            .await?;

        handle.node_exit_future.await
    })
}
