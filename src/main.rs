use std::{convert::Infallible, sync::Arc};

use clap::Parser;
use parking_lot::RwLock;

use alloy_consensus::Header;
use alloy_primitives::{address, Address, Bytes};

use reth::{
    builder::{
        components::ExecutorBuilder,
        engine_tree_config::{
            TreeConfig, DEFAULT_MEMORY_BLOCK_BUFFER_TARGET, DEFAULT_PERSISTENCE_THRESHOLD,
        },
        BuilderContext, EngineNodeLauncher, NodeBuilder,
    },
    providers::providers::BlockchainProvider2,
    revm::{
        handler::register::EvmHandler,
        inspector_handle_register,
        precompile::{Precompile, PrecompileSpecId},
        primitives::{CfgEnvWithHandlerCfg, Env, TxEnv},
        ContextPrecompile, ContextPrecompiles, Database, Evm, EvmBuilder, GetInspector,
    },
    tasks::TaskManager,
};
use reth_chainspec::ChainSpec;
use reth_evm::env::EvmEnv;
use reth_evm_ethereum::EthEvmConfig;
use reth_node_api::{
    ConfigureEvm, ConfigureEvmEnv, FullNodeTypes, NextBlockEnvAttributes, NodeTypes,
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::{
    node::EthereumAddOns, BasicBlockExecutorProvider, EthExecutionStrategyFactory, EthereumNode,
};
use reth_primitives::{EthPrimitives, TransactionSigned};
use reth_tracing::{tracing::info, RethTracer, Tracer};

mod cli;
mod config;
mod modules;

use cli::Args;
use config::{custom_chain, SovaConfig};
use modules::bitcoin_precompile::BitcoinRpcPrecompile;

#[derive(Clone)]
pub struct MyEvmConfig {
    /// Wrapper around mainnet configuration
    inner: EthEvmConfig,
    /// Bitcoin RPC precompile
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl MyEvmConfig {
    pub fn new(config: &SovaConfig, chain_spec: Arc<ChainSpec>) -> Self {
        let bitcoin_precompile = BitcoinRpcPrecompile::new(
            config.bitcoin.as_ref(),
            config.network_signing_url.clone(),
            config.network_utxo_url.clone(),
            config.btc_tx_queue_url.clone(),
        )
        .expect("Failed to create Bitcoin RPC precompile");
        Self {
            inner: EthEvmConfig::new(chain_spec),
            bitcoin_rpc_precompile: Arc::new(RwLock::new(bitcoin_precompile)),
        }
    }

    /// Sets the precompiles to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet precompiles and add additional precompiles.
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
    type Header = Header;
    type Transaction = TransactionSigned;

    type Error = Infallible;

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        self.inner.fill_tx_env(tx_env, transaction, sender);
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        self.inner
            .fill_tx_env_system_contract_call(env, caller, contract, data);
    }

    fn fill_cfg_env(&self, cfg_env: &mut CfgEnvWithHandlerCfg, header: &Self::Header) {
        self.inner.fill_cfg_env(cfg_env, header);
    }

    fn next_cfg_and_block_env(
        &self,
        parent: &Self::Header,
        attributes: NextBlockEnvAttributes,
    ) -> Result<EvmEnv, Self::Error> {
        self.inner.next_cfg_and_block_env(parent, attributes)
    }
}

impl ConfigureEvm for MyEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        EvmBuilder::default()
            .with_db(db)
            // add BTC precompiles
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
    config: SovaConfig,
}

impl MyExecutorBuilder {
    pub fn new(config: SovaConfig) -> Self {
        Self { config }
    }
}

impl<Node> ExecutorBuilder<Node> for MyExecutorBuilder
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec, Primitives = EthPrimitives>>,
{
    type EVM = MyEvmConfig;
    type Executor = BasicBlockExecutorProvider<EthExecutionStrategyFactory<Self::EVM>>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = MyEvmConfig::new(&self.config, ctx.chain_spec());
        Ok((
            evm_config.clone(),
            BasicBlockExecutorProvider::new(EthExecutionStrategyFactory::new(
                ctx.chain_spec(),
                evm_config,
            )),
        ))
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    let args = Args::parse();
    let app_config = SovaConfig::new(&args);

    let node_config = NodeConfig::test()
        .dev() // enable dev chain features, REMOVE THIS IN PRODUCTION
        .with_rpc(RpcServerArgs {
            http: true,
            http_addr: "0.0.0.0".parse().expect("Invalid IP address"), // listen on all available network interfaces
            http_port: 8545,
            ..RpcServerArgs::default()
        })
        .with_chain(custom_chain());

    // NOTE(powvt): remove this when cli runner is added
    // https://github.com/paradigmxyz/reth/issues/13438#issuecomment-2554490575
    let engine_tree_config = TreeConfig::default()
        .with_persistence_threshold(DEFAULT_PERSISTENCE_THRESHOLD)
        .with_memory_block_buffer_target(DEFAULT_MEMORY_BLOCK_BUFFER_TARGET);

    let handle = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        // NOTE(powvt): remove this when cli runner is added
        .with_types_and_provider::<EthereumNode, BlockchainProvider2<_>>()
        .with_components(
            EthereumNode::components().executor(MyExecutorBuilder::new(app_config.clone())),
        )
        .with_add_ons(EthereumAddOns::default())
        // NOTE(powvt): remove this when cli runner is added
        .launch_with_fn(|builder| {
            let launcher = EngineNodeLauncher::new(
                tasks.executor().clone(),
                builder.config().datadir(),
                engine_tree_config,
            );
            builder.launch_with(launcher)
        })
        .await
        .unwrap();

    info!("Sova EVM node started");

    handle.node_exit_future.await
}
