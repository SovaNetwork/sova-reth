use std::{convert::Infallible, sync::Arc};

use clap::Parser;
use parking_lot::RwLock;

use alloy_consensus::Header;
use alloy_primitives::{address, Address, Bytes};

use reth::{
    builder::{
        components::{ExecutorBuilder, PayloadServiceBuilder},
        BuilderContext, NodeBuilder,
    },
    payload::{EthBuiltPayload, EthPayloadBuilderAttributes},
    revm::{
        handler::register::EvmHandler,
        inspector_handle_register,
        precompile::{Precompile, PrecompileSpecId},
        primitives::{CfgEnvWithHandlerCfg, Env, TxEnv},
        ContextPrecompile, ContextPrecompiles, Database, Evm, EvmBuilder, GetInspector,
    },
    rpc::types::engine::PayloadAttributes,
    tasks::TaskManager,
    transaction_pool::{PoolTransaction, TransactionPool},
};
use reth_chainspec::ChainSpec;
use reth_evm::env::EvmEnv;
use reth_evm_ethereum::EthEvmConfig;
use reth_node_api::{
    ConfigureEvm, ConfigureEvmEnv, FullNodeTypes, NextBlockEnvAttributes, NodeTypes,
    NodeTypesWithEngine, PayloadTypes,
};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::{
    node::{EthereumAddOns, EthereumPayloadBuilder},
    BasicBlockExecutorProvider, EthExecutionStrategyFactory, EthereumNode,
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
    fn evm_with_env<DB: Database>(&self, db: DB, evm_env: EvmEnv, tx: TxEnv) -> Evm<'_, (), DB> {
        EvmBuilder::default()
            .with_db(db)
            .with_cfg_env_with_handler_cfg(evm_env.cfg_env_with_handler_cfg)
            .with_block_env(evm_env.block_env)
            .with_tx_env(tx)
            // add BTC precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .build()
    }

    fn evm_with_env_and_inspector<DB, I>(
        &self,
        db: DB,
        evm_env: EvmEnv,
        tx: TxEnv,
        inspector: I,
    ) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            .with_cfg_env_with_handler_cfg(evm_env.cfg_env_with_handler_cfg)
            .with_block_env(evm_env.block_env)
            .with_tx_env(tx)
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, self.bitcoin_rpc_precompile.clone())
            }))
            .append_handler_register(inspector_handle_register)
            .build()
    }
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

/// Builds a regular ethereum block executor that uses the custom EVM.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct MyPayloadBuilder {
    inner: EthereumPayloadBuilder,
    config: SovaConfig,
}

impl<Types, Node, Pool> PayloadServiceBuilder<Node, Pool> for MyPayloadBuilder
where
    Types: NodeTypesWithEngine<ChainSpec = ChainSpec, Primitives = EthPrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Pool: TransactionPool<Transaction: PoolTransaction<Consensus = TransactionSigned>>
        + Unpin
        + 'static,
    Types::Engine: PayloadTypes<
        BuiltPayload = EthBuiltPayload,
        PayloadAttributes = PayloadAttributes,
        PayloadBuilderAttributes = EthPayloadBuilderAttributes,
    >,
{
    async fn spawn_payload_service(
        self,
        ctx: &BuilderContext<Node>,
        pool: Pool,
    ) -> eyre::Result<reth::payload::PayloadBuilderHandle<Types::Engine>> {
        let evm_config = MyEvmConfig::new(&self.config, ctx.chain_spec());
        self.inner.spawn(evm_config, ctx, pool)
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    let args = Args::parse();
    let app_config = SovaConfig::new(
        args.btc_network,
        &args.network_url,
        &args.btc_rpc_username,
        &args.btc_rpc_password,
        &args.network_signing_url,
        &args.network_utxo_url,
        &args.btc_tx_queue_url,
    );

    let node_config = NodeConfig::test()
        .dev() // enable dev chain features, REMOVE THIS IN PRODUCTION
        .with_rpc(RpcServerArgs {
            http: true,
            http_addr: "0.0.0.0".parse().expect("Invalid IP address"), // listen on all available network interfaces
            http_port: 8545,
            ..RpcServerArgs::default()
        })
        .with_chain(custom_chain());

    let handle = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        .with_types::<EthereumNode>()
        .with_components(
            EthereumNode::components()
                .executor(MyExecutorBuilder::new(app_config.clone()))
                .payload(MyPayloadBuilder {
                    inner: EthereumPayloadBuilder::default(),
                    config: app_config.clone(), // Initialize with the config
                }),
        )
        .with_add_ons(EthereumAddOns::default())
        .launch()
        .await
        .unwrap();

    info!("Sova EVM node started");

    handle.node_exit_future.await
}
