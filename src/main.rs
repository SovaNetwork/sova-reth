use std::sync::Arc;
use std::path::PathBuf;
use parking_lot::RwLock;

use reth::{
    builder::{components::ExecutorBuilder, BuilderContext, NodeBuilder},
    primitives::{address, revm_primitives::Env, Bytes},
    revm::{
        handler::register::EvmHandler,
        inspector_handle_register,
        precompile::{Precompile, PrecompileSpecId},
        ContextPrecompile,
        ContextPrecompiles,
        Database,
        Evm,
        EvmBuilder,
        GetInspector
    },
    tasks::TaskManager,
};
use reth_chainspec::{ChainSpec, Head};
use reth_evm_ethereum::EthEvmConfig;
use reth_node_api::{ConfigureEvm, ConfigureEvmEnv, FullNodeTypes};
use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::{
    node::EthereumAddOns,
    EthExecutorProvider,
    EthereumNode,
};
use reth_primitives::{
    revm_primitives::{AnalysisKind, CfgEnvWithHandlerCfg, TxEnv},
    Address, Header, TransactionSigned, U256,
};
use reth_tracing::{RethTracer, Tracer};

mod modules;
mod settings;
mod genesis;

use modules::bitcoin_precompile::BitcoinRpcPrecompile;
use settings::Settings;
use genesis::custom_chain;

#[derive(Clone)]
pub struct MyEvmConfig {
    bitcoin_rpc_precompile: Arc<RwLock<BitcoinRpcPrecompile>>,
}

impl MyEvmConfig {
    pub fn new(settings: &Settings) -> Self {
        let bitcoin_precompile = BitcoinRpcPrecompile::new(settings)
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
            ContextPrecompile::Ordinary(Precompile::StatefulMut(
                Box::new(BitcoinRpcPrecompile::clone(&bitcoin_rpc_precompile.read()))
            )),
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
        let spec_id = reth_evm_ethereum::revm_spec(
            chain_spec,
            &Head {
                number: header.number,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                total_difficulty,
                hash: Default::default(),
            },
        );

        cfg_env.chain_id = chain_spec.chain().id();
        cfg_env.perf_analyse_created_bytecodes = AnalysisKind::Analyse;

        cfg_env.handler_cfg.spec_id = spec_id;
    }

    fn fill_tx_env(&self, tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        EthEvmConfig::default().fill_tx_env(tx_env, transaction, sender)
    }

    fn fill_tx_env_system_contract_call(
        &self,
        env: &mut Env,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) {
        EthEvmConfig::default().fill_tx_env_system_contract_call(env, caller, contract, data)
    }
}

impl ConfigureEvm for MyEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<DB: Database>(&self, db: DB) -> Evm<'_, Self::DefaultExternalContext<'_>, DB> {
        let bitcoin_rpc_precompile = self.bitcoin_rpc_precompile.clone();

        EvmBuilder::default()
            .with_db(db)
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, bitcoin_rpc_precompile.clone())
            }))
            .build()
    }

    fn evm_with_inspector<DB, I>(&self, db: DB, inspector: I) -> Evm<'_, I, DB>
    where
        DB: Database,
        I: GetInspector<DB>,
    {
        let bitcoin_rpc_precompile = self.bitcoin_rpc_precompile.clone();

        EvmBuilder::default()
            .with_db(db)
            .with_external_context(inspector)
            // add additional precompiles
            .append_handler_register_box(Box::new(move |handler| {
                MyEvmConfig::set_precompiles(handler, bitcoin_rpc_precompile.clone())
            }))
            .append_handler_register(inspector_handle_register)
            .build()
    }

    fn default_external_context<'a>(&self) -> Self::DefaultExternalContext<'a> {}
}

#[derive(Debug, Clone)]
pub struct MyExecutorBuilder {
    settings: Settings,
}

impl MyExecutorBuilder {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
        }
    }
}

impl<Node> ExecutorBuilder<Node> for MyExecutorBuilder
where
    Node: FullNodeTypes,
{
    type EVM = MyEvmConfig;
    type Executor = EthExecutorProvider<Self::EVM>;

    async fn build_evm(
        self,
        ctx: &BuilderContext<Node>,
    ) -> eyre::Result<(Self::EVM, Self::Executor)> {
        let evm_config = MyEvmConfig::new(&self.settings);
        Ok((evm_config.clone(), EthExecutorProvider::new(ctx.chain_spec(), evm_config)))
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    let settings = Settings::from_toml_file(&PathBuf::from("settings.toml"))
        .expect("Failed to load settings.toml");

    let node_config = NodeConfig::test()
        .dev() // enable dev chain features, REMOVE THIS IN PRODUCTION
        .with_rpc(RpcServerArgs::default().with_http())
        .with_chain(custom_chain());

    let handle = NodeBuilder::new(node_config)
        .testing_node(tasks.executor())
        .with_types::<EthereumNode>()
        .with_components(EthereumNode::components().executor(MyExecutorBuilder::new(settings)))
        .with_add_ons::<EthereumAddOns>()
        .launch()
        .await
        .unwrap();

    println!("Node started");

    handle.node_exit_future.await
}
