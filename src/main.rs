
use clap::Parser;

use reth::{
    builder::{
        engine_tree_config::{
            TreeConfig, DEFAULT_MEMORY_BLOCK_BUFFER_TARGET, DEFAULT_PERSISTENCE_THRESHOLD,
        },
        EngineNodeLauncher, NodeBuilder,
    },
    providers::providers::BlockchainProvider2,
    tasks::TaskManager,
};

use reth_node_core::{args::RpcServerArgs, node_config::NodeConfig};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};
use reth_tracing::{tracing::info, RethTracer, Tracer};

mod cli;
mod config;
mod modules;

use cli::Args;
use config::{custom_chain, CorsaConfig};
use modules::execute::MyExecutorBuilder;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _guard = RethTracer::new().init()?;

    let tasks = TaskManager::current();

    let args = Args::parse();
    let app_config = CorsaConfig::new(&args);

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

    info!("Corsa EVM node started");

    handle.node_exit_future.await
}
