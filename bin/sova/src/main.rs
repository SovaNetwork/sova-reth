use clap::Parser;

use reth::{cli::Cli, providers::providers::BlockchainProvider};
use reth_node_ethereum::{node::EthereumAddOns, EthereumNode};

use sova_cli::{SovaChainSpecParser, SovaConfig};
use sova_evm::MyExecutorBuilder;
use sova_node::SovaArgs;
use sova_payload::MyPayloadBuilder;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) =
        // Using SovaChainSpecParser for inheriting all ethereum forkchoices
        // Sova args are used to provide flags for auxiliary services
        Cli::<SovaChainSpecParser, SovaArgs>::parse().run(|builder, sova_args| async move {
                let app_config: SovaConfig = SovaConfig::new(
                    &sova_args.btc_network,
                    &sova_args.network_url,
                    &sova_args.btc_rpc_username,
                    &sova_args.btc_rpc_password,
                    &sova_args.network_signing_url,
                    &sova_args.network_utxo_url,
                    &sova_args.btc_tx_queue_url,
                );

                let handle = builder
                    .with_types_and_provider::<EthereumNode, BlockchainProvider<_>>()
                    .with_components(
                        EthereumNode::components()
                            .executor(MyExecutorBuilder::new(&app_config))
                            .payload(MyPayloadBuilder::new(&app_config)),
                    )
                    .with_add_ons(EthereumAddOns::default())
                    .launch()
                    .await
                    .unwrap();

                handle.node_exit_future.await
            })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
