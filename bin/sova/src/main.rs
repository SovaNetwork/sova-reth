use clap::Parser;
use reth_optimism_cli::Cli;
use reth_tracing::tracing::info;
use sova_reth::precompiles::BitcoinRpcPrecompile;
use sova_reth::{chainspec::SovaChainSpecParser, SovaArgs, SovaNode};
use std::env;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn set_env_for_sova(args: SovaArgs) {
    // Set environment variables for Sova
    env::set_var("SOVA_BTC_NETWORK", args.btc_network.network.to_string());
    env::set_var("SOVA_BTC_NETWORK_URL", args.btc_network_url);
    env::set_var("SOVA_BTC_RPC_USERNAME", args.btc_rpc_username);
    env::set_var("SOVA_BTC_RPC_PASSWORD", args.btc_rpc_password);
    env::set_var("SOVA_RPC_CONNECTION_TYPE", args.rpc_connection_type);
    env::set_var("SOVA_NETWORK_UTXOS_URL", args.network_utxos_url);
    env::set_var("SOVA_SENTINEL_URL", args.sentinel_url);
    env::set_var(
        "SOVA_SENTINEL_CONFIRMATION_THRESHOLD",
        args.sentinel_confirmation_threshold.to_string(),
    );
}

fn main() {
    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) =
        Cli::<SovaChainSpecParser, SovaArgs>::parse().run(|builder, sova_args| async move {
            // Set environment variables for Sova
            set_env_for_sova(sova_args.clone());
            // Sanity check to ensure the Sova args are valid
            let _ = BitcoinRpcPrecompile::from_env();

            info!(target: "reth::cli", "Launching node");

            let handle = builder
                .node(SovaNode::default())
                .launch_with_debug_capabilities()
                .await?;
            handle.node_exit_future.await
        })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
