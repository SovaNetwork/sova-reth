use clap::Parser;
use reth_optimism_cli::Cli;
use sova_reth::precompiles::BitcoinRpcPrecompile;
use sova_reth::{chainspec::SovaChainSpecParser, SovaArgs, SovaNode};
use std::env;

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

fn set_env_for_sova(args: &SovaArgs) {
    // set only if not already provided in environment
    let set_if_absent = |k: &str, v: String| {
        if env::var_os(k).is_none() {
            env::set_var(k, v);
        }
    };
    set_if_absent("SOVA_BTC_NETWORK", args.btc_network.network.to_string());
    set_if_absent("SOVA_BTC_NETWORK_URL", args.btc_network_url.clone());
    set_if_absent("SOVA_BTC_RPC_USERNAME", args.btc_rpc_username.clone());
    set_if_absent("SOVA_BTC_RPC_PASSWORD", args.btc_rpc_password.clone());
    set_if_absent("SOVA_NETWORK_UTXOS_URL", args.network_utxos_url.clone());
    set_if_absent("SOVA_SENTINEL_URL", args.sentinel_url.clone());
    set_if_absent(
        "SOVA_SENTINEL_CONFIRMATION_THRESHOLD",
        args.sentinel_confirmation_threshold.to_string(),
    );
    // Sequencer mode from CLI takes precedence; otherwise leave existing env as-is
    if args.sequencer.is_some() {
        env::set_var("SOVA_SEQUENCER_MODE", "true");
    }
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
            set_env_for_sova(&sova_args);

            // Fail fast if BTC RPC config is invalid - this will panic if config is missing
            let _ = BitcoinRpcPrecompile::from_env();

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
