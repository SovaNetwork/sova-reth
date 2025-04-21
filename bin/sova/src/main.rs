use clap::Parser;

use reth_optimism_cli::Cli;

use reth_tracing::tracing::info;

use sova_cli::SovaChainSpecParser;
use sova_node::{SovaArgs, SovaNode};

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
                info!(target: "reth::cli", "Launching node");

                let sova_node = SovaNode::new(sova_args)
                    .map_err(|e| eyre::eyre!("Failed to create Sova node: {}", e))?;

                let handle = builder.launch_node(sova_node).await?;
                handle.node_exit_future.await
            })
    {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
