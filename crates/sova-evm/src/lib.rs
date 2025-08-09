mod evm;
mod execute_simple;
mod l1block_reader;
mod provider;
mod precompiles;
mod sentinel_client;
mod sentinel_worker;
mod state_hook;
#[cfg(test)]
mod tests;

pub use evm::{SovaEvmConfig, SovaEvmFactory, WithInspector};
pub use execute_simple::{SovaBlockExecutor, SlotStatus};
pub use l1block_reader::{L1BlockInfo, read_l1block_from_db};
pub use provider::SovaBlockExecutorProvider;
pub use precompiles::{BitcoinClient, BitcoinRpcPrecompile, SovaPrecompiles};
pub use precompiles::btc_client::SovaL1BlockInfo as SovaL1BlockInfoFromClient;
pub use sentinel_client::{SentinelClient, SentinelError};
pub use sentinel_worker::SentinelWorker;
pub use state_hook::{SovaOnStateHook, SharedSovaStateHook, CombinedStateHook};

// Legacy aliases for compatibility during migration
pub type MyEvmConfig = SovaEvmConfig;

// Placeholder for SovaL1BlockInfo - this might need to be implemented or removed
// depending on what the payload crate actually needs
#[derive(Debug, Clone)]
pub struct SovaL1BlockInfo {
    // TODO: Define the actual fields needed for L1 block info
    pub placeholder: bool,
}