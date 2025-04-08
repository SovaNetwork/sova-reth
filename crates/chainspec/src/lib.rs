mod constants;

mod dev;
mod mainnet;
mod testnet;

pub use constants::L1_BLOCK_CONTRACT_ADDRESS;
pub use dev::DEV;
pub use mainnet::SOVA;
pub use testnet::TESTNET;
