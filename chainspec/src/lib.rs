mod constants;
mod dev;
mod mainnet;
mod testnet;

pub use constants::{
    BitcoinPrecompileMethod, BITCOIN_PRECOMPILE_ADDRESSES, BROADCAST_TRANSACTION_ADDRESS,
    BROADCAST_TRANSACTION_PRECOMPILE_ID, CONVERT_ADDRESS_ADDRESS, CONVERT_ADDRESS_PRECOMPILE_ID,
    DECODE_TRANSACTION_ADDRESS, DECODE_TRANSACTION_PRECOMPILE_ID,
    L1_BLOCK_CURRENT_BLOCK_HEIGHT_SLOT, SOVA_ADDR_CONVERT_DOMAIN_TAG, SOVA_BTC_CONTRACT_ADDRESS,
    SOVA_L1_BLOCK_CONTRACT_ADDRESS,
};
pub use dev::{DEV, SOVA_TESTNET_DERIVATION_XPUB};
pub use mainnet::{SOVA, SOVA_MAINNET_DERIVATION_XPUB};
pub use testnet::TESTNET;

use std::sync::Arc;

use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_optimism_chainspec::OpChainSpec;

/// Chains supported by sova-reth
///
/// mainnet -> sova (Bitcoin mainnet, ETH Mainnet)
/// devnet -> dev (Bitcoin regtest, ETH Sepolia)
pub const SUPPORTED_CHAINS: &[&str] = &["dev", "testnet", "sova"];

/// Sova chain specification parser
/// Using OpChainSpec for inheriting all past and future OP & ethereum forkchoices.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SovaChainSpecParser;

impl ChainSpecParser for SovaChainSpecParser {
    type ChainSpec = OpChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        Ok(match s {
            "dev" => DEV.clone(),
            "testnet" => TESTNET.clone(),
            "sova" => SOVA.clone(),
            _ => Arc::new(parse_genesis(s)?.into()),
        })
    }
}
