mod constants;
mod dev;
mod mainnet;
mod testnet;

use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_optimism_chainspec::OpChainSpec;
use std::sync::Arc;

pub use constants::{
    BitcoinPrecompileMethod, BROADCAST_TRANSACTION_ADDRESS, CONVERT_ADDRESS_ADDRESS,
    DECODE_TRANSACTION_ADDRESS, L1_BLOCK_CONTRACT_ADDRESS, SOVA_ADDR_CONVERT_DOMAIN_TAG,
    SOVA_BTC_CONTRACT_ADDRESS, VAULT_SPEND_ADDRESS, BITCOIN_PRECOMPILE_ADDRESSES
};
pub use dev::DEV;
pub use mainnet::SOVA;
pub use testnet::TESTNET;

/// Chains supported by sova-reth
pub const SUPPORTED_CHAINS: &[&str] = &["sova", "testnet", "dev"];

/// SOVA chain specification parser
/// Using OpChainSpec for inheriting all past and future ethereum forkchoices.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SovaChainSpecParser;

impl ChainSpecParser for SovaChainSpecParser {
    type ChainSpec = OpChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = SUPPORTED_CHAINS;

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        Ok(match s {
            "sova" => SOVA.clone(),
            "testnet" => TESTNET.clone(),
            "dev" => DEV.clone(),
            _ => Arc::new(parse_genesis(s)?.into()),
        })
    }
}
