use std::sync::Arc;

use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use sova_chainspec::{SovaChainSpec, DEV, SOVA, TESTNET};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SovaChainSpecParser;

impl ChainSpecParser for SovaChainSpecParser {
    type ChainSpec = SovaChainSpec;

    /// Chain configurations supported
    ///
    /// mainnet -> Bitcoin mainnet, ETH Mainnet
    /// testnet -> Bitcoin regtest, ETH Sepolia
    /// devnet -> Bitcoin regtest, Local (Mock) Consensus, see reth's `--dev` flag for more details.
    const SUPPORTED_CHAINS: &[&str] = &["sova-devnet", "sova-testnet", "sova"];

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
        chain_value_parser(s)
    }
}

pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<SovaChainSpec>, eyre::Error> {
    Ok(match s {
        "sova-devnet" => DEV.clone(),
        "sova-testnet" => TESTNET.clone(),
        "sova" => SOVA.clone(),
        _ => Arc::new(parse_genesis(s)?.into()),
    })
}
