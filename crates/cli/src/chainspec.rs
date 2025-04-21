use reth_optimism_chainspec::OpChainSpec;
use sova_chainspec::{DEV, SOVA, TESTNET};

use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use std::sync::Arc;

/// Chains supported by reth. First value should be used as the default.
pub const SUPPORTED_CHAINS: &[&str] = &["sova", "testnet", "dev"];

/// Sova chain specification parser
/// Using ChainSpec for inheriting all past and future ethereum forkchoices.
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