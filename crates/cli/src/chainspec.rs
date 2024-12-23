use std::sync::Arc;

use derive_more::Into;

use reth_cli::chainspec::{parse_genesis, ChainSpecParser};

use corsa_reth_chainspec::{CorsaChainSpec, CORSA_DEV};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CorsaChainSpecParser;

impl ChainSpecParser for CorsaChainSpecParser {
    type ChainSpec = CorsaChainSpec;

    const SUPPORTED_CHAINS: &'static [&'static str] = &[
        "dev",
        //"mainnet",
    ];

    fn parse(s: &str) -> eyre::Result<Arc<CorsaChainSpec>, eyre::Error> {
        Ok(match s {
            "dev" => CORSA_DEV.clone(),
            // "mainnet" => {
            //     let genesis_string = fs::read_to_string("src/chainspec/mainnet.json")?;
            //     let genesis: Genesis = serde_json::from_str(&genesis_string)?;
            //     Arc::new(genesis.into())
            // }
            _ => Arc::new(parse_genesis(s)?.into()),
        })
    }
}
