use std::sync::Arc;

use reth::primitives::Genesis;
use reth_chainspec::ChainSpec;

use bitcoin::Network;

#[derive(Clone)]
pub struct BitcoinConfig {
    pub network: Network,
    pub network_url: String,
    pub rpc_username: String,
    pub rpc_password: String,
}

#[derive(Clone)]
pub struct CorsaConfig {
    pub bitcoin: Arc<BitcoinConfig>,
    pub enclave_url: String
}

impl CorsaConfig {
    pub fn new(args: &crate::cli::Args) -> Self {
        let bitcoin_config = BitcoinConfig {
            network: args.btc_network,
            network_url: args.network_url.clone(),
            rpc_username: args.btc_rpc_username.clone(),
            rpc_password: args.btc_rpc_password.clone(),
        };

        CorsaConfig {
            bitcoin: Arc::new(bitcoin_config),
            enclave_url: args.enclave_url.clone(),
        }
    }
}

/// Genesis data for the testnet
pub fn custom_chain() -> Arc<ChainSpec> {
    let custom_genesis = r#"
    {
        "nonce": "0x42",
        "timestamp": "0x0",
        "extraData": "0x5343",
        "gasLimit": "0x1388",
        "difficulty": "0x400000000",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": {
            "0x1a0Fe90f5Bf076533b2B74a21b3AaDf225CdDfF7": {
                "balance": "0x52b7d2dcc80cd2e4000000"
            }
        },
        "number": "0x0",
        "gasUsed": "0x0",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "config": {
            "ethash": {},
            "chainId": 120893,
            "homesteadBlock": 0,
            "eip150Block": 0,
            "eip155Block": 0,
            "eip158Block": 0,
            "byzantiumBlock": 0,
            "constantinopleBlock": 0,
            "petersburgBlock": 0,
            "istanbulBlock": 0,
            "berlinBlock": 0,
            "londonBlock": 0,
            "terminalTotalDifficulty": 0,
            "terminalTotalDifficultyPassed": true,
            "shanghaiTime": 0,
            "cancunTime": 0
        }
    }
    "#;
    let genesis: Genesis = serde_json::from_str(custom_genesis).unwrap();
    Arc::new(genesis.into())
}
