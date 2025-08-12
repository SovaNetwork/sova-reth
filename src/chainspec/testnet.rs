use std::sync::{Arc, LazyLock};

use reth_chainspec::Chain;
use reth_optimism_chainspec::{OpChainSpec, OpChainSpecBuilder};

use super::constants::sova_forks;

pub static TESTNET: LazyLock<Arc<OpChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("res/genesis/sepolia_sova.json"))
        .expect("Can't deserialize Sova Sepolia genesis json");

    let spec: OpChainSpec = OpChainSpecBuilder::default()
        .chain(Chain::from_id(120893))
        .genesis(genesis)
        .with_forks(sova_forks())
        .build();

    spec.into()
});
