use std::sync::{Arc, LazyLock};

use reth_chainspec::Chain;
use reth_optimism_chainspec::{OpChainSpec, OpChainSpecBuilder};

use crate::SovaChainSpec;

use super::constants::sova_forks;

/// Sova mainnet derivation xpub
pub const SOVA_MAINNET_DERIVATION_XPUB: &str = "xpub6BebdYenb6pkUyW4zCn2QT7PMN3eN8mpEEvTkrrWpQFrzoaKTKhaQQS8VSyS7VGCZTfNX3fKQ6WqgQM459yb3gRojzZmwnLdUN2PcLkg9Q4";

pub static SOVA: LazyLock<Arc<SovaChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("res/genesis/sova.json"))
        .expect("Can't deserialize Sova Mainnet genesis json");

    let spec: OpChainSpec = OpChainSpecBuilder::default()
        .chain(Chain::from_id(100021))
        .genesis(genesis)
        .with_forks(sova_forks())
        .build();

    SovaChainSpec { inner: spec }.into()
});
