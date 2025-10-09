use std::sync::{Arc, LazyLock};

use reth_chainspec::Chain;
use reth_optimism_chainspec::{OpChainSpec, OpChainSpecBuilder};

use super::constants::sova_forks;

/// Sova mainnet derivation xpub
pub const SOVA_MAINNET_DERIVATION_XPUB: &str = "xpub661MyMwAqRbcGdAvHLio9QdLWhMTbnfa27fZSD5quMusfEwxeyrXrbMrkvoPzQ2bcMAeMGbwHDueBpgHRjuHLfR2hFot14QgKqaWrL8PSAj";

pub static SOVA: LazyLock<Arc<OpChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("res/genesis/sova.json"))
        .expect("Can't deserialize Sova Mainnet genesis json");

    let spec: OpChainSpec = OpChainSpecBuilder::default()
        .chain(Chain::from_id(100021))
        .genesis(genesis)
        .with_forks(sova_forks())
        .build();

    spec.into()
});
