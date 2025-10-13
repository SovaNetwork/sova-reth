use std::sync::{Arc, LazyLock};

use reth_chainspec::Chain;
use reth_optimism_chainspec::{OpChainSpec, OpChainSpecBuilder};

use crate::SovaChainSpec;

use super::constants::sova_forks;

/// Sova testnet derivation xpub
/// Derived from public BIP32 seed: 999102030405060708090a0b0c0d0e0f
pub const SOVA_TESTNET_DERIVATION_XPUB: &str = "tpubDBDW1EWi7SNXqzpbci5DUc9HuXhx3cUPZ1wyjgxWmDTpwNQR9ijpEb9VomyDEoH7rAZiGmC9f2yQFfqDn5z4H54NavPGK8yuTLJC8JZzTv9";

pub static TESTNET: LazyLock<Arc<SovaChainSpec>> = LazyLock::new(|| {
    let genesis = serde_json::from_str(include_str!("res/genesis/sepolia_sova.json"))
        .expect("Can't deserialize Sova Sepolia genesis json");

    let spec: OpChainSpec = OpChainSpecBuilder::default()
        .chain(Chain::from_id(120893))
        .genesis(genesis)
        .with_forks(sova_forks())
        .build();

    SovaChainSpec { inner: spec }.into()
});
