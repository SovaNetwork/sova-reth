use std::sync::{Arc, LazyLock};

use reth_chainspec::{once_cell_set, BaseFeeParams, BaseFeeParamsKind, ChainSpec};
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition};

use alloy_chains::Chain;
use alloy_consensus::constants::DEV_GENESIS_HASH;
use alloy_primitives::U256;

use crate::CorsaChainSpec;

/// This activates all hardforks from the start
pub fn dev_hardforks() -> ChainHardforks {
    let mut hardforks = Vec::new();

    // Add all Ethereum hardforks activated at block 0
    hardforks.extend([
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::SpuriousDragon.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Constantinople.boxed(),
            ForkCondition::Block(0),
        ),
        (
            EthereumHardfork::Petersburg.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::MuirGlacier.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::ArrowGlacier.boxed(),
            ForkCondition::Block(0),
        ),
        (
            EthereumHardfork::GrayGlacier.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Paris.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(0),
        ),
        (
            EthereumHardfork::Cancun.boxed(),
            ForkCondition::Timestamp(0),
        ),
    ]);

    ChainHardforks::new(hardforks)
}

/// Static reference to dev hardforks
pub static DEV_HARDFORKS: LazyLock<ChainHardforks> = LazyLock::new(dev_hardforks);

/// Corsa development testnet chain specification
///
/// Includes prefunded development accounts and all hardforks enabled
pub static CORSA_DEV: LazyLock<Arc<CorsaChainSpec>> = LazyLock::new(|| {
    CorsaChainSpec {
        inner: ChainSpec {
            chain: Chain::dev(),
            genesis: serde_json::from_str(include_str!("./genesis/dev.json"))
                .expect("Can't deserialize Dev testnet genesis json"),
            genesis_hash: once_cell_set(DEV_GENESIS_HASH),
            paris_block_and_final_difficulty: Some((0, U256::from(0))),
            hardforks: DEV_HARDFORKS.clone(),
            base_fee_params: BaseFeeParamsKind::Constant(BaseFeeParams::ethereum()),
            deposit_contract: None,
            prune_delete_limit: 10000,
            ..Default::default()
        },
    }
    .into()
});
