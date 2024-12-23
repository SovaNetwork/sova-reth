mod constants;
mod dev;

use std::sync::OnceLock;

use constants::MAINNET_DEPOSIT_CONTRACT;
pub use dev::CORSA_DEV;

use derive_more::{Constructor, Deref, From, Into};

use reth_chainspec::{ChainSpec, ChainSpecBuilder, DepositContract};
use reth_ethereum_forks::{ChainHardforks, EthereumHardfork, ForkCondition, Hardfork};

use alloy_chains::Chain;
use alloy_genesis::Genesis;
use alloy_primitives::U256;

/// Chain spec builder for a Corsa stack chain.
#[derive(Debug, Default, From)]
pub struct CorsaChainSpecBuilder {
    /// [`ChainSpecBuilder`]
    inner: ChainSpecBuilder,
}

impl CorsaChainSpecBuilder {
    /// Construct a new builder from the base mainnet chain spec.
    pub fn corsa_dev() -> Self {
        let mut inner = ChainSpecBuilder::default()
            .chain(CORSA_DEV.chain)
            .genesis(CORSA_DEV.genesis.clone());
        let forks = CORSA_DEV.hardforks.clone();
        inner = inner.with_forks(forks);

        Self { inner }
    }
}

impl CorsaChainSpecBuilder {
    /// Set the chain ID
    pub fn chain(mut self, chain: Chain) -> Self {
        self.inner = self.inner.chain(chain);
        self
    }

    /// Set the genesis block.
    pub fn genesis(mut self, genesis: Genesis) -> Self {
        self.inner = self.inner.genesis(genesis);
        self
    }

    /// Add the given fork with the given activation condition to the spec.
    pub fn with_fork<H: Hardfork>(mut self, fork: H, condition: ForkCondition) -> Self {
        self.inner = self.inner.with_fork(fork, condition);
        self
    }

    /// Add the given chain hardforks to the spec.
    pub fn with_forks(mut self, forks: ChainHardforks) -> Self {
        self.inner = self.inner.with_forks(forks);
        self
    }

    /// Remove the given fork from the spec.
    pub fn without_fork<H: Hardfork>(mut self, fork: H) -> Self {
        self.inner = self.inner.without_fork(fork);
        self
    }

    /// Enable the Paris hardfork at the given TTD.
    ///
    /// Does not set the merge netsplit block.
    pub fn paris_at_ttd(self, ttd: U256) -> Self {
        self.with_fork(
            EthereumHardfork::Paris,
            ForkCondition::TTD {
                total_difficulty: ttd,
                fork_block: None,
            },
        )
    }

    /// Enable Frontier at genesis.
    pub fn frontier_activated(self) -> Self {
        self.with_fork(EthereumHardfork::Frontier, ForkCondition::Block(0))
    }

    /// Enable Homestead at genesis.
    pub fn homestead_activated(mut self) -> Self {
        self = self.frontier_activated();
        self.with_fork(EthereumHardfork::Homestead, ForkCondition::Block(0))
    }

    /// Enable Tangerine at genesis.
    pub fn tangerine_whistle_activated(mut self) -> Self {
        self = self.homestead_activated();
        self.with_fork(EthereumHardfork::Tangerine, ForkCondition::Block(0))
    }

    /// Enable Spurious Dragon at genesis.
    pub fn spurious_dragon_activated(mut self) -> Self {
        self = self.tangerine_whistle_activated();
        self.with_fork(EthereumHardfork::SpuriousDragon, ForkCondition::Block(0))
    }

    /// Enable Byzantium at genesis.
    pub fn byzantium_activated(mut self) -> Self {
        self = self.spurious_dragon_activated();
        self.with_fork(EthereumHardfork::Byzantium, ForkCondition::Block(0))
    }

    /// Enable Constantinople at genesis.
    pub fn constantinople_activated(mut self) -> Self {
        self = self.byzantium_activated();
        self.with_fork(EthereumHardfork::Constantinople, ForkCondition::Block(0))
    }

    /// Enable Petersburg at genesis.
    pub fn petersburg_activated(mut self) -> Self {
        self = self.constantinople_activated();
        self.with_fork(EthereumHardfork::Petersburg, ForkCondition::Block(0))
    }

    /// Enable Istanbul at genesis.
    pub fn istanbul_activated(mut self) -> Self {
        self = self.petersburg_activated();
        self.with_fork(EthereumHardfork::Istanbul, ForkCondition::Block(0))
    }

    /// Enable Berlin at genesis.
    pub fn berlin_activated(mut self) -> Self {
        self = self.istanbul_activated();
        self.with_fork(EthereumHardfork::Berlin, ForkCondition::Block(0))
    }

    /// Enable London at genesis.
    pub fn london_activated(mut self) -> Self {
        self = self.berlin_activated();
        self.with_fork(EthereumHardfork::London, ForkCondition::Block(0))
    }

    /// Enable Paris at genesis.
    pub fn paris_activated(mut self) -> Self {
        self = self.london_activated();
        self.with_fork(
            EthereumHardfork::Paris,
            ForkCondition::TTD {
                fork_block: Some(0),
                total_difficulty: U256::ZERO,
            },
        )
    }

    /// Enable Shanghai at genesis.
    pub fn shanghai_activated(mut self) -> Self {
        self = self.paris_activated();
        self.with_fork(EthereumHardfork::Shanghai, ForkCondition::Timestamp(0))
    }

    /// Enable Cancun at genesis.
    pub fn cancun_activated(mut self) -> Self {
        self = self.shanghai_activated();
        self.with_fork(EthereumHardfork::Cancun, ForkCondition::Timestamp(0))
    }

    /// Enable Prague at genesis.
    pub fn prague_activated(mut self) -> Self {
        self = self.cancun_activated();
        self.with_fork(EthereumHardfork::Prague, ForkCondition::Timestamp(0))
    }

    /// Enable Osaka at genesis.
    pub fn osaka_activated(mut self) -> Self {
        self = self.prague_activated();
        self.with_fork(EthereumHardfork::Osaka, ForkCondition::Timestamp(0))
    }

    /// Build the resulting [`CorsaChainSpec`].
    ///
    /// # Panics
    ///
    /// This function panics if the chain ID and genesis is not set ([`Self::chain`] and
    /// [`Self::genesis`])
    pub fn build(self) -> CorsaChainSpec {
        CorsaChainSpec {
            inner: self.inner.build(),
        }
    }
}

/// Corsa stack chain spec type.
#[derive(Debug, Clone, Deref, Into, Constructor, PartialEq, Eq)]
pub struct CorsaChainSpec {
    /// [`ChainSpec`].
    pub inner: ChainSpec,
}

impl From<Genesis> for CorsaChainSpec {
    fn from(genesis: Genesis) -> Self {
        // Block-based hardforks
        let hardfork_opts = [
            (
                EthereumHardfork::Homestead.boxed(),
                genesis.config.homestead_block,
            ),
            (EthereumHardfork::Dao.boxed(), genesis.config.dao_fork_block),
            (
                EthereumHardfork::Tangerine.boxed(),
                genesis.config.eip150_block,
            ),
            (
                EthereumHardfork::SpuriousDragon.boxed(),
                genesis.config.eip155_block,
            ),
            (
                EthereumHardfork::Byzantium.boxed(),
                genesis.config.byzantium_block,
            ),
            (
                EthereumHardfork::Constantinople.boxed(),
                genesis.config.constantinople_block,
            ),
            (
                EthereumHardfork::Petersburg.boxed(),
                genesis.config.petersburg_block,
            ),
            (
                EthereumHardfork::Istanbul.boxed(),
                genesis.config.istanbul_block,
            ),
            (
                EthereumHardfork::MuirGlacier.boxed(),
                genesis.config.muir_glacier_block,
            ),
            (
                EthereumHardfork::Berlin.boxed(),
                genesis.config.berlin_block,
            ),
            (
                EthereumHardfork::London.boxed(),
                genesis.config.london_block,
            ),
            (
                EthereumHardfork::ArrowGlacier.boxed(),
                genesis.config.arrow_glacier_block,
            ),
            (
                EthereumHardfork::GrayGlacier.boxed(),
                genesis.config.gray_glacier_block,
            ),
        ];
        let mut hardforks = hardfork_opts
            .into_iter()
            .filter_map(|(hardfork, opt)| opt.map(|block| (hardfork, ForkCondition::Block(block))))
            .collect::<Vec<_>>();

        // Paris
        let paris_block_and_final_difficulty =
            if let Some(ttd) = genesis.config.terminal_total_difficulty {
                hardforks.push((
                    EthereumHardfork::Paris.boxed(),
                    ForkCondition::TTD {
                        total_difficulty: ttd,
                        fork_block: genesis.config.merge_netsplit_block,
                    },
                ));

                genesis
                    .config
                    .merge_netsplit_block
                    .map(|block| (block, ttd))
            } else {
                None
            };

        // Time-based hardforks
        let time_hardfork_opts = [
            (
                EthereumHardfork::Shanghai.boxed(),
                genesis.config.shanghai_time,
            ),
            (EthereumHardfork::Cancun.boxed(), genesis.config.cancun_time),
            (EthereumHardfork::Prague.boxed(), genesis.config.prague_time),
            (EthereumHardfork::Osaka.boxed(), genesis.config.osaka_time),
        ];

        let mut time_hardforks = time_hardfork_opts
            .into_iter()
            .filter_map(|(hardfork, opt)| {
                opt.map(|time| (hardfork, ForkCondition::Timestamp(time)))
            })
            .collect::<Vec<_>>();

        hardforks.append(&mut time_hardforks);

        // Ordered Hardforks
        let mainnet_hardforks: ChainHardforks = EthereumHardfork::mainnet().into();
        let mainnet_order = mainnet_hardforks.forks_iter();

        let mut ordered_hardforks = Vec::with_capacity(hardforks.len());
        for (hardfork, _) in mainnet_order {
            if let Some(pos) = hardforks.iter().position(|(e, _)| **e == *hardfork) {
                ordered_hardforks.push(hardforks.remove(pos));
            }
        }

        // append the remaining unknown hardforks to ensure we don't filter any out
        ordered_hardforks.append(&mut hardforks);

        // NOTE: in full node, we prune all receipts except the deposit contract's. We do not
        // have the deployment block in the genesis file, so we use block zero. We use the same
        // deposit topic as the mainnet contract if we have the deposit contract address in the
        // genesis json.
        let deposit_contract =
            genesis
                .config
                .deposit_contract_address
                .map(|address| DepositContract {
                    address,
                    block: 0,
                    topic: MAINNET_DEPOSIT_CONTRACT.topic,
                });

        Self {
            inner: ChainSpec {
                chain: genesis.config.chain_id.into(),
                genesis,
                genesis_hash: OnceLock::new(),
                hardforks: ChainHardforks::new(ordered_hardforks),
                paris_block_and_final_difficulty,
                deposit_contract,
                ..Default::default()
            },
        }
    }
}
