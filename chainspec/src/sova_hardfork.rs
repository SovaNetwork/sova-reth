//! Sova-specific hardfork definitions.

use alloy_hardforks::{hardfork, EthereumHardforks, ForkCondition};

hardfork!(
    /// The name of a Sova hardfork.
    ///
    /// Sova-specific hardforks control features like Bitcoin precompile address derivation.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    SovaHardfork {
        /// Beta: Changes Bitcoin precompile to use SOVA_MAINNET_DERIVATION_XPUB_BETA.
        /// Activates at block 1280000.
        #[default]
        Beta,
    }
);

/// Sova mainnet Beta hardfork activation block.
pub const SOVA_MAINNET_BETA_BLOCK: u64 = 1280000;

impl SovaHardfork {
    /// Returns the activation block for Sova mainnet hardforks.
    pub const fn sova_mainnet() -> [(Self, ForkCondition); 1] {
        [(Self::Beta, ForkCondition::Block(SOVA_MAINNET_BETA_BLOCK))]
    }

    /// Returns index of `self` in sorted canonical array.
    pub const fn idx(&self) -> usize {
        *self as usize
    }
}

/// Extends [`EthereumHardforks`] with Sova helper methods.
#[auto_impl::auto_impl(&, Arc)]
pub trait SovaHardforks: EthereumHardforks {
    /// Retrieves [`ForkCondition`] by a [`SovaHardfork`]. If `fork` is not present, returns
    /// [`ForkCondition::Never`].
    fn sova_fork_activation(&self, fork: SovaHardfork) -> ForkCondition;

    /// Convenience method to check if [`SovaHardfork::Beta`] is active at a given block number.
    fn is_beta_active_at_block(&self, block_number: u64) -> bool {
        self.sova_fork_activation(SovaHardfork::Beta).active_at_block(block_number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn check_sova_hardfork_from_str() {
        let hardfork_str = ["bEtA"];
        let expected_hardforks = [SovaHardfork::Beta];

        let hardforks: Vec<SovaHardfork> =
            hardfork_str.iter().map(|h| SovaHardfork::from_str(h).unwrap()).collect();

        assert_eq!(hardforks, expected_hardforks);
    }

    #[test]
    fn check_nonexistent_sova_hardfork_from_str() {
        assert!(SovaHardfork::from_str("not a hardfork").is_err());
    }

    #[test]
    fn sova_mainnet_fork_conditions() {
        let forks = SovaHardfork::sova_mainnet();
        assert_eq!(forks[0], (SovaHardfork::Beta, ForkCondition::Block(1280000)));
    }
}
