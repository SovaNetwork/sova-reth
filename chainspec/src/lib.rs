mod constants;
mod dev;
mod mainnet;
mod testnet;

use alloy_consensus::Header;
use alloy_genesis::Genesis;
pub use constants::{
    BitcoinPrecompileMethod, BITCOIN_PRECOMPILE_ADDRESSES, BROADCAST_TRANSACTION_ADDRESS,
    BROADCAST_TRANSACTION_PRECOMPILE_ID, CONVERT_ADDRESS_ADDRESS, CONVERT_ADDRESS_PRECOMPILE_ID,
    DECODE_TRANSACTION_ADDRESS, DECODE_TRANSACTION_PRECOMPILE_ID,
    L1_BLOCK_CURRENT_BLOCK_HEIGHT_SLOT, SOVA_ADDR_CONVERT_DOMAIN_TAG, SOVA_BTC_CONTRACT_ADDRESS,
    SOVA_L1_BLOCK_CONTRACT_ADDRESS,
};
pub use dev::{DEV, SOVA_DEVNET_DERIVATION_XPUB};
pub use mainnet::{SOVA, SOVA_MAINNET_DERIVATION_XPUB};
use reth_chainspec::Hardforks;
pub use testnet::{SOVA_TESTNET_DERIVATION_XPUB, TESTNET};

use std::sync::Arc;

use reth_cli::chainspec::{parse_genesis, ChainSpecParser};
use reth_ethereum::chainspec::{Hardfork, EthChainSpec, EthereumHardforks};
use reth_network_peers::NodeRecord;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_forks::OpHardforks;

#[derive(Debug, Clone)]
pub struct SovaChainSpec {
    inner: OpChainSpec,
}

impl SovaChainSpec {
    pub const fn inner(&self) -> &OpChainSpec {
        &self.inner
    }
}

impl Hardforks for SovaChainSpec {
    fn fork<H: Hardfork>(&self, fork: H) -> reth_ethereum::chainspec::ForkCondition {
        self.inner.fork(fork)
    }

    fn forks_iter(
        &self,
    ) -> impl Iterator<Item = (&dyn Hardfork, reth_ethereum::chainspec::ForkCondition)> {
        self.inner.forks_iter()
    }

    fn fork_id(&self, head: &reth_ethereum::chainspec::Head) -> reth_ethereum::chainspec::ForkId {
        self.inner.fork_id(head)
    }

    fn latest_fork_id(&self) -> reth_ethereum::chainspec::ForkId {
        self.inner.latest_fork_id()
    }

    fn fork_filter(
        &self,
        head: reth_ethereum::chainspec::Head,
    ) -> reth_ethereum::chainspec::ForkFilter {
        self.inner.fork_filter(head)
    }
}

impl EthChainSpec for SovaChainSpec {
    type Header = Header;

    fn chain(&self) -> reth_ethereum::chainspec::Chain {
        self.inner.chain()
    }

    fn base_fee_params_at_timestamp(
        &self,
        timestamp: u64,
    ) -> reth_ethereum::chainspec::BaseFeeParams {
        self.inner.base_fee_params_at_timestamp(timestamp)
    }

    fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<alloy_eips::eip7840::BlobParams> {
        self.inner.blob_params_at_timestamp(timestamp)
    }

    fn deposit_contract(&self) -> Option<&reth_ethereum::chainspec::DepositContract> {
        self.inner.deposit_contract()
    }

    fn genesis_hash(&self) -> revm_primitives::B256 {
        self.inner.genesis_hash()
    }

    fn prune_delete_limit(&self) -> usize {
        self.inner.prune_delete_limit()
    }

    fn display_hardforks(&self) -> Box<dyn std::fmt::Display> {
        self.inner.display_hardforks()
    }

    fn genesis_header(&self) -> &Self::Header {
        self.inner().genesis_header()
    }

    fn genesis(&self) -> &Genesis {
        self.inner.genesis()
    }

    // TODO(powvt): override when bootnode urls are ready
    fn bootnodes(&self) -> Option<Vec<NodeRecord>> {
        self.inner.bootnodes()
    }

    fn final_paris_total_difficulty(&self) -> Option<revm_primitives::U256> {
        self.inner.get_final_paris_total_difficulty()
    }
}

impl EthereumHardforks for SovaChainSpec {
    fn ethereum_fork_activation(
        &self,
        fork: reth_ethereum::chainspec::EthereumHardfork,
    ) -> reth_ethereum::chainspec::ForkCondition {
        self.inner.ethereum_fork_activation(fork)
    }
}

impl OpHardforks for SovaChainSpec {
    fn op_fork_activation(
        &self,
        fork: reth_optimism_forks::OpHardfork,
    ) -> reth_ethereum::chainspec::ForkCondition {
        self.inner.op_fork_activation(fork)
    }
}

impl From<Genesis> for SovaChainSpec {
    fn from(genesis: Genesis) -> Self {
        Self {
            inner: OpChainSpec::from(genesis),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SovaChainSpecParser;

impl ChainSpecParser for SovaChainSpecParser {
    type ChainSpec = SovaChainSpec;

    /// Chain configurations supported
    ///
    /// mainnet -> Bitcoin mainnet, ETH Mainnet
    /// testnet -> Bitcoin regtest, ETH Sepolia
    /// devnet -> Bitcoin regtest, Local (Mock) Consensus, see reth's `--dev` flag for more details.
    const SUPPORTED_CHAINS: &[&str] = &["sova-devnet", "sova-testnet", "sova"];

    fn parse(s: &str) -> eyre::Result<Arc<Self::ChainSpec>> {
       chain_value_parser(s)
    }
}

pub fn chain_value_parser(s: &str) -> eyre::Result<Arc<SovaChainSpec>, eyre::Error> {
    Ok(match s {
            "sova-devnet" => DEV.clone(),
            "sova-testnet" => TESTNET.clone(),
            "sova" => SOVA.clone(),
            _ => Arc::new(parse_genesis(s)?.into()),
        })
}
