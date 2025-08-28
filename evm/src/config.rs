use alloy_consensus::{BlockHeader, Header};
use alloy_evm::EvmEnv;
use alloy_op_evm::OpBlockExecutionCtx;
use alloy_op_hardforks::OpHardforks;
use alloy_primitives::U256;
use op_alloy_consensus::EIP1559ParamError;
use op_revm::OpSpecId;
use reth_ethereum::{
    node::api::ConfigureEvm,
    primitives::{SealedBlock, SealedHeader},
};
use reth_op::chainspec::EthChainSpec;
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_evm::{
    revm_spec_by_timestamp_after_bedrock, OpBlockAssembler, OpNextBlockEnvAttributes,
    OpRethReceiptBuilder,
};
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::NodePrimitives;
use revm::{
    context::{BlockEnv, CfgEnv},
    context_interface::block::BlobExcessGasAndPrice,
    primitives::hardfork::SpecId,
};
use std::sync::Arc;

use crate::{alloy::SovaEvmFactory, executor::SovaBlockExecutorFactory};
use reth_optimism_primitives::{OpReceipt, OpTransactionSigned};

/// Optimism-related EVM configuration.
#[derive(Debug)]
pub struct SovaEvmConfig<
    ChainSpec = OpChainSpec,
    N: NodePrimitives = OpPrimitives,
    R = OpRethReceiptBuilder,
> {
    /// Inner [`SovaBlockExecutorFactory`].
    pub executor_factory: SovaBlockExecutorFactory<R, Arc<ChainSpec>>,
    /// Optimism block assembler.
    pub block_assembler: OpBlockAssembler<ChainSpec>,
    _pd: core::marker::PhantomData<N>,
}

impl<ChainSpec, N: NodePrimitives, R: Clone> Clone for SovaEvmConfig<ChainSpec, N, R> {
    fn clone(&self) -> Self {
        Self {
            executor_factory: self.executor_factory.clone(),
            block_assembler: self.block_assembler.clone(),
            _pd: self._pd,
        }
    }
}

impl<ChainSpec: OpHardforks> SovaEvmConfig<ChainSpec> {
    /// Creates a new [`SovaEvmConfig`] with the given chain spec for OP chains.
    pub fn sova(chain_spec: Arc<ChainSpec>) -> Self {
        Self::new(chain_spec, OpRethReceiptBuilder::default())
    }
}

impl<ChainSpec: OpHardforks, N: NodePrimitives, R> SovaEvmConfig<ChainSpec, N, R> {
    /// Creates a new [`SovaEvmConfig`] with the given chain spec.
    pub fn new(chain_spec: Arc<ChainSpec>, receipt_builder: R) -> Self {
        Self {
            block_assembler: OpBlockAssembler::new(chain_spec.clone()),
            executor_factory: SovaBlockExecutorFactory::new(
                receipt_builder,
                chain_spec,
                SovaEvmFactory,
                std::env::var("SOVA_SENTINEL_URL").unwrap_or_default(),
                reth_tasks::TaskExecutor::current(),
            ),
            _pd: core::marker::PhantomData,
        }
    }

    /// Returns the chain spec associated with this configuration.
    pub const fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.executor_factory.spec()
    }
}

impl<ChainSpec, N> ConfigureEvm for SovaEvmConfig<ChainSpec, N, OpRethReceiptBuilder>
where
    ChainSpec: EthChainSpec<Header = Header> + OpHardforks,
    N: NodePrimitives<
        Receipt = OpReceipt,
        SignedTx = OpTransactionSigned,
        BlockHeader = Header,
        BlockBody = alloy_consensus::BlockBody<OpTransactionSigned>,
        Block = alloy_consensus::Block<OpTransactionSigned>,
    >,
    Self: Send + Sync + Unpin + Clone + 'static,
{
    type Primitives = N;
    type Error = EIP1559ParamError;
    type NextBlockEnvCtx = OpNextBlockEnvAttributes;
    type BlockExecutorFactory = SovaBlockExecutorFactory<OpRethReceiptBuilder, Arc<ChainSpec>>;
    type BlockAssembler = OpBlockAssembler<ChainSpec>;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        &self.executor_factory
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> EvmEnv<OpSpecId> {
        let spec = reth_optimism_evm::revm_spec(self.chain_spec(), header);

        let cfg_env = CfgEnv::new()
            .with_chain_id(self.chain_spec().chain().id())
            .with_spec(spec);

        let blob_excess_gas_and_price = spec
            .into_eth_spec()
            .is_enabled_in(SpecId::CANCUN)
            .then_some(BlobExcessGasAndPrice {
                excess_blob_gas: 0,
                blob_gasprice: 1,
            });

        let block_env = BlockEnv {
            number: U256::from(header.number()),
            beneficiary: header.beneficiary(),
            timestamp: U256::from(header.timestamp()),
            difficulty: if spec.into_eth_spec() >= SpecId::MERGE {
                U256::ZERO
            } else {
                header.difficulty()
            },
            prevrandao: if spec.into_eth_spec() >= SpecId::MERGE {
                header.mix_hash()
            } else {
                None
            },
            gas_limit: header.gas_limit(),
            basefee: header.base_fee_per_gas().unwrap_or_default(),
            // EIP-4844 excess blob gas of this block, introduced in Cancun
            blob_excess_gas_and_price,
        };

        EvmEnv { cfg_env, block_env }
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &OpNextBlockEnvAttributes,
    ) -> Result<EvmEnv<OpSpecId>, Self::Error> {
        // ensure we're not missing any timestamp based hardforks
        let spec_id = revm_spec_by_timestamp_after_bedrock(self.chain_spec(), attributes.timestamp);

        // configure evm env based on parent block
        let cfg_env = CfgEnv::new()
            .with_chain_id(self.chain_spec().chain().id())
            .with_spec(spec_id);

        // if the parent block did not have excess blob gas (i.e. it was pre-cancun), but it is
        // cancun now, we need to set the excess blob gas to the default value(0)
        let blob_excess_gas_and_price = spec_id
            .into_eth_spec()
            .is_enabled_in(SpecId::CANCUN)
            .then_some(BlobExcessGasAndPrice {
                excess_blob_gas: 0,
                blob_gasprice: 1,
            });

        let block_env = BlockEnv {
            number: U256::from(parent.number() + 1),
            beneficiary: attributes.suggested_fee_recipient,
            timestamp: U256::from(attributes.timestamp),
            difficulty: U256::ZERO,
            prevrandao: Some(attributes.prev_randao),
            gas_limit: attributes.gas_limit,
            // calculate basefee based on parent block's gas usage
            basefee: self
                .chain_spec()
                .next_block_base_fee(parent, attributes.timestamp)
                .unwrap_or_default(),
            // calculate excess gas based on parent block's blob gas usage
            blob_excess_gas_and_price,
        };

        Ok(EvmEnv { cfg_env, block_env })
    }

    fn context_for_block(&self, block: &'_ SealedBlock<N::Block>) -> OpBlockExecutionCtx {
        OpBlockExecutionCtx {
            parent_hash: block.header().parent_hash(),
            parent_beacon_block_root: block.header().parent_beacon_block_root(),
            extra_data: block.header().extra_data().clone(),
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<N::BlockHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> OpBlockExecutionCtx {
        OpBlockExecutionCtx {
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            extra_data: attributes.extra_data,
        }
    }
}
