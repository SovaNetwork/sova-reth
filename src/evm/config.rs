use crate::evm::{alloy::CustomEvmFactory, CustomBlockAssembler};
use alloy_consensus::{BlockHeader, Header};
use alloy_evm::EvmEnv;
use alloy_op_evm::OpBlockExecutionCtx;
use op_revm::OpSpecId;
use reth_ethereum::{
    node::api::ConfigureEvm,
    primitives::{SealedBlock, SealedHeader},
};
use reth_op::node::{OpEvmConfig, OpNextBlockEnvAttributes, OpRethReceiptBuilder};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::NodePrimitives;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SovaEvmConfig {
    pub(super) inner: OpEvmConfig,
    pub(super) block_assembler: CustomBlockAssembler,
    pub(super) custom_evm_factory: CustomEvmFactory,
}

impl SovaEvmConfig {
    pub fn new(chain_spec: Arc<OpChainSpec>) -> Self {
        Self {
            inner: OpEvmConfig::new(chain_spec.clone(), OpRethReceiptBuilder::default()),
            block_assembler: CustomBlockAssembler::new(chain_spec),
            custom_evm_factory: CustomEvmFactory::new(),
        }
    }
}

impl ConfigureEvm for SovaEvmConfig {
    type Primitives = OpPrimitives;
    type Error = <OpEvmConfig as ConfigureEvm>::Error;
    type NextBlockEnvCtx = <OpEvmConfig as ConfigureEvm>::NextBlockEnvCtx;
    type BlockExecutorFactory = Self;
    type BlockAssembler = CustomBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &Header) -> EvmEnv<OpSpecId> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &Header,
        attributes: &OpNextBlockEnvAttributes,
    ) -> Result<EvmEnv<OpSpecId>, Self::Error> {
        self.inner.next_evm_env(parent, attributes)
    }

    fn context_for_block(
        &self,
        block: &SealedBlock<<OpPrimitives as NodePrimitives>::Block>,
    ) -> OpBlockExecutionCtx {
        OpBlockExecutionCtx {
            parent_hash: block.header().parent_hash(),
            parent_beacon_block_root: block.header().parent_beacon_block_root(),
            extra_data: block.header().extra_data().clone(),
        }
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<Header>,
        attributes: Self::NextBlockEnvCtx,
    ) -> OpBlockExecutionCtx {
        OpBlockExecutionCtx {
            parent_hash: parent.hash(),
            parent_beacon_block_root: attributes.parent_beacon_block_root,
            extra_data: attributes.extra_data,
        }
    }
}
